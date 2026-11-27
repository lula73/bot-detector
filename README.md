# Bot Detector — public blocklist

IP addresses that send malicious automated traffic — vulnerability scanners,
scrapers, bots hiding behind fake browsers — observed on a network of
high-traffic Italian news websites and blocked there.

| | |
|---|---|
| Addresses | **229,997** |
| Networks | **1,720** |
| Last update | 2026-11-27 14:42 UTC |
| Update frequency | once a day |

This is the list we block with ourselves, published as it is. Use it the same
way you would use any third-party blocklist: **read
[Before you use it](#before-you-use-it) first.**

## Files

| File | For | Notes |
|---|---|---|
| [`blacklist.csv`](blacklist.csv) | people and scripts | one row per address, **with the reason** |
| [`nginx/geo.conf`](nginx/geo.conf) | nginx | `geo` block, constant-time lookup |
| [`php/`](php/) | any PHP site | lookup library, binary list, daily updater |
| [`wordpress/botdetector-blocklist.php`](wordpress/botdetector-blocklist.php) | WordPress | single-file plugin, updates itself daily |
| [`haproxy/blacklist.list`](haproxy/blacklist.list) | HAProxy | `acl … src -f` |
| [`apache/blocklist.map`](apache/blocklist.map) | Apache | `RewriteMap`, plus `networks.conf` |
| [`iptables/botdetector.ipset`](iptables/botdetector.ipset) | Linux firewall | `ipset restore` file, atomic swap |
| [`cloudflare/ip_list.txt`](cloudflare/ip_list.txt) | anything else | plain list, one address or network per line |
| [`nginx/deny.conf`](nginx/deny.conf) | nginx (legacy) | `deny` rules; slow with a list this long, prefer `geo.conf` |

All files hold the same addresses. IPv4 and IPv6 are both present.

## Why an address is listed

`blacklist.csv` has one row per address:

| Column | Meaning |
|---|---|
| `ip` | address, or network in CIDR form |
| `category` | why it was blocked, as a stable code (table below) |
| `reason` | what was observed, in words |
| `score` | bot score from 0 to 100, when the block came from scoring |
| `country`, `asn`, `as_org` | where the address is, when known |
| `first_blocked` | day it entered the list (UTC) |
| `expires` | day it leaves unless seen again; empty means no expiry |

Every entry has exactly one category. The codes are stable: a script can filter
on them. The count is the number of entries in today's list.

| Category | Addresses | Meaning |
|---|---|---|
| `vulnerability_scan` | 2,459 | Probed for files and endpoints only an attacker asks for: `.env` and other configuration files, `.git/`, database dumps and backups, admin panels, WordPress internals, web shells |
| `honeypot` | 193,306 | Requested a decoy URL: one that no page links to and no reader reaches |
| `user_agent_rotation` | 1,863 | One address presenting itself as many different browsers |
| `http_tool` | 195 | Scripted HTTP client or headless browser, from a datacenter network |
| `no_user_agent` | 33 | Requests with no User-Agent at all, from a datacenter network |
| `datacenter_crawler` | 6,152 | Datacenter address crawling across many of our sites |
| `behavior` | 12,256 | No single signal: the overall behaviour scored as a bot (see `score`) |
| `manual` | 13,733 | Blocked by an operator |
| `network` | 1,720 | Whole network blocked by an operator |
| `legacy` | 0 | Carried over from the previous version of this list |
| `other` | 0 | Not classified |

The first six are blocks on a single, unambiguous signal. `behavior` is the
score: no single signal, but the sum of how the address moved through the
sites. `manual` and `network` are decisions taken by a person, and their
`reason` is never published.

How long an entry stays depends on what the address did and where it is:
vulnerability scanners stay the longest, addresses on networks that change
hands quickly the shortest. The day is in `expires`.

Top countries:

| Country | Addresses |
|---|---|
| US | 8,099 |
| SG | 4,505 |
| NL | 2,304 |
| IE | 1,534 |
| FR | 1,349 |
| CN | 1,276 |
| DE | 1,227 |
| CH | 536 |
| BE | 456 |
| FI | 430 |

You can build a stricter list of your own from the CSV, for instance only
`vulnerability_scan` and `honeypot`:

```bash
curl -s https://raw.githubusercontent.com/lula73/bot-detector/master/blacklist.csv \
  | awk -F, 'NR > 1 && ($2 == "vulnerability_scan" || $2 == "honeypot") { print $1 }'
```

## nginx

```bash
mkdir -p /etc/nginx/botdetector
curl -fsS -o /etc/nginx/botdetector/geo.conf.new https://raw.githubusercontent.com/lula73/bot-detector/master/nginx/geo.conf \
  && mv /etc/nginx/botdetector/geo.conf.new /etc/nginx/botdetector/geo.conf \
  && nginx -t && nginx -s reload
```

```nginx
http {
    include /etc/nginx/botdetector/geo.conf;

    server {
        if ($botdetector_blocked) { return 403; }
    }
}
```

Run the `curl` line from cron once a day. `nginx -t` keeps a broken download
from being loaded.

Behind a proxy or a CDN, `geo` must look at the real client address. Tell nginx
which proxies to trust with `set_real_ip_from` and `real_ip_header`, otherwise
it compares the proxy's address and nothing is ever blocked.

## PHP

Download [`php/botdetector.php`](php/botdetector.php) and
[`php/update.php`](php/update.php) once, then let cron fetch the list:

```cron
17 6 * * *  php /opt/botdetector/update.php /var/lib/botdetector/blacklist.bin
```

At the very top of your front controller:

```php
require '/opt/botdetector/botdetector.php';

$blocklist = new BotDetector_Blocklist('/var/lib/botdetector/blacklist.bin');
$blocklist->blockIfListed();          // answers 403 and stops if listed
```

Or decide yourself:

```php
if ($blocklist->contains($_SERVER['REMOTE_ADDR'])) { /* … */ }
```

The lookup is a binary search on disk: about 18 small reads, no memory, the
same cost with or without OPcache. If the file is missing or damaged the answer
is "not listed": a broken list never takes your site down.

Behind a proxy, pass the addresses of **your** proxies:

```php
$blocklist->blockIfListed(['10.0.0.0/8', '203.0.113.7']);
```

`X-Forwarded-For` is read only when the request comes from one of them. Anyone
can send that header, so it is never trusted on its own.

## WordPress

Copy [`wordpress/botdetector-blocklist.php`](wordpress/botdetector-blocklist.php)
to `wp-content/plugins/` and activate it — or to `wp-content/mu-plugins/` to
have it always on. It is a single file: it downloads the list once a day with
WP-Cron, keeps it in `wp-content/uploads/botdetector/`, and answers 403 to
listed addresses before WordPress finishes loading.

Optional settings in `wp-config.php`:

```php
// Your reverse proxies or CDN (see the PHP section).
define('BOTDETECTOR_TRUSTED_PROXIES', array('10.0.0.0/8'));
// Addresses that are never blocked.
define('BOTDETECTOR_ALLOW', array('198.51.100.20'));
```

The first download happens about a minute after the plugin starts running.

## HAProxy

```haproxy
acl botdetector_blocked src -f /etc/haproxy/botdetector.list
http-request deny deny_status 403 if botdetector_blocked
```

## Apache

`blocklist.map` holds the addresses, `networks.conf` the networks. In the
server or virtual host configuration, not in `.htaccess`:

```apache
RewriteEngine On
RewriteMap botdetector "txt:/etc/apache2/botdetector/blocklist.map"
RewriteCond ${botdetector:%{REMOTE_ADDR}|0} =1
RewriteRule ^ - [F]

Include /etc/apache2/botdetector/networks.conf
```

Apache reads the map once and reloads it when the file changes. An `.htaccess`
with one line per address is no longer published: Apache would parse all of it
on every request.

## Linux firewall (ipset)

```bash
curl -fsS https://raw.githubusercontent.com/lula73/bot-detector/master/iptables/botdetector.ipset | ipset restore -exist
# once:
iptables  -I INPUT -m set --match-set botdetector4 src -j DROP
ip6tables -I INPUT -m set --match-set botdetector6 src -j DROP
```

The file fills a spare set and swaps it with the live one, so the rule never
sees an empty list while it updates.

## Before you use it

- **It is our traffic, not yours.** An address that hammered a news site may
  be a tool you rely on: a monitoring service, an API client, a partner's
  crawler. Check the list against your own logs before you block with it.
- **A blocked visitor gets no explanation.** We send blocked visitors to a page
  where a person can report a mistake. A `403` from your firewall offers no such
  way back, so false positives are yours to notice.
- **Addresses change hands.** Entries expire on their own (see `expires`), and
  the list is rebuilt every day. Do not keep a copy for weeks: an old copy
  blocks people who inherited an address.
- **Shared addresses exist.** VPN exits, mobile carriers and corporate gateways
  put many people behind one address. Most entries are datacenter addresses,
  but not all of them.
- **No warranty.** The list is provided as is.

## How the list is built

Each address that sends enough requests gets a score from 0 to 100, from its
behaviour (request rhythm, path variety, bursts, missing referers, error rate)
and from explicit rules (exploit paths, decoy URLs, scripted clients, declared
bots). Addresses above the threshold are blocked, and leave when they stop or
when the entry expires. Search engines and other declared, well-behaved
crawlers are verified and never listed.

The detection rules and thresholds are not published: a bot that can read them
can route around them. What was observed for each address is in the CSV.

## Reporting a mistake

Open an issue on this repository with the address and the day. Entries removed
on our side disappear from the next daily update.
