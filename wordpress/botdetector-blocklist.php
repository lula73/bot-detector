<?php
/**
 * Plugin Name: Bot Detector Blocklist
 * Description: Blocks the addresses of the Bot Detector public blocklist. The list is downloaded once a day.
 * Version: 3.0.0
 * Requires PHP: 7.2
 * License: MIT
 *
 * Install: copy this single file to wp-content/plugins/ and activate it, or to
 * wp-content/mu-plugins/ to have it always on (no activation needed).
 *
 * Optional settings, in wp-config.php:
 *
 *   // Your reverse proxies or CDN. Without this the plugin looks at
 *   // REMOTE_ADDR only. Behind a proxy that is the proxy's own address, and
 *   // nothing would ever be blocked.
 *   define('BOTDETECTOR_TRUSTED_PROXIES', array('10.0.0.0/8', '203.0.113.7'));
 *
 *   // Addresses that are never blocked (your office, your monitoring).
 *   define('BOTDETECTOR_ALLOW', array('198.51.100.20'));
 *
 *   // Where the list is kept. Default: wp-content/uploads/botdetector/
 *   define('BOTDETECTOR_DIR', '/var/lib/botdetector');
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('BOTDETECTOR_URL')) {
    define('BOTDETECTOR_URL', 'https://raw.githubusercontent.com/lula73/bot-detector/master/php/blacklist.bin');
}
if (!defined('BOTDETECTOR_DIR')) {
    define('BOTDETECTOR_DIR', WP_CONTENT_DIR . '/uploads/botdetector');
}

/**
 * Bot Detector blocklist — lookup library.
 *
 * Reads `blacklist.bin`, a sorted table of address ranges, with a binary
 * search on disk: about 18 small reads per lookup, no memory used, no array of
 * 200,000 entries parsed on every request. Works with or without OPcache.
 * PHP 7.2 or later, no extensions required.
 *
 * File format (all integers big-endian):
 *   bytes 0-7    magic "BOTDBL01"
 *   bytes 8-11   n4, number of IPv4 ranges
 *   bytes 12-15  n6, number of IPv6 ranges
 *   then n4 records of 8 bytes  (first address, last address)
 *   then n6 records of 32 bytes (first address, last address)
 * Ranges are sorted and never overlap. A single address is a range of one.
 *
 * Every failure (file missing, truncated, unreadable) answers "not listed":
 * a broken blocklist must never take the site down.
 */

if (!class_exists('BotDetector_Blocklist')) {
    class BotDetector_Blocklist
    {
        const MAGIC = 'BOTDBL01';
        const HEADER = 16;

        /** @var string */
        private $file;

        /** @param string $file path of blacklist.bin */
        public function __construct($file)
        {
            $this->file = (string) $file;
        }

        /**
         * Is this address in the blocklist?
         *
         * @param string $ip IPv4 or IPv6, textual
         * @return bool
         */
        public function contains($ip)
        {
            $packed = self::pack($ip);
            if ($packed === null) {
                return false;
            }
            $handle = @fopen($this->file, 'rb');
            if ($handle === false) {
                return false;
            }
            $found = $this->search($handle, $packed);
            fclose($handle);
            return $found;
        }

        /**
         * Check a downloaded file before putting it in place.
         *
         * @param string $file
         * @return bool true when header and size agree and the list is not empty
         */
        public static function isValid($file)
        {
            $handle = @fopen($file, 'rb');
            if ($handle === false) {
                return false;
            }
            $header = fread($handle, self::HEADER);
            fclose($handle);
            if (!is_string($header) || strlen($header) !== self::HEADER) {
                return false;
            }
            if (substr($header, 0, 8) !== self::MAGIC) {
                return false;
            }
            $counts = unpack('Nn4/Nn6', substr($header, 8));
            $expected = self::HEADER + $counts['n4'] * 8 + $counts['n6'] * 32;
            return $counts['n4'] + $counts['n6'] > 0 && filesize($file) === $expected;
        }

        /**
         * The address of the visitor.
         *
         * By default this is REMOTE_ADDR and nothing else. X-Forwarded-For is
         * read only when REMOTE_ADDR is one of YOUR proxies: anyone can send
         * that header, so trusting it blindly lets a bot pick its own address.
         *
         * @param array $server usually $_SERVER
         * @param string[] $trustedProxies addresses or CIDR networks of your proxies
         * @return string
         */
        public static function clientIp(array $server, array $trustedProxies = array())
        {
            $remote = isset($server['REMOTE_ADDR']) ? (string) $server['REMOTE_ADDR'] : '';
            if (!$trustedProxies || empty($server['HTTP_X_FORWARDED_FOR'])) {
                return $remote;
            }
            if (!self::inAny($remote, $trustedProxies)) {
                return $remote;
            }
            // Right to left: the first address that is not one of our proxies.
            $hops = array_reverse(array_map('trim', explode(',', (string) $server['HTTP_X_FORWARDED_FOR'])));
            foreach ($hops as $hop) {
                if (self::pack($hop) === null) {
                    break;
                }
                if (!self::inAny($hop, $trustedProxies)) {
                    return $hop;
                }
            }
            return $remote;
        }

        /**
         * Answer 403 and stop if the visitor is listed.
         *
         * @param string[] $trustedProxies see clientIp()
         * @param string[] $allow addresses or CIDR networks that are never blocked
         * @return void
         */
        public function blockIfListed(array $trustedProxies = array(), array $allow = array())
        {
            if (PHP_SAPI === 'cli') {
                return;
            }
            $ip = self::clientIp($_SERVER, $trustedProxies);
            if ($ip === '' || self::inAny($ip, $allow) || !$this->contains($ip)) {
                return;
            }
            if (!headers_sent()) {
                http_response_code(403);
                header('Content-Type: text/plain; charset=utf-8');
                header('Cache-Control: no-store');
            }
            exit("403 Forbidden\n");
        }

        /**
         * @param string $ip
         * @param string[] $networks addresses or CIDR networks
         * @return bool
         */
        public static function inAny($ip, array $networks)
        {
            $packed = self::pack($ip);
            if ($packed === null) {
                return false;
            }
            foreach ($networks as $network) {
                $parts = explode('/', (string) $network, 2);
                $base = self::pack($parts[0]);
                if ($base === null || strlen($base) !== strlen($packed)) {
                    continue;
                }
                $bits = isset($parts[1]) ? (int) $parts[1] : strlen($base) * 8;
                $bits = max(0, min($bits, strlen($base) * 8));
                $bytes = intdiv($bits, 8);
                if (strncmp($packed, $base, $bytes) !== 0) {
                    continue;
                }
                $rest = $bits % 8;
                if ($rest === 0) {
                    return true;
                }
                $mask = (0xFF << (8 - $rest)) & 0xFF;
                if ((ord($packed[$bytes]) & $mask) === (ord($base[$bytes]) & $mask)) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Textual address to 4 or 16 bytes. IPv4-mapped IPv6 becomes IPv4.
         *
         * @param string $ip
         * @return string|null
         */
        private static function pack($ip)
        {
            $packed = @inet_pton(trim((string) $ip));
            if ($packed === false) {
                return null;
            }
            if (strlen($packed) === 16 && substr($packed, 0, 12) === "\0\0\0\0\0\0\0\0\0\0\xff\xff") {
                return substr($packed, 12);
            }
            return $packed;
        }

        /**
         * @param resource $handle
         * @param string $packed
         * @return bool
         */
        private function search($handle, $packed)
        {
            $header = fread($handle, self::HEADER);
            if (!is_string($header) || strlen($header) !== self::HEADER
                || substr($header, 0, 8) !== self::MAGIC) {
                return false;
            }
            $counts = unpack('Nn4/Nn6', substr($header, 8));
            $size = strlen($packed);
            if ($size === 4) {
                $offset = self::HEADER;
                $count = $counts['n4'];
            } else {
                $offset = self::HEADER + $counts['n4'] * 8;
                $count = $counts['n6'];
            }
            $record = $size * 2;

            // The last range that starts at or before the address, if any.
            $low = 0;
            $high = $count - 1;
            while ($low <= $high) {
                $middle = intdiv($low + $high, 2);
                if (fseek($handle, $offset + $middle * $record) !== 0) {
                    return false;
                }
                $range = fread($handle, $record);
                if (!is_string($range) || strlen($range) !== $record) {
                    return false;
                }
                if (strcmp($packed, substr($range, 0, $size)) < 0) {
                    $high = $middle - 1;
                } elseif (strcmp($packed, substr($range, $size)) > 0) {
                    $low = $middle + 1;
                } else {
                    return true;
                }
            }
            return false;
        }
    }
}

/** @return string */
function botdetector_blocklist_file()
{
    return rtrim(BOTDETECTOR_DIR, '/') . '/blacklist.bin';
}

/**
 * Download the list, check it, move it in place. The old list stays if
 * anything goes wrong.
 *
 * @return bool
 */
function botdetector_blocklist_update()
{
    $directory = rtrim(BOTDETECTOR_DIR, '/');
    if (!wp_mkdir_p($directory)) {
        return false;
    }
    // The file holds nothing secret, but there is no reason to serve it.
    if (!file_exists($directory . '/index.html')) {
        @file_put_contents($directory . '/index.html', '');
    }
    $temporary = $directory . '/blacklist.bin.download';
    $response = wp_remote_get(BOTDETECTOR_URL, array(
        'timeout' => 120,
        'stream' => true,
        'filename' => $temporary,
    ));
    $ok = !is_wp_error($response)
        && wp_remote_retrieve_response_code($response) === 200
        && BotDetector_Blocklist::isValid($temporary);
    if (!$ok) {
        @unlink($temporary);
        return false;
    }
    return @rename($temporary, botdetector_blocklist_file());
}

/** @return void */
function botdetector_blocklist_schedule()
{
    if (!wp_next_scheduled('botdetector_blocklist_update')) {
        wp_schedule_event(time() + 60, 'daily', 'botdetector_blocklist_update');
    }
}

add_action('botdetector_blocklist_update', 'botdetector_blocklist_update');
// On `init` and not only on activation: a must-use plugin is never activated.
add_action('init', 'botdetector_blocklist_schedule');

if (function_exists('register_deactivation_hook')) {
    register_deactivation_hook(__FILE__, function () {
        wp_clear_scheduled_hook('botdetector_blocklist_update');
    });
}

// The check runs here, while plugins are still loading: a blocked request
// costs as little of WordPress as possible. WP-CLI and cron are left alone.
if (!(defined('WP_CLI') && WP_CLI) && !(defined('DOING_CRON') && DOING_CRON)) {
    $botdetector_list = new BotDetector_Blocklist(botdetector_blocklist_file());
    $botdetector_list->blockIfListed(
        defined('BOTDETECTOR_TRUSTED_PROXIES') ? (array) BOTDETECTOR_TRUSTED_PROXIES : array(),
        defined('BOTDETECTOR_ALLOW') ? (array) BOTDETECTOR_ALLOW : array()
    );
    unset($botdetector_list);
}
