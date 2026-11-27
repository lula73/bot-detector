<?php
/**
 * Bot Detector blocklist — daily download, for cron.
 *
 *   php update.php /var/lib/botdetector/blacklist.bin
 *
 * Downloads the list next to the destination, checks it, and only then moves
 * it in place: the site never reads a half-written or broken file. If anything
 * goes wrong the old list stays where it is and the exit code is 1.
 *
 * The list is published once a day; downloading it more often is pointless.
 */

require __DIR__ . '/botdetector.php';

const BOTDETECTOR_URL = 'https://raw.githubusercontent.com/lula73/bot-detector/master/php/blacklist.bin';

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
if ($argc < 2) {
    fwrite(STDERR, "usage: php update.php /path/to/blacklist.bin [url]\n");
    exit(1);
}

$target = $argv[1];
$url = isset($argv[2]) ? $argv[2] : BOTDETECTOR_URL;
$temporary = $target . '.download';

$context = stream_context_create(array(
    'http' => array('timeout' => 120, 'user_agent' => 'botdetector-blocklist-update'),
));
if (!@copy($url, $temporary, $context)) {
    fwrite(STDERR, "download failed: $url\n");
    @unlink($temporary);
    exit(1);
}
if (!BotDetector_Blocklist::isValid($temporary)) {
    fwrite(STDERR, "downloaded file is not a valid blocklist, keeping the old one\n");
    @unlink($temporary);
    exit(1);
}
if (!rename($temporary, $target)) {
    fwrite(STDERR, "cannot write $target\n");
    @unlink($temporary);
    exit(1);
}
echo "blocklist updated: $target (" . filesize($target) . " bytes)\n";
