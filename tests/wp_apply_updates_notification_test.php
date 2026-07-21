<?php
declare(strict_types=1);

require_once __DIR__ . '/../wp_apply_updates.php';

function assertApplyNotificationSame($expected, $actual, string $message): void
{
    if ($expected !== $actual) {
        fwrite(STDERR, $message . "\nExpected: " . var_export($expected, true) . "\nActual: " . var_export($actual, true) . "\n");
        exit(1);
    }
}

function assertApplyNotificationContains(string $needle, string $haystack, string $message): void
{
    if (strpos($haystack, $needle) === false) {
        fwrite(STDERR, $message . "\nMissing: {$needle}\n");
        exit(1);
    }
}

$summary = [
    'site_key' => 'hfe.hovr',
    'site_path' => '/var/www/example/public',
    'policy' => '/var/www/example/policies/hfe.hovr.json',
    'mode' => 'emergency',
    'error' => 'Plugin path is not writable by deploy.',
    'updates' => [
        [
            'type' => 'plugin',
            'slug' => 'enable-media-replace',
            'from_version' => '4.2.1',
            'to_version' => '4.2.2',
            'status' => 'failed',
            'stderr' => 'directory not writable/searchable',
        ],
    ],
];

$signature = applyFailureSignature($summary);
assertApplyNotificationSame(64, strlen($signature), 'Failure signature should be a SHA-256 hash.');

$body = applyFailureEmailBody($summary);
assertApplyNotificationContains('Site: hfe.hovr', $body, 'Failure email should identify the site.');
assertApplyNotificationContains('PLUGIN enable-media-replace 4.2.1 => 4.2.2 [failed]', $body, 'Failure email should identify the attempted update.');
assertApplyNotificationContains('directory not writable/searchable', $body, 'Failure email should include update stderr.');

$now = strtotime('2026-07-21T12:00:00+00:00');
assertApplyNotificationSame(
    ['send' => true, 'reason' => 'new_or_expired_failure'],
    applyFailureNotificationDecision([], $signature, $now, 86400),
    'A new failure should send.'
);

$state = updatedApplyFailureNotificationState([], $signature, $now);
assertApplyNotificationSame(
    ['send' => false, 'reason' => 'identical_failure_recently_sent'],
    applyFailureNotificationDecision($state, $signature, $now + 3600, 86400),
    'An identical failure should be suppressed during the throttle window.'
);
assertApplyNotificationSame(
    ['send' => true, 'reason' => 'new_or_expired_failure'],
    applyFailureNotificationDecision($state, $signature, $now + 86400, 86400),
    'An identical failure should send again after the throttle window.'
);
assertApplyNotificationSame(
    ['send' => true, 'reason' => 'suppression_disabled'],
    applyFailureNotificationDecision($state, $signature, $now + 60, 0),
    'A zero throttle should disable suppression.'
);

$stateRoot = sys_get_temp_dir() . '/wp-apply-notification-test-' . bin2hex(random_bytes(4));
$statePath = applyFailureNotificationStatePath($summary, ['failure-notification-state-dir' => $stateRoot]);
try {
    writeApplyFailureNotificationState($statePath, $state);
    assertApplyNotificationSame($state, readApplyFailureNotificationState($statePath), 'Failure notification state should round-trip through JSON.');
} finally {
    if (is_file($statePath)) {
        unlink($statePath);
    }
    if (is_dir($stateRoot)) {
        rmdir($stateRoot);
    }
}

fwrite(STDOUT, "wp_apply_updates notification tests passed\n");
