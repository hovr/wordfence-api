<?php
declare(strict_types=1);

require_once __DIR__ . '/../wp_update_policy.php';

function assertSameValue($expected, $actual, string $message): void
{
    if ($expected !== $actual) {
        fwrite(STDERR, $message . "\nExpected: " . var_export($expected, true) . "\nActual: " . var_export($actual, true) . "\n");
        exit(1);
    }
}

function assertTrueValue(bool $actual, string $message): void
{
    if (!$actual) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

function assertContainsText(string $needle, string $haystack, string $message): void
{
    if (strpos($haystack, $needle) === false) {
        fwrite(STDERR, $message . "\nMissing: {$needle}\nBody:\n{$haystack}\n");
        exit(1);
    }
}

$vulnerabilityRows = [
    [
        'id' => 'wf-test-1',
        'title' => 'Test vulnerable range',
        'affected_versions' => [
            [
                'from_version' => '*',
                'to_version' => '2.0.0',
                'from_inclusive' => true,
                'to_inclusive' => true,
            ],
        ],
    ],
];

$observedVersions = [
    [
        'version' => '1.5.0',
        'source' => 'candidate',
        'first_seen_at' => gmdate('Y-m-d H:i:s', time() - 3600),
        'last_seen_at' => gmdate('Y-m-d H:i:s'),
    ],
    [
        'version' => '2.1.0',
        'source' => 'candidate',
        'first_seen_at' => gmdate('Y-m-d H:i:s', time() - 3600),
        'last_seen_at' => gmdate('Y-m-d H:i:s'),
    ],
];

$safeObserved = safeObservedVersions($vulnerabilityRows, $observedVersions, '1.0.0');
assertSameValue(['2.1.0'], array_column($safeObserved, 'version'), 'Only non-vulnerable observed versions should be retained.');

$manualReviewPolicy = [
    'rules' => [
        'normal_delay_hours' => 168,
        'emergency_delay_hours' => 24,
    ],
    'core' => [
        'type' => 'core',
        'slug' => 'wordpress',
        'current_version' => '1.0.0',
        'current_is_vulnerable' => true,
        'recommended_action' => 'manual_review',
        'emergency_update_version' => null,
        'allowed_update_version' => null,
        'safe_observed_versions' => [],
    ],
    'plugins' => [],
];

$manualReviewGroups = policyUpdateEmailGroupsForPolicy($manualReviewPolicy);
assertSameValue(1, count($manualReviewGroups['manual_review']), 'Manual-review assets should remain visible when no safe waiting update exists.');
assertSameValue(0, count($manualReviewGroups['emergency_waiting']), 'Unsafe waiting updates should not be shown as emergency waiting updates.');

$vulnerableWaitingPolicy = $manualReviewPolicy;
$vulnerableWaitingPolicy['core']['current_vulnerabilities'] = [
    [
        'id' => 'wf-test-1',
        'title' => 'Test vulnerable range',
        'cve' => 'CVE-2026-1234',
        'cvss_score' => 8.1,
        'cvss_rating' => 'High',
        'references' => [
            [
                'url' => 'https://www.wordfence.com/threat-intel/vulnerabilities/id/wf-test-1',
                'label' => 'Wordfence',
            ],
        ],
    ],
];
$vulnerableWaitingPolicy['core']['safe_observed_versions'] = [
    [
        'version' => '2.1.0',
        'source' => 'candidate',
        'first_seen_at' => gmdate('Y-m-d H:i:s', time() - 3600),
        'last_seen_at' => gmdate('Y-m-d H:i:s'),
    ],
];
$vulnerableWaitingGroups = policyUpdateEmailGroupsForPolicy($vulnerableWaitingPolicy);
assertSameValue(1, count($vulnerableWaitingGroups['emergency_waiting']), 'Safe emergency updates within delay should appear in the waiting group.');
assertSameValue(1, count($vulnerableWaitingGroups['manual_review']), 'Vulnerable assets should remain in manual review while a safe update is still waiting.');
assertSameValue('1 manual review', policySubjectSummary(policyActionCounts($vulnerableWaitingPolicy), $vulnerableWaitingGroups), 'Manual-review subject should stay consistent for vulnerable waiting assets.');
assertSameValue(8.1, $vulnerableWaitingGroups['emergency_waiting'][0]['vulnerabilities'][0]['cvss_score'], 'Emergency dashboard summaries should include the vulnerability CVSS score.');
assertSameValue('High', $vulnerableWaitingGroups['emergency_waiting'][0]['vulnerabilities'][0]['cvss_rating'], 'Emergency dashboard summaries should include the vulnerability CVSS rating.');
assertSameValue('https://www.wordfence.com/threat-intel/vulnerabilities/id/wf-test-1', $vulnerableWaitingGroups['emergency_waiting'][0]['vulnerabilities'][0]['references'][0]['url'], 'Emergency dashboard summaries should include Wordfence reference links.');

$normalizedReferences = normalizeVulnerabilityReferences([
    'Wordfence' => 'https://www.wordfence.com/threat-intel/vulnerabilities/id/wf-test-1',
    ['url' => 'https://example.com/advisory', 'title' => 'Advisory'],
    'javascript:alert(1)',
]);
assertSameValue(2, count($normalizedReferences), 'Reference normalization should keep only HTTP links.');
assertSameValue('Wordfence', $normalizedReferences[0]['label'], 'Reference normalization should use associative labels when available.');
$singleReference = normalizeVulnerabilityReferences(['url' => 'https://www.wordfence.com/example', 'label' => 'Wordfence details']);
assertSameValue('Wordfence details', $singleReference[0]['label'], 'Reference normalization should preserve labels from a single reference object.');

$waitingPolicy = [
    'site_key' => 'example-site',
    'site_path' => '/var/www/example',
    'generated_at' => gmdate('Y-m-d H:i:s'),
    'rules' => [
        'normal_delay_hours' => 168,
        'emergency_delay_hours' => 24,
    ],
    'core' => [
        'type' => 'core',
        'slug' => 'wordpress',
        'current_version' => '6.5.0',
        'current_is_vulnerable' => false,
        'recommended_action' => 'hold',
        'allowed_update_version' => null,
        'emergency_update_version' => null,
        'safe_observed_versions' => [
            [
                'version' => '6.5.1',
                'source' => 'candidate',
                'first_seen_at' => gmdate('Y-m-d H:i:s', time() - 3600),
                'last_seen_at' => gmdate('Y-m-d H:i:s'),
            ],
        ],
    ],
    'plugins' => [],
];

$waitingGroups = policyUpdateEmailGroupsForPolicy($waitingPolicy);
assertSameValue(1, count($waitingGroups['normal_waiting']), 'Pending safe updates should appear in the normal waiting group.');
assertTrueValue(policyEmailGroupsHaveAssets($waitingGroups), 'Waiting groups should prevent no-update suppression.');
assertSameValue('1 pending update', policySubjectSummary(policyActionCounts($waitingPolicy), $waitingGroups), 'Waiting-only emails should not use a no-updates subject.');

$body = policyEmailBody(
    $waitingPolicy,
    '/tmp/example-policy.json',
    null,
    policyActionCounts($waitingPolicy),
    $waitingGroups
);
assertContainsText('Assets with updates but still within the 168 hour delay:', $body, 'Email body should include the waiting update section.');
assertContainsText('CORE wordpress 6.5.0 => normal_waiting to 6.5.1', $body, 'Email body should include the waiting update asset.');

$today = '2026-06-20';
assertSameValue(
    ['send' => true, 'reason' => 'daily_notification_due', 'type' => 'daily'],
    policyNotificationDecision([], [], $today),
    'First policy notification of the day should send.'
);
assertSameValue(
    ['send' => false, 'reason' => 'daily_notification_already_sent', 'type' => 'daily'],
    policyNotificationDecision(['last_daily_sent_date' => $today], [], $today),
    'Second non-emergency policy notification on the same day should be suppressed.'
);

$emergencyPluginPolicy = $waitingPolicy;
$emergencyPluginPolicy['plugins'] = [
    [
        'type' => 'plugin',
        'slug' => 'classic-editor',
        'current_version' => '1.6.7',
        'recommended_action' => 'emergency_update',
        'emergency_update_version' => '1.7.0',
    ],
];
$emergencySignatures = emergencyPluginNotificationSignatures($emergencyPluginPolicy);
assertSameValue(1, count($emergencySignatures), 'Emergency plugin updates should produce a notification signature.');
assertSameValue(
    ['send' => true, 'reason' => 'emergency_plugin_update', 'type' => 'emergency'],
    policyNotificationDecision(['last_daily_sent_date' => $today], $emergencySignatures, $today),
    'A new emergency plugin update should bypass the daily notification limit.'
);

$updatedState = updatedPolicyNotificationState(['last_daily_sent_date' => $today], $emergencySignatures, $today);
assertSameValue($today, $updatedState['last_daily_sent_date'], 'Successful notification should record the daily send date.');
assertTrueValue(isset($updatedState['sent_emergency_signatures'][$emergencySignatures[0]]), 'Successful emergency notification should record its signature.');
assertSameValue(
    ['send' => false, 'reason' => 'daily_notification_already_sent', 'type' => 'daily'],
    policyNotificationDecision($updatedState, $emergencySignatures, $today),
    'The same emergency plugin signature should not resend on every cron run.'
);

$now = strtotime('2026-06-20T12:00:00+00:00');
$prunedSignatures = prunedPolicyNotificationEmergencySignatures([
    'old-signature' => '2026-02-01T12:00:00+00:00',
    'recent-signature' => '2026-06-19T12:00:00+00:00',
    'invalid-signature' => 'not-a-date',
], $now, 90, 500);
assertSameValue(['recent-signature'], array_keys($prunedSignatures), 'Old or invalid emergency notification signatures should be pruned.');

$signatureOverflow = [];
for ($index = 0; $index < 3; $index++) {
    $signatureOverflow['signature-' . $index] = date('c', $now - ($index * 60));
}
$cappedSignatures = prunedPolicyNotificationEmergencySignatures($signatureOverflow, $now, 90, 2);
assertSameValue(['signature-0', 'signature-1'], array_keys($cappedSignatures), 'Emergency notification signature pruning should keep the newest entries when capped.');

$coreEmergencyPolicy = $waitingPolicy;
$coreEmergencyPolicy['core']['recommended_action'] = 'emergency_update';
$coreEmergencyPolicy['core']['emergency_update_version'] = '6.5.2';
assertSameValue([], emergencyPluginNotificationSignatures($coreEmergencyPolicy), 'Core emergency updates should not bypass the daily plugin notification rule.');

$stateRoot = sys_get_temp_dir() . '/wp-policy-notification-state-' . bin2hex(random_bytes(4));
$statePath = policyNotificationStatePath(['site_key' => 'hfe.hovr'], ['notification-state-dir' => $stateRoot]);
try {
    writePolicyNotificationState($statePath, $updatedState);
    assertSameValue($updatedState, readPolicyNotificationState($statePath), 'Notification state should round-trip through JSON.');
} finally {
    if (is_file($statePath)) {
        unlink($statePath);
    }
    if (is_dir($stateRoot)) {
        rmdir($stateRoot);
    }
}

fwrite(STDOUT, "wp_update_policy notification tests passed\n");
