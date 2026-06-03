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

fwrite(STDOUT, "wp_update_policy notification tests passed\n");
