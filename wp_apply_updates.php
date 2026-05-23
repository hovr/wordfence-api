<?php
declare(strict_types=1);

/**
 * Apply WordPress core/plugin updates allowed by a generated policy JSON file.
 *
 * Usage:
 *   php wp_apply_updates.php --policy=policies/example-site.json
 *   php wp_apply_updates.php --policy=policies/example-site.json --apply --mode=all --backup-db --maintenance
 */

require_once __DIR__ . '/cli_helpers.php';

main($argv);

function main(array $argv): void
{
    $options = parseOptions($argv);
    $policyPath = (string) ($options['policy'] ?? '');
    if ($policyPath === '' || !is_file($policyPath)) {
        fwrite(STDERR, "Missing or invalid --policy path.\n\n");
        printUsage();
        exit(1);
    }

    try {
        $policy = loadPolicy($policyPath);
        $sitePath = rtrim((string) ($options['site'] ?? $policy['site_path'] ?? ''), DIRECTORY_SEPARATOR);
        if ($sitePath === '' || !is_dir($sitePath)) {
            throw new RuntimeException('Missing or invalid site path. Pass --site or regenerate the policy with a valid site_path.');
        }

        loadConfigForOptions(['site' => $sitePath]);
    } catch (RuntimeException $exception) {
        fwrite(STDERR, $exception->getMessage() . "\n\n");
        printUsage();
        exit(1);
    }

    $siteKey = (string) ($options['site-key'] ?? $policy['site_key'] ?? basename($sitePath));
    $wpBinary = (string) ($options['wp'] ?? 'wp');
    $mode = strtolower((string) ($options['mode'] ?? 'all'));
    if (!in_array($mode, ['normal', 'emergency', 'all'], true)) {
        fwrite(STDERR, "Invalid --mode. Use normal, emergency, or all.\n");
        exit(1);
    }

    $apply = array_key_exists('apply', $options);
    $backupDb = array_key_exists('backup-db', $options);
    $maintenance = array_key_exists('maintenance', $options);
    $notifyEmail = notificationEmail($options);
    $lockFile = (string) ($options['lock-file'] ?? sys_get_temp_dir() . '/wp-apply-updates-' . safeFileName($siteKey) . '.lock');

    $filters = [
        'core_only' => array_key_exists('core-only', $options),
        'plugins_only' => array_key_exists('plugins-only', $options),
        'plugin' => isset($options['plugin']) ? (string) $options['plugin'] : null,
        'exclude' => parseCsvOption($options['exclude'] ?? ''),
    ];

    $manualReview = manualReviewItems($policy);
    $notification = notifyManualReview($manualReview, $policy, $notifyEmail, array_key_exists('no-notify', $options));

    $lockHandle = null;
    $maintenanceActive = false;
    $summary = [
        'site_key' => $siteKey,
        'site_path' => $sitePath,
        'policy' => $policyPath,
        'apply' => $apply,
        'mode' => $mode,
        'backup' => null,
        'maintenance' => false,
        'manual_review_count' => count($manualReview),
        'notification' => $notification,
        'updates' => [],
    ];

    try {
        $lockHandle = acquireLock($lockFile);
        $updates = plannedUpdates($policy, $mode, $filters);
        $summary['updates'] = $updates;

        if ($apply && $updates !== []) {
            if ($backupDb) {
                $summary['backup'] = backupDatabase($wpBinary, $sitePath, $siteKey, (string) ($options['backup-dir'] ?? __DIR__ . '/backups'));
            }

            if ($maintenance) {
                runWp($wpBinary, $sitePath, ['maintenance-mode', 'activate'], true);
                $maintenanceActive = true;
                $summary['maintenance'] = true;
            }

            foreach ($summary['updates'] as &$update) {
                applyUpdate($wpBinary, $sitePath, $update);
            }
            unset($update);
        }
    } catch (RuntimeException $exception) {
        $summary['error'] = $exception->getMessage();
        fwrite(STDERR, $exception->getMessage() . "\n");
    } finally {
        if ($maintenanceActive) {
            runWp($wpBinary, $sitePath, ['maintenance-mode', 'deactivate'], true);
        }

        if (is_resource($lockHandle)) {
            releaseLock($lockHandle, $lockFile);
        }
    }

    echo json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    exit(isset($summary['error']) ? 1 : 0);
}

function printUsage(): void
{
    echo <<<TEXT
Usage:
  php wp_apply_updates.php --policy=policies/example-site.json
  php wp_apply_updates.php --policy=policies/example-site.json --apply --mode=all --backup-db --maintenance

Options:
  --policy=PATH       Required. Policy JSON from wp_update_policy.php.
  --apply             Actually run updates. Omit for dry-run.
  --mode=VALUE        normal, emergency, or all. Default: all.
  --wp=PATH           Optional WP-CLI binary. Default: wp.
  --site=PATH         Optional override for policy site_path.
  --site-key=VALUE    Optional override for policy site_key.
  --backup-db         Export database before applying updates.
  --backup-dir=PATH   Optional backup directory. Default: ./backups.
  --maintenance       Activate maintenance mode while applying updates.
  --core-only         Only consider WordPress core.
  --plugins-only      Only consider plugins.
  --plugin=SLUG       Only consider one plugin slug.
  --exclude=SLUGS     Comma-separated plugin slugs to skip.
  --notify-email=ADDR Email for manual_review notifications.
  --no-notify         Disable manual_review email notifications.
  --lock-file=PATH    Optional lock file path.

TEXT;
}

function loadPolicy(string $path): array
{
    $json = file_get_contents($path);
    if ($json === false) {
        throw new RuntimeException("Unable to read policy file: {$path}");
    }

    $policy = json_decode($json, true);
    if (!is_array($policy)) {
        throw new RuntimeException("Invalid policy JSON: {$path}");
    }

    return $policy;
}

function plannedUpdates(array $policy, string $mode, array $filters): array
{
    $updates = [];

    if (!$filters['plugins_only'] && isset($policy['core']) && is_array($policy['core'])) {
        $core = plannedAssetUpdate($policy['core'], $mode);
        if ($core !== null) {
            $updates[] = $core;
        }
    }

    if (!$filters['core_only']) {
        foreach (($policy['plugins'] ?? []) as $plugin) {
            if (!is_array($plugin) || !passesPluginFilters($plugin, $filters)) {
                continue;
            }

            $update = plannedAssetUpdate($plugin, $mode);
            if ($update !== null) {
                $updates[] = $update;
            }
        }
    }

    return $updates;
}

function plannedAssetUpdate(array $asset, string $mode): ?array
{
    $action = (string) ($asset['recommended_action'] ?? 'hold');
    if ($action === 'manual_review' || $action === 'hold') {
        return null;
    }

    $target = null;
    $reason = null;
    if (($mode === 'normal' || $mode === 'all') && !empty($asset['allowed_update_version'])) {
        $target = (string) $asset['allowed_update_version'];
        $reason = 'normal';
    }

    if (($mode === 'emergency' || $mode === 'all') && !empty($asset['current_is_vulnerable']) && !empty($asset['emergency_update_version'])) {
        $target = (string) $asset['emergency_update_version'];
        $reason = 'emergency';
    }

    if ($target === null || compareVersions($target, (string) ($asset['current_version'] ?? '')) <= 0) {
        return null;
    }

    return [
        'type' => (string) ($asset['type'] ?? ''),
        'slug' => (string) ($asset['slug'] ?? ''),
        'name' => (string) ($asset['name'] ?? ''),
        'from_version' => (string) ($asset['current_version'] ?? ''),
        'to_version' => $target,
        'reason' => $reason,
        'status' => 'planned',
        'stdout' => null,
        'stderr' => null,
    ];
}

function passesPluginFilters(array $plugin, array $filters): bool
{
    $slug = (string) ($plugin['slug'] ?? '');

    if ($filters['plugin'] !== null && $slug !== $filters['plugin']) {
        return false;
    }

    return !in_array($slug, $filters['exclude'], true);
}

function applyUpdate(string $wpBinary, string $sitePath, array &$update): void
{
    if ($update['type'] === 'core') {
        $args = ['core', 'update', '--version=' . $update['to_version']];
    } elseif ($update['type'] === 'plugin') {
        $args = ['plugin', 'update', $update['slug'], '--version=' . $update['to_version']];
    } else {
        $update['status'] = 'skipped';
        $update['stderr'] = 'Unsupported update type.';
        return;
    }

    $stdout = runWp($wpBinary, $sitePath, $args, false, $stderr, $status);
    $update['stdout'] = trim($stdout);
    $update['stderr'] = trim($stderr);
    $update['status'] = $status === 0 ? 'updated' : 'failed';

    if ($status !== 0) {
        throw new RuntimeException("Update failed for {$update['type']} {$update['slug']}: " . trim($stderr));
    }
}

function backupDatabase(string $wpBinary, string $sitePath, string $siteKey, string $backupDir): array
{
    ensureDirectory($backupDir);
    $backupPath = rtrim($backupDir, DIRECTORY_SEPARATOR)
        . DIRECTORY_SEPARATOR
        . safeFileName($siteKey) . '-' . gmdate('Ymd-His') . '.sql';

    $stdout = runWp($wpBinary, $sitePath, ['db', 'export', $backupPath], false, $stderr, $status);
    if ($status !== 0) {
        throw new RuntimeException('Database backup failed: ' . trim($stderr));
    }

    return [
        'path' => $backupPath,
        'stdout' => trim($stdout),
    ];
}

function manualReviewItems(array $policy): array
{
    $items = [];

    if (($policy['core']['recommended_action'] ?? null) === 'manual_review') {
        $items[] = manualReviewSummary($policy['core']);
    }

    foreach (($policy['plugins'] ?? []) as $plugin) {
        if (is_array($plugin) && ($plugin['recommended_action'] ?? null) === 'manual_review') {
            $items[] = manualReviewSummary($plugin);
        }
    }

    return $items;
}

function manualReviewSummary(array $asset): array
{
    return [
        'type' => (string) ($asset['type'] ?? ''),
        'slug' => (string) ($asset['slug'] ?? ''),
        'name' => (string) ($asset['name'] ?? ''),
        'current_version' => (string) ($asset['current_version'] ?? ''),
        'current_vulnerabilities' => $asset['current_vulnerabilities'] ?? [],
    ];
}

function notifyManualReview(array $manualReview, array $policy, string $email, bool $disabled): array
{
    if ($disabled) {
        return ['sent' => false, 'reason' => 'disabled'];
    }

    if ($manualReview === []) {
        return ['sent' => false, 'reason' => 'no_manual_review_items'];
    }

    if ($email === '') {
        return ['sent' => false, 'reason' => 'missing_email'];
    }

    $subject = '[WordPress Updates] Manual review required for ' . (string) ($policy['site_key'] ?? 'site');
    $body = manualReviewEmailBody($manualReview, $policy);
    $headers = 'From: WordPress Update Policy <wordpress-updates@localhost>';

    $sent = mail($email, $subject, $body, $headers);
    return [
        'sent' => $sent,
        'to' => $email,
        'reason' => $sent ? null : 'mail_failed',
    ];
}

function manualReviewEmailBody(array $manualReview, array $policy): string
{
    $lines = [
        'Manual review is required before updating one or more WordPress assets.',
        '',
        'Site: ' . (string) ($policy['site_key'] ?? ''),
        'Path: ' . (string) ($policy['site_path'] ?? ''),
        'Policy generated: ' . (string) ($policy['generated_at'] ?? ''),
        '',
    ];

    foreach ($manualReview as $item) {
        $lines[] = strtoupper($item['type']) . ': ' . $item['slug'] . ' (' . $item['current_version'] . ')';
        foreach (($item['current_vulnerabilities'] ?? []) as $vulnerability) {
            if (!is_array($vulnerability)) {
                continue;
            }
            $lines[] = '  - ' . (string) ($vulnerability['title'] ?? $vulnerability['id'] ?? 'Vulnerability');
        }
        $lines[] = '';
    }

    return implode("\n", $lines);
}

function notificationEmail(array $options): string
{
    if (!empty($options['notify-email'])) {
        return (string) $options['notify-email'];
    }

    $email = getConfiguredValue('UPDATE_NOTIFY_EMAIL');
    if ($email !== '') {
        return $email;
    }

    return getConfiguredValue('ADMIN_EMAIL');
}

function acquireLock(string $lockFile)
{
    $handle = fopen($lockFile, 'c');
    if ($handle === false) {
        throw new RuntimeException("Unable to open lock file: {$lockFile}");
    }

    if (!flock($handle, LOCK_EX | LOCK_NB)) {
        fclose($handle);
        throw new RuntimeException("Another update run is already active: {$lockFile}");
    }

    ftruncate($handle, 0);
    fwrite($handle, (string) getmypid());

    return $handle;
}

function releaseLock($handle, string $lockFile): void
{
    flock($handle, LOCK_UN);
    fclose($handle);
    @unlink($lockFile);
}

function runWp(string $wpBinary, string $sitePath, array $args, bool $allowFailure = false, ?string &$stderr = null, ?int &$status = null): string
{
    $command = array_merge([$wpBinary, '--path=' . $sitePath], $args);
    $stdout = runCommand($command, $stderr, $status, false);

    if ($status !== 0 && !$allowFailure) {
        throw new RuntimeException("WP-CLI failed: " . implode(' ', $args) . "\n" . trim((string) $stderr));
    }

    return $stdout;
}

function runCommand(array $command, ?string &$stderr = null, ?int &$status = null, bool $throwOnFailure = true): string
{
    $escaped = array_map('escapeshellarg', $command);
    $stderrFile = tempnam(sys_get_temp_dir(), 'wp-apply-stderr-');
    if ($stderrFile === false) {
        throw new RuntimeException('Unable to create temporary stderr file.');
    }

    $descriptor = [
        1 => ['pipe', 'w'],
        2 => ['file', $stderrFile, 'w'],
    ];

    $process = proc_open(implode(' ', $escaped), $descriptor, $pipes);
    if (!is_resource($process)) {
        @unlink($stderrFile);
        throw new RuntimeException('Unable to run command.');
    }

    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $status = proc_close($process);
    $stderr = (string) file_get_contents($stderrFile);
    @unlink($stderrFile);

    if ($status !== 0 && $throwOnFailure) {
        throw new RuntimeException("Command failed: " . implode(' ', $command) . "\n" . trim($stderr));
    }

    return (string) $stdout;
}

function parseCsvOption($value): array
{
    if (!is_string($value) || trim($value) === '') {
        return [];
    }

    return array_values(array_filter(array_map('trim', explode(',', $value)), static function (string $item): bool {
        return $item !== '';
    }));
}

function compareVersions(string $a, string $b): int
{
    return version_compare(normalizeVersion($a), normalizeVersion($b));
}

function normalizeVersion(string $version): string
{
    return preg_replace('/[^0-9A-Za-z.+_-]/', '', trim($version)) ?: '0';
}

function safeFileName(string $value): string
{
    return preg_replace('/[^A-Za-z0-9_.-]+/', '-', $value) ?: 'site';
}
