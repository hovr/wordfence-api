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
require_once __DIR__ . '/email_helpers.php';

if (realpath((string) ($_SERVER['SCRIPT_FILENAME'] ?? '')) === __FILE__) {
    main($argv);
}

function main(array $argv): void
{
    try {
        $cliOptions = parseOptions($argv);
        $options = loadApplySettings($cliOptions);
    } catch (RuntimeException $exception) {
        fwrite(STDERR, $exception->getMessage() . "\n\n");
        printUsage();
        exit(1);
    }

    $policyPath = (string) ($options['policy'] ?? '');
    if ($policyPath === '' || !is_file($policyPath)) {
        fwrite(STDERR, "Missing or invalid --policy path.\n\n");
        printUsage();
        exit(1);
    }

    try {
        $policy = loadPolicy($policyPath);
        assertPolicyFresh($policy, (int) ($options['max-policy-age'] ?? 86400));
        $sitePath = rtrim((string) ($options['site'] ?? $policy['site_path'] ?? ''), DIRECTORY_SEPARATOR);
        if ($sitePath === '' || !is_dir($sitePath)) {
            throw new RuntimeException('Missing or invalid site path. Pass --site or regenerate the policy with a valid site_path.');
        }

        loadConfigForOptions([
            'site' => $sitePath,
            'config' => $options['config'] ?? null,
        ]);
    } catch (RuntimeException $exception) {
        fwrite(STDERR, $exception->getMessage() . "\n\n");
        printUsage();
        exit(1);
    }

    $siteKey = (string) ($options['site-key'] ?? $policy['site_key'] ?? basename($sitePath));
    $wpBinary = (string) ($options['wp'] ?? 'wp');
    $wpUser = optionalWpUser($options);
    $mode = strtolower((string) ($options['mode'] ?? 'all'));
    if (!in_array($mode, ['normal', 'emergency', 'all'], true)) {
        fwrite(STDERR, "Invalid --mode. Use normal, emergency, or all.\n");
        exit(1);
    }

    $apply = array_key_exists('apply', $cliOptions);
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
    $premiumPlugins = parseCsvOption($options['premium-plugins'] ?? '');

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
        $updates = plannedUpdates($policy, $mode, $filters, $premiumPlugins);
        $summary['updates'] = $updates;

        if ($apply && $updates !== []) {
            if ($backupDb) {
                $summary['backup'] = backupDatabase($wpBinary, $sitePath, $siteKey, (string) ($options['backup-dir'] ?? __DIR__ . '/backups'), $wpUser);
            }

            if ($maintenance) {
                runWp($wpBinary, $sitePath, ['maintenance-mode', 'activate'], false, $wpUser);
                $maintenanceActive = true;
                $summary['maintenance'] = true;
            }

            foreach ($summary['updates'] as &$update) {
                applyUpdate(
                    $wpBinary,
                    $sitePath,
                    $update,
                    $wpUser,
                    (string) ($options['plugin-backup-dir'] ?? defaultPluginBackupRoot($sitePath))
                );
            }
            unset($update);
        }
    } catch (RuntimeException $exception) {
        $summary['error'] = $exception->getMessage();
        fwrite(STDERR, $exception->getMessage() . "\n");
    } finally {
        if ($maintenanceActive) {
            runWp($wpBinary, $sitePath, ['maintenance-mode', 'deactivate'], true, $wpUser);
        }

        if (is_resource($lockHandle)) {
            releaseLock($lockHandle);
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
  --wp-user=USER      Optional. Run WP-CLI via sudo -u USER.
  --site=PATH         Optional override for policy site_path.
  --config=PATH       Optional private config file to parse before wp-config.php.
  --site-key=VALUE    Optional override for policy site_key.
  --policy-settings=PATH Optional JSON settings file for apply options.
  --backup-db         Export database before applying updates.
  --backup-dir=PATH   Optional backup directory. Default: ./backups.
  --plugin-backup-dir=PATH Optional plugin file backup directory. Default: private system temp directory.
  --maintenance       Activate maintenance mode while applying updates.
  --core-only         Only consider WordPress core.
  --plugins-only      Only consider plugins.
  --plugin=SLUG       Only consider one plugin slug.
  --exclude=SLUGS     Comma-separated plugin slugs to skip.
  --premium-plugins=SLUGS Comma-separated plugin slugs to update without --version.
  --notify-email=ADDR Email for manual_review notifications.
  --no-notify         Disable manual_review email notifications.
  --lock-file=PATH    Optional lock file path.
  --max-policy-age=N  Maximum policy age in seconds before apply/dry-run fails. Default: 86400. Use 0 to disable.

TEXT;
}

function loadApplySettings(array $cliOptions): array
{
    return loadOptionsWithSettings($cliOptions);
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

function assertPolicyFresh(array $policy, int $maxAgeSeconds): void
{
    if ($maxAgeSeconds <= 0) {
        return;
    }

    $generatedAt = (string) ($policy['generated_at'] ?? '');
    $generatedTimestamp = $generatedAt === '' ? false : strtotime($generatedAt);
    if ($generatedTimestamp === false) {
        throw new RuntimeException('Policy is missing a valid generated_at timestamp. Regenerate the policy before applying updates.');
    }

    $age = time() - $generatedTimestamp;
    if ($age < 0) {
        throw new RuntimeException('Policy generated_at timestamp is in the future. Regenerate the policy before applying updates.');
    }

    if ($age > $maxAgeSeconds) {
        throw new RuntimeException("Policy is {$age} seconds old, exceeding the {$maxAgeSeconds} second limit. Regenerate the policy before applying updates or pass --max-policy-age=0 to override.");
    }
}

function plannedUpdates(array $policy, string $mode, array $filters, array $premiumPlugins = []): array
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

            $update = plannedAssetUpdate($plugin, $mode, $premiumPlugins);
            if ($update !== null) {
                $updates[] = $update;
            }
        }
    }

    return $updates;
}

function plannedAssetUpdate(array $asset, string $mode, array $premiumPlugins = []): ?array
{
    $action = (string) ($asset['recommended_action'] ?? 'hold');
    if ($action === 'manual_review' || $action === 'hold') {
        return null;
    }

    $candidates = [];
    if (($mode === 'normal' || $mode === 'all') && !empty($asset['allowed_update_version'])) {
        $candidates[] = [
            'target' => (string) $asset['allowed_update_version'],
            'reason' => 'normal',
        ];
    }

    if (($mode === 'emergency' || $mode === 'all') && !empty($asset['current_is_vulnerable']) && !empty($asset['emergency_update_version'])) {
        $candidates[] = [
            'target' => (string) $asset['emergency_update_version'],
            'reason' => 'emergency',
        ];
    }

    $selected = newestUpdateCandidate($candidates);
    $target = $selected['target'] ?? null;
    $reason = $selected['reason'] ?? null;

    if ($target === null || compareVersions($target, (string) ($asset['current_version'] ?? '')) <= 0) {
        return null;
    }

    $type = (string) ($asset['type'] ?? '');
    $slug = (string) ($asset['slug'] ?? '');

    return [
        'type' => $type,
        'slug' => $slug,
        'name' => (string) ($asset['name'] ?? ''),
        'from_version' => (string) ($asset['current_version'] ?? ''),
        'to_version' => $target,
        'reason' => $reason,
        'premium_plugin' => $type === 'plugin' && in_array($slug, $premiumPlugins, true),
        'status' => 'planned',
        'stdout' => null,
        'stderr' => null,
    ];
}

function newestUpdateCandidate(array $candidates): ?array
{
    $selected = null;

    foreach ($candidates as $candidate) {
        if (!is_array($candidate) || empty($candidate['target'])) {
            continue;
        }

        if ($selected === null || compareVersions((string) $candidate['target'], (string) $selected['target']) > 0) {
            $selected = $candidate;
        }
    }

    return $selected;
}

function passesPluginFilters(array $plugin, array $filters): bool
{
    $slug = (string) ($plugin['slug'] ?? '');

    if ($filters['plugin'] !== null && $slug !== $filters['plugin']) {
        return false;
    }

    return !in_array($slug, $filters['exclude'], true);
}

function applyUpdate(string $wpBinary, string $sitePath, array &$update, ?string $wpUser, string $pluginBackupDir): void
{
    $pluginBackup = null;

    if ($update['type'] === 'core') {
        $args = ['core', 'update', '--version=' . $update['to_version']];
    } elseif ($update['type'] === 'plugin') {
        $args = ['plugin', 'update', $update['slug']];
        if (empty($update['premium_plugin'])) {
            $args[] = '--version=' . $update['to_version'];
        }
    } else {
        $update['status'] = 'skipped';
        $update['stderr'] = 'Unsupported update type.';
        return;
    }

    try {
        verifyLiveVersionBeforeUpdate($wpBinary, $sitePath, $update, $wpUser);
    } catch (RuntimeException $exception) {
        $update['status'] = 'failed';
        $update['stderr'] = $exception->getMessage();
        throw $exception;
    }

    if ($update['status'] === 'skipped') {
        return;
    }

    if ($update['type'] === 'plugin') {
        $pluginBackup = backupPluginDirectory($sitePath, (string) $update['slug'], $pluginBackupDir);
        $update['plugin_backup'] = $pluginBackup;
    }

    $stdout = runWp($wpBinary, $sitePath, $args, true, $wpUser, $stderr, $status);
    $update['stdout'] = trim($stdout);
    $update['stderr'] = trim((string) $stderr);
    $update['status'] = $status === 0 ? 'updated' : 'failed';

    if ($status !== 0) {
        restorePluginBackupAfterFailure($sitePath, $update, $pluginBackup);
        $message = "Update failed for {$update['type']} {$update['slug']}: " . trim($stderr);
        throw new RuntimeException(appendRestoreFailureMessage($message, $update));
    }

    try {
        verifyLiveVersionAfterUpdate($wpBinary, $sitePath, $update, $wpUser);
    } catch (RuntimeException $exception) {
        restorePluginBackupAfterFailure($sitePath, $update, $pluginBackup);
        $message = appendRestoreFailureMessage($exception->getMessage(), $update);
        throw new RuntimeException($message, 0, $exception);
    }
}

function verifyLiveVersionBeforeUpdate(string $wpBinary, string $sitePath, array &$update, ?string $wpUser): void
{
    $liveVersion = liveAssetVersion($wpBinary, $sitePath, (string) $update['type'], (string) $update['slug'], $wpUser);
    $update['live_version'] = $liveVersion;

    if (compareVersions($liveVersion, (string) $update['to_version']) >= 0) {
        $update['status'] = 'skipped';
        $update['stdout'] = null;
        $update['stderr'] = "Live version {$liveVersion} is already at or newer than target {$update['to_version']}.";
        return;
    }

    if (compareVersions($liveVersion, (string) $update['from_version']) !== 0) {
        $asset = updateLabel($update);
        $update['status'] = 'failed';
        $update['stderr'] = "Live version {$liveVersion} does not match policy version {$update['from_version']} for {$asset}. Regenerate the policy before applying updates.";
        throw new RuntimeException($update['stderr']);
    }
}

function liveAssetVersion(string $wpBinary, string $sitePath, string $type, string $slug, ?string $wpUser): string
{
    if ($type === 'core') {
        return trim(runWp($wpBinary, $sitePath, ['core', 'version'], false, $wpUser));
    }

    if ($type === 'plugin') {
        return trim(runWp($wpBinary, $sitePath, ['plugin', 'get', $slug, '--field=version'], false, $wpUser));
    }

    throw new RuntimeException("Unsupported update type: {$type}");
}

function verifyLiveVersionAfterUpdate(string $wpBinary, string $sitePath, array &$update, ?string $wpUser): void
{
    $liveVersion = liveAssetVersion($wpBinary, $sitePath, (string) $update['type'], (string) $update['slug'], $wpUser);
    $update['installed_version'] = $liveVersion;

    if (compareVersions($liveVersion, (string) $update['to_version']) < 0) {
        $update['status'] = 'failed';
        $update['stderr'] = trim((string) ($update['stderr'] ?? '') . "\nInstalled version {$liveVersion} is below policy target {$update['to_version']}.");
        throw new RuntimeException("Update failed for {$update['type']} {$update['slug']}: installed version {$liveVersion} is below policy target {$update['to_version']}.");
    }

    if (!empty($update['premium_plugin']) && compareVersions($liveVersion, (string) $update['to_version']) > 0) {
        $update['status'] = 'updated_beyond_policy';
        $update['stderr'] = trim((string) ($update['stderr'] ?? '') . "\nPremium plugin updated beyond policy target {$update['to_version']} to {$liveVersion}.");
    }
}

function updateLabel(array $update): string
{
    $type = (string) ($update['type'] ?? 'asset');
    $slug = (string) ($update['slug'] ?? '');

    return $slug === '' ? $type : "{$type} {$slug}";
}

function backupDatabase(string $wpBinary, string $sitePath, string $siteKey, string $backupDir, ?string $wpUser): array
{
    ensureDirectory($backupDir);
    $backupPath = rtrim($backupDir, DIRECTORY_SEPARATOR)
        . DIRECTORY_SEPARATOR
        . safeFileName($siteKey) . '-' . gmdate('Ymd-His') . '.sql';

    $stdout = runWp($wpBinary, $sitePath, ['db', 'export', $backupPath], false, $wpUser, $stderr, $status);
    if ($status !== 0) {
        throw new RuntimeException('Database backup failed: ' . trim($stderr));
    }

    return [
        'path' => $backupPath,
        'stdout' => trim($stdout),
    ];
}

function backupPluginDirectory(string $sitePath, string $slug, string $backupRoot): array
{
    $pluginPath = pluginPathFromSlug($sitePath, $slug);
    if (!file_exists($pluginPath) && !is_link($pluginPath)) {
        throw new RuntimeException("Plugin path does not exist before update: {$pluginPath}");
    }

    $pluginsDir = pluginBaseDirectory($sitePath);
    $sourcePath = normalizedAbsolutePath($pluginPath);
    $backupRootPath = normalizedAbsolutePath($backupRoot);
    if (pathIsWithin($backupRootPath, $pluginsDir)) {
        throw new RuntimeException('Plugin backup directory must be outside wp-content/plugins.');
    }

    if (pathIsWithin($backupRootPath, $sourcePath)) {
        throw new RuntimeException('Plugin backup directory must not be inside the plugin being backed up.');
    }

    ensurePrivateDirectory($backupRootPath);

    $backupPath = $backupRootPath
        . DIRECTORY_SEPARATOR
        . safeFileName(basename($sitePath)) . '-'
        . safeFileName($slug) . '-'
        . gmdate('Ymd-His') . '-'
        . bin2hex(random_bytes(4));

    copyPath($pluginPath, $backupPath);

    return [
        'source' => $pluginPath,
        'path' => $backupPath,
        'kind' => is_dir($pluginPath) && !is_link($pluginPath) ? 'directory' : 'file',
    ];
}

function restorePluginBackupAfterFailure(string $sitePath, array &$update, ?array $pluginBackup): void
{
    if ($pluginBackup === null || ($update['type'] ?? null) !== 'plugin') {
        return;
    }

    $pluginPath = pluginPathFromSlug($sitePath, (string) $update['slug']);
    $backupPath = (string) ($pluginBackup['path'] ?? '');
    if ($backupPath === '' || (!file_exists($backupPath) && !is_link($backupPath))) {
        $update['plugin_restore'] = [
            'status' => 'failed',
            'stderr' => 'Plugin backup path is missing.',
        ];
        return;
    }

    $restoreParent = dirname($pluginPath);
    $restoreTemp = $restoreParent
        . DIRECTORY_SEPARATOR
        . '.restore-' . safeFileName(basename($pluginPath)) . '-' . bin2hex(random_bytes(4));
    $failedPath = null;

    try {
        ensureDirectory($restoreParent);
        copyPath($backupPath, $restoreTemp);

        if (file_exists($pluginPath) || is_link($pluginPath)) {
            $failedPath = $pluginPath . '.failed-' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(4));
            if (!rename($pluginPath, $failedPath)) {
                throw new RuntimeException("Unable to quarantine failed plugin path: {$pluginPath}");
            }
        }

        if (!rename($restoreTemp, $pluginPath)) {
            if ($failedPath !== null && (file_exists($failedPath) || is_link($failedPath)) && !file_exists($pluginPath)) {
                if (!rename($failedPath, $pluginPath)) {
                    throw new RuntimeException("Unable to move restored plugin backup into place: {$pluginPath}; original plugin also remains quarantined at {$failedPath}.");
                }

                $failedPath = null;
            }
            throw new RuntimeException("Unable to move restored plugin backup into place: {$pluginPath}");
        }

        $update['plugin_restore'] = [
            'status' => 'restored',
            'path' => $pluginPath,
            'backup' => $backupPath,
        ];
        $update['stderr'] = trim((string) ($update['stderr'] ?? '') . "\nRestored plugin files from backup after failed update.");

        if ($failedPath !== null) {
            try {
                removePath($failedPath);
            } catch (RuntimeException $cleanupException) {
                $update['plugin_restore']['cleanup_status'] = 'failed';
                $update['plugin_restore']['cleanup_stderr'] = $cleanupException->getMessage();
                $update['stderr'] = trim((string) ($update['stderr'] ?? '') . "\nRestored plugin, but cleanup of failed update path failed: " . $cleanupException->getMessage());
            }
        }
    } catch (RuntimeException $exception) {
        if (file_exists($restoreTemp) || is_link($restoreTemp)) {
            removePath($restoreTemp);
        }

        $update['plugin_restore'] = [
            'status' => 'failed',
            'stderr' => $exception->getMessage(),
            'backup' => $backupPath,
        ];
        $update['stderr'] = trim((string) ($update['stderr'] ?? '') . "\nPlugin file restore failed: " . $exception->getMessage());
    }
}

function appendRestoreFailureMessage(string $message, array $update): string
{
    $restore = $update['plugin_restore'] ?? null;
    if (!is_array($restore) || ($restore['status'] ?? null) !== 'failed') {
        return $message;
    }

    return trim($message . "\nPlugin restore failed: " . (string) ($restore['stderr'] ?? 'Unknown restore failure.'));
}

function defaultPluginBackupRoot(string $sitePath): string
{
    return rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR)
        . DIRECTORY_SEPARATOR
        . 'wp-update-plugin-backups'
        . DIRECTORY_SEPARATOR
        . safeFileName(basename($sitePath));
}

function pluginDirectoryPath(string $sitePath, string $slug): string
{
    return pluginPathFromSlug($sitePath, $slug);
}

function pluginPathFromSlug(string $sitePath, string $slug): string
{
    validatePluginSlug($slug);

    return pluginBaseDirectory($sitePath) . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $slug);
}

function pluginBaseDirectory(string $sitePath): string
{
    $pluginsDir = rtrim($sitePath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins';
    $realPluginsDir = realpath($pluginsDir);
    if ($realPluginsDir === false || !is_dir($realPluginsDir)) {
        throw new RuntimeException("WordPress plugin directory does not exist: {$pluginsDir}");
    }

    return $realPluginsDir;
}

function validatePluginSlug(string $slug): void
{
    if ($slug === '' || $slug[0] === '/' || strpos($slug, "\0") !== false || strpos($slug, '\\') !== false || strpos($slug, ':') !== false) {
        throw new RuntimeException('Invalid plugin slug.');
    }

    foreach (explode('/', $slug) as $segment) {
        if ($segment === '' || $segment === '.' || $segment === '..') {
            throw new RuntimeException('Invalid plugin slug.');
        }
    }
}

function normalizedAbsolutePath(string $path): string
{
    if ($path === '') {
        throw new RuntimeException('Path must not be empty.');
    }

    $absolute = $path[0] === DIRECTORY_SEPARATOR ? $path : getcwd() . DIRECTORY_SEPARATOR . $path;
    $realPath = realpath($absolute);
    if ($realPath !== false) {
        return $realPath;
    }

    $missing = [];
    $candidate = $absolute;
    while ($candidate !== '' && $candidate !== DIRECTORY_SEPARATOR && realpath($candidate) === false) {
        array_unshift($missing, basename($candidate));
        $candidate = dirname($candidate);
    }

    $base = realpath($candidate);
    if ($base === false) {
        $base = DIRECTORY_SEPARATOR;
    }

    foreach ($missing as $part) {
        if ($part === '' || $part === '.') {
            continue;
        }

        if ($part === '..') {
            $base = dirname($base);
            continue;
        }

        $base = rtrim($base, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $part;
    }

    return $base;
}

function pathIsWithin(string $path, string $parent): bool
{
    $path = rtrim(normalizedAbsolutePath($path), DIRECTORY_SEPARATOR);
    $parent = rtrim(normalizedAbsolutePath($parent), DIRECTORY_SEPARATOR);

    return $path === $parent || strpos($path . DIRECTORY_SEPARATOR, $parent . DIRECTORY_SEPARATOR) === 0;
}

function ensurePrivateDirectory(string $directory): void
{
    ensureDirectory($directory);
    if (!chmod($directory, 0700)) {
        throw new RuntimeException("Unable to restrict directory permissions: {$directory}");
    }
}

function copyPath(string $source, string $destination): void
{
    if (is_dir($source) && !is_link($source)) {
        copyDirectory($source, $destination);
        return;
    }

    copyFileOrLink($source, $destination);
}

function copyDirectory(string $source, string $destination): void
{
    if (!is_dir($source) || is_link($source)) {
        throw new RuntimeException("Source directory does not exist: {$source}");
    }

    if (file_exists($destination) || is_link($destination)) {
        throw new RuntimeException("Destination already exists: {$destination}");
    }

    ensureDirectory($destination);
    applyCopiedPathMetadata($source, $destination);

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iterator as $item) {
        $target = $destination . DIRECTORY_SEPARATOR . $iterator->getSubPathName();
        if ($item->isDir() && !$item->isLink()) {
            ensureDirectory($target);
            applyCopiedPathMetadata($item->getPathname(), $target, $item);
            continue;
        }

        copyFileOrLink($item->getPathname(), $target, $item);
    }
}

function copyFileOrLink(string $source, string $destination, ?SplFileInfo $item = null): void
{
    if (file_exists($destination) || is_link($destination)) {
        throw new RuntimeException("Destination already exists: {$destination}");
    }

    ensureDirectory(dirname($destination));

    if (is_link($source)) {
        $linkTarget = readlink($source);
        if ($linkTarget === false || !symlink($linkTarget, $destination)) {
            throw new RuntimeException("Unable to copy symlink: {$source}");
        }
        applyCopiedPathMetadata($source, $destination, $item);
        return;
    }

    if (!is_file($source)) {
        throw new RuntimeException("Source file does not exist: {$source}");
    }

    if (!copy($source, $destination)) {
        throw new RuntimeException("Unable to copy file: {$source}");
    }

    applyCopiedPathMetadata($source, $destination, $item);
    touch($destination, filemtime($source));
}

function applyCopiedPathMetadata(string $source, string $destination, ?SplFileInfo $item = null): void
{
    $owner = $item instanceof SplFileInfo ? $item->getOwner() : fileowner($source);
    $group = $item instanceof SplFileInfo ? $item->getGroup() : filegroup($source);
    $mode = $item instanceof SplFileInfo ? $item->getPerms() : fileperms($source);

    if (is_link($destination)) {
        if ($owner !== false && function_exists('lchown')) {
            @lchown($destination, $owner);
        }
        if ($group !== false && function_exists('lchgrp')) {
            @lchgrp($destination, $group);
        }
        return;
    }

    if ($owner !== false) {
        @chown($destination, $owner);
    }
    if ($group !== false) {
        @chgrp($destination, $group);
    }
    if ($mode !== false) {
        chmod($destination, $mode & 0777);
    }
}

function removePath(string $path): void
{
    if (is_dir($path) && !is_link($path)) {
        removeDirectory($path);
        return;
    }

    if ((file_exists($path) || is_link($path)) && !unlink($path)) {
        throw new RuntimeException("Unable to remove file: {$path}");
    }
}

function removeDirectory(string $directory): void
{
    if (!is_dir($directory) || is_link($directory)) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($iterator as $item) {
        if ($item->isDir() && !$item->isLink()) {
            if (!rmdir($item->getPathname())) {
                throw new RuntimeException("Unable to remove directory: {$item->getPathname()}");
            }
            continue;
        }

        if (!unlink($item->getPathname())) {
            throw new RuntimeException("Unable to remove file: {$item->getPathname()}");
        }
    }

    if (!rmdir($directory)) {
        throw new RuntimeException("Unable to remove directory: {$directory}");
    }
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
    $delivery = sendUpdaterEmail($email, $subject, $body);
    return [
        'sent' => $delivery['sent'],
        'to' => $email,
        'reason' => $delivery['reason'] ?? null,
        'transport' => $delivery['transport'] ?? null,
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

function releaseLock($handle): void
{
    ftruncate($handle, 0);
    flock($handle, LOCK_UN);
    fclose($handle);
}

function runWp(string $wpBinary, string $sitePath, array $args, bool $allowFailure = false, ?string $wpUser = null, ?string &$stderr = null, ?int &$status = null): string
{
    $command = wpCliCommand($wpBinary, $sitePath, $args, $wpUser);
    $stdout = runCommand($command, $stderr, $status, false, 'wp-apply-stderr-');

    if ($status !== 0 && !$allowFailure) {
        throw new RuntimeException("WP-CLI failed: " . implode(' ', $args) . "\n" . trim((string) $stderr));
    }

    return $stdout;
}

function wpCliCommand(string $wpBinary, string $sitePath, array $args, ?string $wpUser): array
{
    $command = [$wpBinary, '--path=' . $sitePath];
    if ($wpUser !== null) {
        $command = ['sudo', '-u', $wpUser, '--', $wpBinary, '--path=' . $sitePath];
    }

    return array_merge($command, $args);
}

function optionalWpUser(array $options): ?string
{
    if (empty($options['wp-user'])) {
        return null;
    }

    $user = (string) $options['wp-user'];
    if (!preg_match('/^[A-Za-z0-9._-]+$/', $user)) {
        throw new RuntimeException('Invalid --wp-user value.');
    }

    return $user;
}

function parseCsvOption($value): array
{
    if (is_array($value)) {
        return array_values(array_filter(array_map(static fn($item): string => trim((string) $item), $value), static function (string $item): bool {
            return $item !== '';
        }));
    }

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
