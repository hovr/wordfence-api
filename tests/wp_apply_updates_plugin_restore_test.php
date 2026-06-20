<?php
declare(strict_types=1);

require_once __DIR__ . '/../wp_apply_updates.php';

function assertApplyTrue(bool $actual, string $message): void
{
    if (!$actual) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

function assertApplyThrows(callable $callback, string $expectedMessage, string $message): RuntimeException
{
    try {
        $callback();
    } catch (RuntimeException $exception) {
        assertApplyTrue(strpos($exception->getMessage(), $expectedMessage) !== false, $message . ' Expected message containing: ' . $expectedMessage);
        return $exception;
    }

    fwrite(STDERR, $message . "\n");
    exit(1);
}

function writeWpStub(string $path, string $statePath, string $pluginFile, string $mode): void
{
    $script = <<<'PHP'
#!/usr/bin/env php
<?php
$statePath = STATE_PATH;
$pluginFile = PLUGIN_FILE;
$mode = MODE;
$args = array_values(array_filter(array_slice($argv, 1), static fn(string $arg): bool => strpos($arg, '--path=') !== 0));

if (array_slice($args, 0, 2) === ['plugin', 'get']) {
    $count = is_file($statePath) ? (int) file_get_contents($statePath) : 0;
    file_put_contents($statePath, (string) ($count + 1));
    if ($mode === 'verification_failure' && $count > 0) {
        fwrite(STDOUT, "1.5\n");
        exit(0);
    }

    fwrite(STDOUT, "1.0\n");
    exit(0);
}

if (array_slice($args, 0, 2) === ['plugin', 'update']) {
    file_put_contents($pluginFile, "<?php\n// broken update\n");
    if ($mode === 'update_failure') {
        fwrite(STDERR, "simulated update failure\n");
        exit(1);
    }

    fwrite(STDOUT, "simulated update success\n");
    exit(0);
}

fwrite(STDERR, 'unexpected command: ' . implode(' ', $args) . "\n");
exit(1);
PHP;

    $script = str_replace(
        ['STATE_PATH', 'PLUGIN_FILE', 'MODE'],
        [var_export($statePath, true), var_export($pluginFile, true), var_export($mode, true)],
        $script
    );

    file_put_contents($path, $script);
    chmod($path, 0755);
}

function pluginUpdateFixture(string $pluginPath): array
{
    removeDirectory($pluginPath);
    ensureDirectory($pluginPath);
    file_put_contents($pluginPath . '/example-plugin.php', "<?php\n// original plugin\n");

    return [
        'type' => 'plugin',
        'slug' => 'example-plugin',
        'name' => 'Example Plugin',
        'from_version' => '1.0',
        'to_version' => '2.0',
        'reason' => 'normal',
        'premium_plugin' => false,
        'status' => 'planned',
        'stdout' => null,
        'stderr' => null,
    ];
}

$root = sys_get_temp_dir() . '/wp-apply-plugin-restore-' . bin2hex(random_bytes(4));
$sitePath = $root . '/site';
$pluginsPath = $sitePath . '/wp-content/plugins';
$pluginPath = $pluginsPath . '/example-plugin';
$singleFilePluginPath = $pluginsPath . '/hello.php';
$backupRoot = $root . '/backups';

try {
    ensureDirectory($pluginPath . '/includes');
    chmod($pluginPath . '/includes', 0750);
    file_put_contents($pluginPath . '/example-plugin.php', "<?php\n// plugin\n");
    file_put_contents($pluginPath . '/includes/admin.php', "<?php\n// admin\n");

    $backup = backupPluginDirectory($sitePath, 'example-plugin', $backupRoot);
    removeDirectory($pluginPath);
    ensureDirectory($pluginPath);

    $update = [
        'type' => 'plugin',
        'slug' => 'example-plugin',
        'stderr' => 'Update failed.',
    ];
    restorePluginBackupAfterFailure($sitePath, $update, $backup);

    assertApplyTrue(($update['plugin_restore']['status'] ?? null) === 'restored', 'Plugin backup should be restored after failure.');
    assertApplyTrue(is_file($pluginPath . '/example-plugin.php'), 'Main plugin file should be restored.');
    assertApplyTrue(is_file($pluginPath . '/includes/admin.php'), 'Nested plugin file should be restored.');
    assertApplyTrue((fileperms($pluginPath . '/includes') & 0777) === 0750, 'Nested directory permissions should be restored.');
    assertApplyTrue(fileowner($pluginPath . '/includes/admin.php') === fileowner($backup['path'] . '/includes/admin.php'), 'Nested file owner should be restored from backup.');
    assertApplyTrue(filegroup($pluginPath . '/includes/admin.php') === filegroup($backup['path'] . '/includes/admin.php'), 'Nested file group should be restored from backup.');
    assertApplyTrue(strpos((string) $update['stderr'], 'Restored plugin files from backup') !== false, 'Restore should be noted in stderr.');

    assertPluginUpdateWritable($sitePath, 'example-plugin', null);
    if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
        chmod($pluginPath . '/includes/admin.php', 0444);
        assertApplyThrows(
            static fn() => assertPluginUpdateWritable($sitePath, 'example-plugin', null),
            'Plugin path is not writable',
            'Unwritable plugin files should fail preflight before WP-CLI runs.'
        );
        chmod($pluginPath . '/includes/admin.php', 0644);
    }

    file_put_contents($singleFilePluginPath, "<?php\n// single file plugin\n");
    chmod($singleFilePluginPath, 0640);
    $singleFileBackup = backupPluginDirectory($sitePath, 'hello.php', $backupRoot);
    unlink($singleFilePluginPath);

    $singleFileUpdate = [
        'type' => 'plugin',
        'slug' => 'hello.php',
        'stderr' => 'Update failed.',
    ];
    restorePluginBackupAfterFailure($sitePath, $singleFileUpdate, $singleFileBackup);
    assertApplyTrue(($singleFileUpdate['plugin_restore']['status'] ?? null) === 'restored', 'Single-file plugin backup should be restored.');
    assertApplyTrue(is_file($singleFilePluginPath), 'Single-file plugin should exist after restore.');
    assertApplyTrue((fileperms($singleFilePluginPath) & 0777) === 0640, 'Single-file plugin permissions should be restored.');

    assertApplyThrows(
        static fn() => pluginDirectoryPath($sitePath, '../evil'),
        'Invalid plugin slug',
        'Path traversal plugin slugs should be rejected.'
    );

    assertApplyThrows(
        static fn() => backupPluginDirectory($sitePath, 'example-plugin', $pluginsPath . '/plugin-backups'),
        'outside wp-content/plugins',
        'Backup roots inside wp-content/plugins should be rejected.'
    );

    assertApplyThrows(
        static fn() => backupPluginDirectory($sitePath, 'example-plugin', $pluginPath . '/backups'),
        'outside wp-content/plugins',
        'Backup roots inside the plugin source should be rejected.'
    );

    $wpStub = $root . '/wp-stub.php';
    $statePath = $root . '/wp-state.txt';

    $failedUpdate = pluginUpdateFixture($pluginPath);
    writeWpStub($wpStub, $statePath, $pluginPath . '/example-plugin.php', 'update_failure');
    assertApplyThrows(
        static function () use ($wpStub, $sitePath, &$failedUpdate, $backupRoot): void {
            applyUpdate($wpStub, $sitePath, $failedUpdate, null, $backupRoot);
        },
        'simulated update failure',
        'WP-CLI update failures should throw.'
    );
    assertApplyTrue(($failedUpdate['plugin_restore']['status'] ?? null) === 'restored', 'WP-CLI update failure should restore plugin backup.');
    assertApplyTrue(file_get_contents($pluginPath . '/example-plugin.php') === "<?php\n// original plugin\n", 'WP-CLI update failure should restore original plugin file contents.');
    unlink($statePath);

    $verificationFailure = pluginUpdateFixture($pluginPath);
    writeWpStub($wpStub, $statePath, $pluginPath . '/example-plugin.php', 'verification_failure');
    assertApplyThrows(
        static function () use ($wpStub, $sitePath, &$verificationFailure, $backupRoot): void {
            applyUpdate($wpStub, $sitePath, $verificationFailure, null, $backupRoot);
        },
        'installed version 1.5 is below policy target 2.0',
        'Post-update verification failures should throw.'
    );
    assertApplyTrue(($verificationFailure['plugin_restore']['status'] ?? null) === 'restored', 'Post-update verification failure should restore plugin backup.');
    assertApplyTrue(file_get_contents($pluginPath . '/example-plugin.php') === "<?php\n// original plugin\n", 'Post-update verification failure should restore original plugin file contents.');

    $missingBackupUpdate = [
        'type' => 'plugin',
        'slug' => 'example-plugin',
        'stderr' => 'Update failed.',
    ];
    restorePluginBackupAfterFailure($sitePath, $missingBackupUpdate, ['path' => $root . '/missing-backup']);
    assertApplyTrue(($missingBackupUpdate['plugin_restore']['status'] ?? null) === 'failed', 'Missing backup should be reported as a failed restore.');
    assertApplyTrue(is_dir($pluginPath), 'Existing plugin directory should remain when backup is missing.');
} finally {
    removeDirectory($root);
}

fwrite(STDOUT, "wp_apply_updates plugin restore tests passed\n");
