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

function assertApplyThrows(callable $callback, string $expectedMessage, string $message): void
{
    try {
        $callback();
    } catch (RuntimeException $exception) {
        assertApplyTrue(strpos($exception->getMessage(), $expectedMessage) !== false, $message . ' Expected message containing: ' . $expectedMessage);
        return;
    }

    fwrite(STDERR, $message . "\n");
    exit(1);
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
    assertApplyTrue(strpos((string) $update['stderr'], 'Restored plugin files from backup') !== false, 'Restore should be noted in stderr.');

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
