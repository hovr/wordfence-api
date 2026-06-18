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

$root = sys_get_temp_dir() . '/wp-apply-plugin-restore-' . bin2hex(random_bytes(4));
$sitePath = $root . '/site';
$pluginPath = $sitePath . '/wp-content/plugins/example-plugin';
$backupRoot = $root . '/backups';

ensureDirectory($pluginPath . '/includes');
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
assertApplyTrue(strpos((string) $update['stderr'], 'Restored plugin files from backup') !== false, 'Restore should be noted in stderr.');

removeDirectory($root);

fwrite(STDOUT, "wp_apply_updates plugin restore tests passed\n");
