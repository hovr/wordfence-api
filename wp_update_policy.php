<?php
declare(strict_types=1);

/**
 * Inspect a WordPress install with WP-CLI, record first-seen update versions,
 * check installed/candidate versions against the local Wordfence vulnerability
 * table, and emit an update policy JSON file for a separate updater script.
 *
 * Usage:
 *   php wp_update_policy.php --site=/path/to/wordpress
 *   php wp_update_policy.php --site=/path/to/wordpress --refresh-wordfence
 *   php wp_update_policy.php --site=/path/to/wordpress --wp=/usr/local/bin/wp --normal-days=7 --emergency-days=2
 */

const DEFAULT_VULN_TABLE = 'wordfence_plugin_vulnerabilities';
const DEFAULT_ASSETS_TABLE = 'wp_update_assets';
const DEFAULT_VERSIONS_TABLE = 'wp_update_versions';
const DEFAULT_POLICY_DIR = 'policies';

main($argv);

function main(array $argv): void
{
    $options = parseOptions($argv);
    $sitePath = rtrim((string) ($options['site'] ?? ''), DIRECTORY_SEPARATOR);
    if ($sitePath === '' || !is_dir($sitePath)) {
        fwrite(STDERR, "Missing or invalid --site path.\n\n");
        printUsage();
        exit(1);
    }

    loadConfigForOptions($options);
    requireDbClass();

    $wpBinary = (string) ($options['wp'] ?? 'wp');
    $siteKey = (string) ($options['site-key'] ?? basename($sitePath));
    $normalDays = parsePositiveInt((string) ($options['normal-days'] ?? '7'), 7);
    $emergencyDays = parsePositiveInt((string) ($options['emergency-days'] ?? '2'), 2);
    $vulnTable = (string) ($options['vuln-table'] ?? DEFAULT_VULN_TABLE);
    $assetsTable = (string) ($options['assets-table'] ?? DEFAULT_ASSETS_TABLE);
    $versionsTable = (string) ($options['versions-table'] ?? DEFAULT_VERSIONS_TABLE);
    $output = (string) ($options['output'] ?? defaultPolicyPath($siteKey));
    $refreshWordfence = array_key_exists('refresh-wordfence', $options);

    validateTableName($vulnTable);
    validateTableName($assetsTable);
    validateTableName($versionsTable);

    $wordfenceRefresh = null;

    try {
        if ($refreshWordfence) {
            $wordfenceRefresh = refreshWordfence($options, $sitePath, $vulnTable);
        }

        $db = createDatabase();
        createPolicyTables($db, $assetsTable, $versionsTable);

        $inventory = collectWordPressInventory($wpBinary, $sitePath);
        recordObservedAssets($db, $assetsTable, $versionsTable, $siteKey, $inventory);

        $policy = buildPolicy(
            $db,
            $assetsTable,
            $versionsTable,
            $vulnTable,
            $siteKey,
            $sitePath,
            $inventory,
            $normalDays,
            $emergencyDays
        );

        writeJsonFile($output, $policy);
    } catch (RuntimeException $exception) {
        fwrite(STDERR, $exception->getMessage() . "\n");
        exit(1);
    }

    echo json_encode([
        'site_key' => $siteKey,
        'site_path' => $sitePath,
        'output' => $output,
        'core_current_version' => $policy['core']['current_version'],
        'plugin_count' => count($policy['plugins']),
        'generated_at' => $policy['generated_at'],
        'wordfence_refresh' => $wordfenceRefresh,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
}

function printUsage(): void
{
    echo <<<TEXT
Usage:
  php wp_update_policy.php --site=/path/to/wordpress

Options:
  --site=PATH            Required. WordPress install path.
  --site-key=VALUE       Optional stable site id. Default: basename of --site.
  --wp=PATH              Optional WP-CLI binary. Default: wp.
  --normal-days=N        Optional normal update delay. Default: 7.
  --emergency-days=N     Optional emergency update delay. Default: 2.
  --output=PATH          Optional policy JSON output path.
  --refresh-wordfence    Optional. Refresh Wordfence vulnerability DB before building policy.
  --wf-feed=VALUE        Optional with --refresh-wordfence. production or scanner. Default: production.
  --wf-timeout=SECONDS   Optional with --refresh-wordfence. Default: 600.
  --wf-use-cache         Optional with --refresh-wordfence. Import existing cache without download.
  --wf-cache-file=PATH   Optional with --refresh-wordfence. Feed cache path.
  --vuln-table=VALUE     Optional Wordfence table. Default: wordfence_plugin_vulnerabilities.
  --assets-table=VALUE   Optional current asset table. Default: wp_update_assets.
  --versions-table=VALUE Optional first-seen versions table. Default: wp_update_versions.

TEXT;
}

function refreshWordfence(array $options, string $sitePath, string $vulnTable): array
{
    $script = __DIR__ . '/wordfence_plugin_vulns.php';
    if (!is_file($script)) {
        throw new RuntimeException('wordfence_plugin_vulns.php was not found.');
    }

    $args = [
        PHP_BINARY,
        $script,
        '--all',
        '--software=all',
        '--site=' . $sitePath,
        '--table=' . $vulnTable,
        '--feed=' . (string) ($options['wf-feed'] ?? 'production'),
        '--timeout=' . (string) ($options['wf-timeout'] ?? '600'),
    ];

    if (isset($options['wf-cache-file'])) {
        $args[] = '--cache-file=' . (string) $options['wf-cache-file'];
    }

    if (array_key_exists('wf-use-cache', $options)) {
        $args[] = '--use-cache';
    }

    $output = runCommand($args, $stderr, $status, true);
    $decoded = json_decode(trim($output), true);
    if (!is_array($decoded) || empty($decoded['saved_to_mysql'])) {
        throw new RuntimeException("Wordfence refresh did not complete as expected.\n" . trim($output));
    }

    return [
        'feed' => $decoded['feed'] ?? null,
        'software' => $decoded['software'] ?? null,
        'count' => $decoded['count'] ?? null,
        'matched_software_rows' => $decoded['matched_software_rows'] ?? null,
        'saved_rows' => $decoded['saved_rows'] ?? null,
        'cache_file' => $decoded['cache_file'] ?? null,
    ];
}

function collectWordPressInventory(string $wpBinary, string $sitePath): array
{
    $plugins = runWpJson($wpBinary, $sitePath, [
        'plugin',
        'list',
        '--fields=name,title,status,version,update,update_version',
        '--format=json',
    ]);

    $coreVersion = trim(runWp($wpBinary, $sitePath, ['core', 'version']));
    if ($coreVersion === '') {
        throw new RuntimeException('Unable to read WordPress core version.');
    }

    $coreUpdates = runWpJson($wpBinary, $sitePath, ['core', 'check-update', '--format=json'], true);

    return [
        'core' => [
            'slug' => 'wordpress',
            'name' => 'WordPress Core',
            'version' => $coreVersion,
            'updates' => normalizeCoreUpdates($coreUpdates),
        ],
        'plugins' => normalizePlugins($plugins),
    ];
}

function runWpJson(string $wpBinary, string $sitePath, array $args, bool $allowNoUpdates = false): array
{
    $output = runWp($wpBinary, $sitePath, $args, $allowNoUpdates);
    $output = trim($output);
    if ($output === '') {
        return [];
    }

    $decoded = json_decode($output, true);
    if (!is_array($decoded)) {
        if ($allowNoUpdates && isWpNoUpdatesOutput($output)) {
            return [];
        }

        throw new RuntimeException('WP-CLI returned invalid JSON for: ' . implode(' ', $args));
    }

    return $decoded;
}

function runWp(string $wpBinary, string $sitePath, array $args, bool $allowNoUpdates = false): string
{
    $command = array_merge([$wpBinary, '--path=' . $sitePath], $args);
    $stdout = runCommand($command, $stderr, $status, false);

    if ($status !== 0) {
        $combinedOutput = trim($stdout . "\n" . $stderr);
        if ($allowNoUpdates && isWpNoUpdatesOutput($combinedOutput)) {
            return $stdout;
        }

        throw new RuntimeException("WP-CLI failed: " . implode(' ', $args) . "\n" . trim($stderr));
    }

    return $stdout;
}

function isWpNoUpdatesOutput(string $output): bool
{
    return preg_match('/\b(already|latest|up to date|no updates?)\b/i', $output) === 1;
}

function runCommand(array $command, ?string &$stderr = null, ?int &$status = null, bool $throwOnFailure = true): string
{
    $escaped = array_map('escapeshellarg', $command);
    $descriptor = [
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    $process = proc_open(implode(' ', $escaped), $descriptor, $pipes);
    if (!is_resource($process)) {
        throw new RuntimeException('Unable to run command.');
    }

    $stdout = stream_get_contents($pipes[1]);
    $stderr = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $status = proc_close($process);

    if ($status !== 0 && $throwOnFailure) {
        throw new RuntimeException("Command failed: " . implode(' ', $command) . "\n" . trim($stderr));
    }

    return (string) $stdout;
}

function normalizePlugins(array $plugins): array
{
    $normalized = [];

    foreach ($plugins as $plugin) {
        if (!is_array($plugin) || empty($plugin['name'])) {
            continue;
        }

        $updateVersion = trim((string) ($plugin['update_version'] ?? ''));
        $normalized[] = [
            'slug' => (string) $plugin['name'],
            'name' => (string) ($plugin['title'] ?? $plugin['name']),
            'status' => (string) ($plugin['status'] ?? ''),
            'version' => (string) ($plugin['version'] ?? ''),
            'update_available' => (($plugin['update'] ?? '') === 'available') && $updateVersion !== '',
            'latest_version' => $updateVersion,
        ];
    }

    return $normalized;
}

function normalizeCoreUpdates(array $updates): array
{
    $normalized = [];

    foreach ($updates as $update) {
        if (!is_array($update) || empty($update['version'])) {
            continue;
        }

        $normalized[] = [
            'version' => (string) $update['version'],
            'update_type' => (string) ($update['update_type'] ?? ''),
            'package_url' => (string) ($update['package_url'] ?? ''),
        ];
    }

    usort($normalized, static function (array $a, array $b): int {
        return compareVersions($a['version'], $b['version']);
    });

    return $normalized;
}

function recordObservedAssets(DB $db, string $assetsTable, string $versionsTable, string $siteKey, array $inventory): void
{
    $core = $inventory['core'];
    upsertAsset($db, $assetsTable, $siteKey, 'core', 'wordpress', $core['name'], 'active', $core['version']);
    upsertObservedVersion($db, $versionsTable, $siteKey, 'core', 'wordpress', $core['version'], 'installed');

    foreach ($core['updates'] as $update) {
        upsertObservedVersion($db, $versionsTable, $siteKey, 'core', 'wordpress', $update['version'], 'available');
    }

    foreach ($inventory['plugins'] as $plugin) {
        upsertAsset($db, $assetsTable, $siteKey, 'plugin', $plugin['slug'], $plugin['name'], $plugin['status'], $plugin['version']);
        upsertObservedVersion($db, $versionsTable, $siteKey, 'plugin', $plugin['slug'], $plugin['version'], 'installed');

        if ($plugin['update_available']) {
            upsertObservedVersion($db, $versionsTable, $siteKey, 'plugin', $plugin['slug'], $plugin['latest_version'], 'available');
        }
    }
}

function buildPolicy(
    DB $db,
    string $assetsTable,
    string $versionsTable,
    string $vulnTable,
    string $siteKey,
    string $sitePath,
    array $inventory,
    int $normalDays,
    int $emergencyDays
): array {
    $now = gmdate('Y-m-d H:i:s');
    $policy = [
        'generated_at' => $now . 'Z',
        'site_key' => $siteKey,
        'site_path' => $sitePath,
        'rules' => [
            'normal_delay_days' => $normalDays,
            'emergency_delay_days' => $emergencyDays,
        ],
        'core' => buildAssetPolicy($db, $versionsTable, $vulnTable, $siteKey, 'core', 'wordpress', 'WordPress Core', $inventory['core']['version'], $normalDays, $emergencyDays),
        'plugins' => [],
    ];

    foreach ($inventory['plugins'] as $plugin) {
        $policy['plugins'][] = buildAssetPolicy(
            $db,
            $versionsTable,
            $vulnTable,
            $siteKey,
            'plugin',
            $plugin['slug'],
            $plugin['name'],
            $plugin['version'],
            $normalDays,
            $emergencyDays,
            $plugin['status']
        );
    }

    return $policy;
}

function buildAssetPolicy(
    DB $db,
    string $versionsTable,
    string $vulnTable,
    string $siteKey,
    string $assetType,
    string $slug,
    string $name,
    string $currentVersion,
    int $normalDays,
    int $emergencyDays,
    string $status = 'active'
): array {
    $observedVersions = getObservedVersions($db, $versionsTable, $siteKey, $assetType, $slug);
    $currentVulns = in_array($assetType, ['plugin', 'core'], true)
        ? findVulnerabilitiesForVersion($db, $vulnTable, $assetType, $slug, $currentVersion)
        : [];
    $normalCandidates = agedVersions($observedVersions, $currentVersion, $normalDays);
    $emergencyCandidates = agedVersions($observedVersions, $currentVersion, $emergencyDays);

    $normalVersion = newestSafeVersion($db, $vulnTable, $assetType, $slug, $normalCandidates);
    $emergencyVersion = newestSafeVersion($db, $vulnTable, $assetType, $slug, $emergencyCandidates);

    return [
        'type' => $assetType,
        'slug' => $slug,
        'name' => $name,
        'status' => $status,
        'current_version' => $currentVersion,
        'current_is_vulnerable' => count($currentVulns) > 0,
        'current_vulnerabilities' => $currentVulns,
        'allowed_update_version' => $normalVersion,
        'emergency_update_version' => $emergencyVersion,
        'observed_versions' => $observedVersions,
        'recommended_action' => recommendedAction($currentVulns, $normalVersion, $emergencyVersion),
    ];
}

function recommendedAction(array $currentVulns, ?string $normalVersion, ?string $emergencyVersion): string
{
    if ($currentVulns !== []) {
        return $emergencyVersion !== null ? 'emergency_update' : 'manual_review';
    }

    return $normalVersion !== null ? 'normal_update' : 'hold';
}

function getObservedVersions(DB $db, string $versionsTable, string $siteKey, string $assetType, string $slug): array
{
    $result = $db->query("
        SELECT `version`, `source`, `first_seen_at`, `last_seen_at`
        FROM `{$versionsTable}`
        WHERE `site_key` = " . sqlString($db, $siteKey) . "
          AND `asset_type` = " . sqlString($db, $assetType) . "
          AND `slug` = " . sqlString($db, $slug) . "
        ORDER BY `first_seen_at` ASC
    ");

    $versions = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $versions[] = [
            'version' => (string) $row['version'],
            'source' => (string) $row['source'],
            'first_seen_at' => (string) $row['first_seen_at'],
            'last_seen_at' => (string) $row['last_seen_at'],
        ];
    }

    usort($versions, static function (array $a, array $b): int {
        return compareVersions($a['version'], $b['version']);
    });

    return $versions;
}

function agedVersions(array $observedVersions, string $currentVersion, int $days): array
{
    $cutoff = time() - ($days * 86400);
    $versions = [];

    foreach ($observedVersions as $observed) {
        $version = $observed['version'];
        $firstSeen = strtotime($observed['first_seen_at']);

        if ($firstSeen === false || $firstSeen > $cutoff) {
            continue;
        }

        if (compareVersions($version, $currentVersion) <= 0) {
            continue;
        }

        $versions[] = $version;
    }

    usort($versions, 'compareVersions');
    return array_values(array_unique($versions));
}

function newestSafeVersion(DB $db, string $vulnTable, string $assetType, string $slug, array $versions): ?string
{
    for ($i = count($versions) - 1; $i >= 0; $i--) {
        $version = $versions[$i];
        if (!in_array($assetType, ['plugin', 'core'], true) || findVulnerabilitiesForVersion($db, $vulnTable, $assetType, $slug, $version) === []) {
            return $version;
        }
    }

    return null;
}

function findVulnerabilitiesForVersion(DB $db, string $vulnTable, string $assetType, string $slug, string $version): array
{
    $result = $db->query("
        SELECT `vulnerability_id`, `title`, `cve`, `cvss_score`, `cvss_rating`, `affected_versions_json`, `patched_versions_json`, `remediation`
        FROM `{$vulnTable}`
        WHERE `software_type` = " . sqlString($db, $assetType) . "
          AND `software_slug` = " . sqlString($db, $slug) . "
    ");

    $vulnerabilities = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $ranges = json_decode((string) $row['affected_versions_json'], true);
        if (!is_array($ranges) || !versionMatchesAffectedRanges($version, $ranges)) {
            continue;
        }

        $vulnerabilities[] = [
            'id' => (string) $row['vulnerability_id'],
            'title' => (string) $row['title'],
            'cve' => $row['cve'] !== null ? (string) $row['cve'] : null,
            'cvss_score' => $row['cvss_score'] !== null ? (float) $row['cvss_score'] : null,
            'cvss_rating' => $row['cvss_rating'] !== null ? (string) $row['cvss_rating'] : null,
            'patched_versions' => json_decode((string) $row['patched_versions_json'], true) ?: [],
            'remediation' => $row['remediation'] !== null ? (string) $row['remediation'] : null,
        ];
    }

    return $vulnerabilities;
}

function versionMatchesAffectedRanges(string $version, array $ranges): bool
{
    foreach ($ranges as $range) {
        if (!is_array($range)) {
            continue;
        }

        $from = (string) ($range['from_version'] ?? '*');
        $to = (string) ($range['to_version'] ?? '*');
        $fromInclusive = (bool) ($range['from_inclusive'] ?? true);
        $toInclusive = (bool) ($range['to_inclusive'] ?? true);

        $afterFrom = $from === '*'
            || compareVersions($version, $from) > 0
            || ($fromInclusive && compareVersions($version, $from) === 0);
        $beforeTo = $to === '*'
            || compareVersions($version, $to) < 0
            || ($toInclusive && compareVersions($version, $to) === 0);

        if ($afterFrom && $beforeTo) {
            return true;
        }
    }

    return false;
}

function createPolicyTables(DB $db, string $assetsTable, string $versionsTable): void
{
    $db->execute("
        CREATE TABLE IF NOT EXISTS `{$assetsTable}` (
            `site_key` varchar(191) NOT NULL,
            `asset_type` varchar(20) NOT NULL,
            `slug` varchar(191) NOT NULL,
            `name` varchar(255) DEFAULT NULL,
            `status` varchar(40) DEFAULT NULL,
            `current_version` varchar(80) DEFAULT NULL,
            `last_checked_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (`site_key`, `asset_type`, `slug`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    $db->execute("
        CREATE TABLE IF NOT EXISTS `{$versionsTable}` (
            `site_key` varchar(191) NOT NULL,
            `asset_type` varchar(20) NOT NULL,
            `slug` varchar(191) NOT NULL,
            `version` varchar(80) NOT NULL,
            `source` varchar(20) NOT NULL,
            `first_seen_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `last_seen_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (`site_key`, `asset_type`, `slug`, `version`),
            KEY `idx_asset_seen` (`asset_type`, `slug`, `first_seen_at`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");
}

function upsertAsset(DB $db, string $table, string $siteKey, string $assetType, string $slug, string $name, string $status, string $version): void
{
    $db->execute("
        INSERT INTO `{$table}` (`site_key`, `asset_type`, `slug`, `name`, `status`, `current_version`)
        VALUES (
            " . sqlString($db, $siteKey) . ",
            " . sqlString($db, $assetType) . ",
            " . sqlString($db, $slug) . ",
            " . sqlString($db, $name) . ",
            " . sqlString($db, $status) . ",
            " . sqlString($db, $version) . "
        )
        ON DUPLICATE KEY UPDATE
            `name` = VALUES(`name`),
            `status` = VALUES(`status`),
            `current_version` = VALUES(`current_version`),
            `last_checked_at` = CURRENT_TIMESTAMP
    ");
}

function upsertObservedVersion(DB $db, string $table, string $siteKey, string $assetType, string $slug, string $version, string $source): void
{
    if ($version === '') {
        return;
    }

    $db->execute("
        INSERT INTO `{$table}` (`site_key`, `asset_type`, `slug`, `version`, `source`)
        VALUES (
            " . sqlString($db, $siteKey) . ",
            " . sqlString($db, $assetType) . ",
            " . sqlString($db, $slug) . ",
            " . sqlString($db, $version) . ",
            " . sqlString($db, $source) . "
        )
        ON DUPLICATE KEY UPDATE
            `source` = IF(`source` = 'installed', `source`, VALUES(`source`)),
            `last_seen_at` = CURRENT_TIMESTAMP
    ");
}

function defaultPolicyPath(string $siteKey): string
{
    return __DIR__ . '/' . DEFAULT_POLICY_DIR . '/' . preg_replace('/[^A-Za-z0-9_.-]+/', '-', $siteKey) . '.json';
}

function writeJsonFile(string $path, array $data): void
{
    ensureDirectory(dirname($path));
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        throw new RuntimeException('Unable to encode policy JSON.');
    }

    if (file_put_contents($path, $json . PHP_EOL) === false) {
        throw new RuntimeException("Unable to write policy file: {$path}");
    }
}

function compareVersions(string $a, string $b): int
{
    return version_compare(normalizeVersion($a), normalizeVersion($b));
}

function normalizeVersion(string $version): string
{
    return preg_replace('/[^0-9A-Za-z.+_-]/', '', trim($version)) ?: '0';
}

function parseOptions(array $argv): array
{
    $options = [];

    foreach (array_slice($argv, 1) as $arg) {
        if (substr($arg, 0, 2) !== '--') {
            continue;
        }

        $arg = substr($arg, 2);
        if (strpos($arg, '=') !== false) {
            [$key, $value] = explode('=', $arg, 2);
            $options[$key] = $value;
            continue;
        }

        $options[$arg] = true;
    }

    return $options;
}

function loadConfigForOptions(array $options): void
{
    foreach (configPathsForOptions($options) as $configPath) {
        loadConfigFile($configPath);
    }
}

function configPathsForOptions(array $options): array
{
    $paths = [];
    $sitePath = isset($options['site']) ? rtrim((string) $options['site'], DIRECTORY_SEPARATOR) : '';
    if ($sitePath !== '') {
        foreach (possibleWpConfigPaths($sitePath) as $path) {
            $paths[] = $path;
        }
    }

    $paths[] = __DIR__ . '/wp-config.php';

    return array_values(array_unique($paths));
}

function possibleWpConfigPaths(string $sitePath): array
{
    return [
        $sitePath . '/wp-config.php',
        $sitePath . '/public/wp-config.php',
        $sitePath . '/public_html/wp-config.php',
        $sitePath . '/htdocs/wp-config.php',
        dirname($sitePath) . '/wp-config.php',
    ];
}

function loadConfigFile(string $configPath): void
{
    if (!is_file($configPath)) {
        return;
    }

    $config = file_get_contents($configPath);
    if ($config === false) {
        return;
    }

    preg_match_all(
        '/define\s*\(\s*[\'"]([A-Z0-9_]+)[\'"]\s*,\s*([\'"])(.*?)\2\s*\)\s*;/s',
        $config,
        $matches,
        PREG_SET_ORDER
    );

    foreach ($matches as $match) {
        if (!defined($match[1])) {
            define($match[1], stripcslashes($match[3]));
        }
    }
}

function getConfiguredValue(string $constant): string
{
    if (defined($constant)) {
        return (string) constant($constant);
    }

    $envValue = getenv($constant);
    return $envValue === false ? '' : (string) $envValue;
}

function getRequiredConfiguredValue(string $constant): string
{
    $value = getConfiguredValue($constant);
    if ($value === '') {
        throw new RuntimeException("Missing {$constant} in wp-config.php.");
    }

    return $value;
}

function requireDbClass(): void
{
    $dbPath = __DIR__ . '/DB.php';
    if (!is_file($dbPath)) {
        throw new RuntimeException('DB.php was not found in the script directory.');
    }

    require_once $dbPath;

    if (!class_exists('DB')) {
        throw new RuntimeException('DB.php did not load a DB class.');
    }
}

function createDatabase(): DB
{
    return new DB(
        getRequiredConfiguredValue('DB_NAME'),
        getRequiredConfiguredValue('DB_HOST'),
        getRequiredConfiguredValue('DB_USER'),
        getRequiredConfiguredValue('DB_PASSWORD')
    );
}

function validateTableName(string $table): void
{
    if (!preg_match('/^[A-Za-z0-9_]+$/', $table)) {
        throw new RuntimeException('Invalid table name. Use letters, numbers, and underscores only.');
    }
}

function parsePositiveInt(string $value, int $default): int
{
    if (!ctype_digit($value) || (int) $value < 1) {
        return $default;
    }

    return (int) $value;
}

function ensureDirectory(string $directory): void
{
    if (is_dir($directory)) {
        return;
    }

    if (!mkdir($directory, 0775, true) && !is_dir($directory)) {
        throw new RuntimeException("Unable to create directory: {$directory}");
    }
}

function sqlString(DB $db, string $value): string
{
    return "'" . $db->escapeString($value) . "'";
}
