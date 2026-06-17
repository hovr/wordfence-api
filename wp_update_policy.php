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
 *   php wp_update_policy.php --site=/path/to/wordpress --wp=/usr/local/bin/wp --normal-hours=168 --emergency-hours=48
 */

const DEFAULT_VULN_TABLE = 'wordfence_plugin_vulnerabilities';
const DEFAULT_ASSETS_TABLE = 'wp_update_assets';
const DEFAULT_VERSIONS_TABLE = 'wp_update_versions';
const DEFAULT_POLICY_DIR = 'policies';
const DEFAULT_DASHBOARD_PLUGIN = 'wp-update-dashboard';
const DEFAULT_DASHBOARD_JSON = 'update-status.json';

require_once __DIR__ . '/cli_helpers.php';
require_once __DIR__ . '/email_helpers.php';

if (realpath((string) ($_SERVER['SCRIPT_FILENAME'] ?? '')) === __FILE__) {
    main($argv);
}

function main(array $argv): void
{
    try {
        $options = loadPolicySettings(parseOptions($argv));
    } catch (RuntimeException $exception) {
        fwrite(STDERR, $exception->getMessage() . "\n\n");
        printUsage();
        exit(1);
    }

    $sitePath = rtrim((string) ($options['site'] ?? ''), DIRECTORY_SEPARATOR);
    if ($sitePath === '' || !is_dir($sitePath)) {
        fwrite(STDERR, "Missing or invalid --site path.\n\n");
        printUsage();
        exit(1);
    }

    loadConfigForOptions($options);
    requireDbClass();

    $wpBinary = (string) ($options['wp'] ?? 'wp');
    $wpUser = optionalWpUser($options);
    $siteKey = (string) ($options['site-key'] ?? basename($sitePath));
    $normalHours = delayHours($options, 'normal', 168);
    $emergencyHours = delayHours($options, 'emergency', 48);
    $vulnTable = (string) ($options['vuln-table'] ?? DEFAULT_VULN_TABLE);
    $assetsTable = (string) ($options['assets-table'] ?? DEFAULT_ASSETS_TABLE);
    $versionsTable = (string) ($options['versions-table'] ?? DEFAULT_VERSIONS_TABLE);
    $output = (string) ($options['output'] ?? defaultPolicyPath($siteKey));
    $dashboardOutput = (string) ($options['dashboard-json'] ?? defaultDashboardJsonPath($sitePath, (string) ($options['dashboard-plugin'] ?? DEFAULT_DASHBOARD_PLUGIN)));
    $refreshWordfence = array_key_exists('refresh-wordfence', $options);
    $ignoredVulnerabilities = parseIgnoredVulnerabilities($options['ignore-vuln'] ?? '');

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
        ensureWordfenceVulnerabilityTableCompatible($db, $vulnTable);

        $inventory = collectWordPressInventory($wpBinary, $sitePath, $wpUser);
        recordObservedAssets($db, $assetsTable, $versionsTable, $siteKey, $inventory);

        $policy = buildPolicy(
            $db,
            $assetsTable,
            $versionsTable,
            $vulnTable,
            $siteKey,
            $sitePath,
            $inventory,
            $normalHours,
            $emergencyHours,
            $ignoredVulnerabilities
        );

        writeJsonFile($output, $policy);
        $dashboardJson = writeDashboardJson($dashboardOutput, $policy, $wordfenceRefresh);
        $notification = notifyPolicy($policy, $output, $wordfenceRefresh, $options, $dashboardJson);
    } catch (RuntimeException $exception) {
        fwrite(STDERR, $exception->getMessage() . "\n");
        exit(1);
    }

    echo json_encode([
        'site_key' => $siteKey,
        'site_path' => $sitePath,
        'output' => $output,
        'dashboard_json' => $dashboardJson,
        'core_current_version' => $policy['core']['current_version'],
        'plugin_count' => count($policy['plugins']),
        'generated_at' => $policy['generated_at'],
        'wordfence_refresh' => $wordfenceRefresh,
        'notification' => $notification,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
}

function printUsage(): void
{
    echo <<<TEXT
Usage:
  php wp_update_policy.php --site=/path/to/wordpress

Options:
  --site=PATH            Required. WordPress install path.
  --config=PATH          Optional private config file to parse before wp-config.php.
  --site-key=VALUE       Optional stable site id. Default: basename of --site.
  --wp=PATH              Optional WP-CLI binary. Default: wp.
  --wp-user=USER         Optional. Run WP-CLI via sudo -u USER.
  --normal-hours=N       Optional normal update delay. Default: 168.
  --emergency-hours=N    Optional emergency update delay. Default: 48.
  --normal-days=N        Backward-compatible alias. Converted to hours.
  --emergency-days=N     Backward-compatible alias. Converted to hours.
  --output=PATH          Optional policy JSON output path.
  --dashboard-json=PATH  Optional dashboard JSON path. Default: SITE/wp-content/plugins/wp-update-dashboard/update-status.json.
  --dashboard-plugin=DIR Optional dashboard plugin folder name. Default: wp-update-dashboard.
  --policy-settings=PATH Optional JSON settings file for policy generation options.
  --notify-email=ADDR    Optional. Email policy summary after generation.
  --no-notify            Optional. Disable policy email notification.
  --refresh-wordfence    Optional. Refresh Wordfence vulnerability DB before building policy.
  --wf-feed=VALUE        Optional with --refresh-wordfence. production or scanner. Default: production.
  --wf-timeout=SECONDS   Optional with --refresh-wordfence. Default: 600.
  --wf-use-cache         Optional with --refresh-wordfence. Import existing cache without download.
  --wf-cache-file=PATH   Optional with --refresh-wordfence. Feed cache path.
  --vuln-table=VALUE     Optional Wordfence table. Default: wordfence_plugin_vulnerabilities.
  --assets-table=VALUE   Optional current asset table. Default: wp_update_assets.
  --versions-table=VALUE Optional first-seen versions table. Default: wp_update_versions.
  --ignore-vuln=LIST     Optional comma-separated TYPE:SLUG:ID_OR_TITLE entries to suppress.

TEXT;
}

function loadPolicySettings(array $cliOptions): array
{
    return loadOptionsWithSettings($cliOptions);
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

    if (isset($options['config'])) {
        $args[] = '--config=' . (string) $options['config'];
    }

    if (isset($options['wf-cache-file'])) {
        $args[] = '--cache-file=' . (string) $options['wf-cache-file'];
    }

    if (array_key_exists('wf-use-cache', $options)) {
        $args[] = '--use-cache';
    }

    $output = runCommand($args, $stderr, $status, true, 'wp-policy-stderr-');
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
        'skipped_import' => $decoded['skipped_import'] ?? null,
        'cache_sha256' => $decoded['cache_sha256'] ?? null,
        'cache_file' => $decoded['cache_file'] ?? null,
    ];
}

function collectWordPressInventory(string $wpBinary, string $sitePath, ?string $wpUser): array
{
    $plugins = runWpJson($wpBinary, $sitePath, [
        'plugin',
        'list',
        '--fields=name,title,status,version,update,update_version',
        '--format=json',
    ], false, $wpUser);

    $coreVersion = trim(runWp($wpBinary, $sitePath, ['core', 'version'], false, $wpUser));
    if ($coreVersion === '') {
        throw new RuntimeException('Unable to read WordPress core version.');
    }

    $coreUpdates = runWpJson($wpBinary, $sitePath, ['core', 'check-update', '--format=json'], true, $wpUser);

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

function runWpJson(string $wpBinary, string $sitePath, array $args, bool $allowNoUpdates = false, ?string $wpUser = null): array
{
    $output = runWp($wpBinary, $sitePath, $args, $allowNoUpdates, $wpUser);
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

function runWp(string $wpBinary, string $sitePath, array $args, bool $allowNoUpdates = false, ?string $wpUser = null): string
{
    $command = wpCliCommand($wpBinary, $sitePath, $args, $wpUser);
    $stdout = runCommand($command, $stderr, $status, false, 'wp-policy-stderr-');

    if ($status !== 0) {
        $combinedOutput = trim($stdout . "\n" . $stderr);
        if ($allowNoUpdates && isWpNoUpdatesOutput($combinedOutput)) {
            return $stdout;
        }

        throw new RuntimeException("WP-CLI failed: " . implode(' ', $args) . "\n" . trim($stderr));
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

function delayHours(array $options, string $prefix, int $defaultHours): int
{
    $hoursKey = $prefix . '-hours';
    if (isset($options[$hoursKey])) {
        return parsePositiveInt((string) $options[$hoursKey], $defaultHours);
    }

    $daysKey = $prefix . '-days';
    if (isset($options[$daysKey])) {
        return parsePositiveInt((string) $options[$daysKey], (int) ceil($defaultHours / 24)) * 24;
    }

    return $defaultHours;
}

function isWpNoUpdatesOutput(string $output): bool
{
    return preg_match('/\b(already|latest|up to date|no updates?)\b/i', $output) === 1;
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
    int $normalHours,
    int $emergencyHours,
    array $ignoredVulnerabilities = []
): array {
    $now = gmdate('Y-m-d H:i:s');
    $policy = [
        'generated_at' => $now . 'Z',
        'site_key' => $siteKey,
        'site_path' => $sitePath,
        'rules' => [
            'normal_delay_hours' => $normalHours,
            'emergency_delay_hours' => $emergencyHours,
            'normal_delay_days' => $normalHours / 24,
            'emergency_delay_days' => $emergencyHours / 24,
        ],
        'core' => buildAssetPolicy($db, $versionsTable, $vulnTable, $siteKey, 'core', 'wordpress', 'WordPress Core', $inventory['core']['version'], $normalHours, $emergencyHours, 'active', $ignoredVulnerabilities),
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
            $normalHours,
            $emergencyHours,
            $plugin['status'],
            $ignoredVulnerabilities
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
    int $normalHours,
    int $emergencyHours,
    string $status = 'active',
    array $ignoredVulnerabilities = []
): array {
    $observedVersions = getObservedVersions($db, $versionsTable, $siteKey, $assetType, $slug);
    $allVulnerabilityRows = in_array($assetType, ['plugin', 'core'], true)
        ? loadVulnerabilitiesForAsset($db, $vulnTable, $assetType, $slug)
        : [];
    $vulnerabilityRows = actionableVulnerabilityRows($allVulnerabilityRows, $assetType, $slug, $ignoredVulnerabilities);
    $ignoredRows = ignoredVulnerabilityRows($allVulnerabilityRows, $assetType, $slug, $ignoredVulnerabilities);
    $currentVulns = findVulnerabilitiesForVersion($vulnerabilityRows, $currentVersion);
    $ignoredCurrentVulns = findVulnerabilitiesForVersion($ignoredRows, $currentVersion);
    $normalCandidates = agedVersions($observedVersions, $currentVersion, $normalHours);
    $emergencyCandidates = agedVersions($observedVersions, $currentVersion, $emergencyHours);

    $normalVersion = newestSafeVersion($vulnerabilityRows, $normalCandidates);
    $emergencyVersion = newestSafeVersion($vulnerabilityRows, $emergencyCandidates);

    return [
        'type' => $assetType,
        'slug' => $slug,
        'name' => $name,
        'status' => $status,
        'current_version' => $currentVersion,
        'current_is_vulnerable' => count($currentVulns) > 0,
        'current_vulnerabilities' => $currentVulns,
        'ignored_current_vulnerabilities' => $ignoredCurrentVulns,
        'allowed_update_version' => $normalVersion,
        'emergency_update_version' => $emergencyVersion,
        'observed_versions' => $observedVersions,
        'safe_observed_versions' => safeObservedVersions($vulnerabilityRows, $observedVersions, $currentVersion),
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

function parseIgnoredVulnerabilities($value): array
{
    if ($value === '' || $value === null || $value === false) {
        return [];
    }

    if (is_array($value) && (array_key_exists('type', $value) || array_key_exists('slug', $value))) {
        $entries = [$value];
    } else {
        $entries = is_array($value)
            ? $value
            : array_filter(array_map('trim', explode(',', (string) $value)));
    }

    $rules = [];
    foreach ($entries as $entry) {
        if (is_array($entry)) {
            $type = trim((string) ($entry['type'] ?? ''));
            $slug = trim((string) ($entry['slug'] ?? ''));
            $identifier = trim((string) ($entry['identifier'] ?? $entry['id'] ?? $entry['title'] ?? ''));
        } else {
            $parts = explode(':', trim((string) $entry), 3);
            if (count($parts) !== 3) {
                throw new RuntimeException('Invalid --ignore-vuln entry. Use TYPE:SLUG:ID_OR_TITLE.');
            }

            [$type, $slug, $identifier] = array_map('trim', $parts);
        }

        if ($type === '' || $slug === '' || $identifier === '') {
            throw new RuntimeException('Invalid --ignore-vuln entry. TYPE, SLUG, and ID_OR_TITLE are required.');
        }

        $rules[] = [
            'type' => normalizeVulnerabilityIdentifier($type),
            'slug' => normalizeVulnerabilityIdentifier($slug),
            'identifier' => normalizeVulnerabilityIdentifier($identifier),
        ];
    }

    return $rules;
}

function actionableVulnerabilityRows(array $rows, string $assetType, string $slug, array $ignoredVulnerabilities): array
{
    return array_values(array_filter($rows, static function (array $row) use ($assetType, $slug, $ignoredVulnerabilities): bool {
        return !vulnerabilityIsIgnored($row, $assetType, $slug, $ignoredVulnerabilities);
    }));
}

function ignoredVulnerabilityRows(array $rows, string $assetType, string $slug, array $ignoredVulnerabilities): array
{
    return array_values(array_filter($rows, static function (array $row) use ($assetType, $slug, $ignoredVulnerabilities): bool {
        return vulnerabilityIsIgnored($row, $assetType, $slug, $ignoredVulnerabilities);
    }));
}

function vulnerabilityIsIgnored(array $row, string $assetType, string $slug, array $ignoredVulnerabilities): bool
{
    $type = normalizeVulnerabilityIdentifier($assetType);
    $assetSlug = normalizeVulnerabilityIdentifier($slug);
    $id = normalizeVulnerabilityIdentifier((string) ($row['id'] ?? ''));
    $title = normalizeVulnerabilityIdentifier((string) ($row['title'] ?? ''));

    foreach ($ignoredVulnerabilities as $rule) {
        if (($rule['type'] ?? '') !== $type || ($rule['slug'] ?? '') !== $assetSlug) {
            continue;
        }

        $identifier = (string) ($rule['identifier'] ?? '');
        if ($identifier !== '' && ($identifier === $id || $identifier === $title)) {
            return true;
        }
    }

    return false;
}

function normalizeVulnerabilityIdentifier(string $value): string
{
    return strtolower(trim(preg_replace('/\s+/', ' ', $value) ?? $value));
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

function agedVersions(array $observedVersions, string $currentVersion, int $hours): array
{
    $cutoff = time() - ($hours * 3600);
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

function newestSafeVersion(array $vulnerabilityRows, array $versions): ?string
{
    for ($i = count($versions) - 1; $i >= 0; $i--) {
        $version = $versions[$i];
        if (findVulnerabilitiesForVersion($vulnerabilityRows, $version) === []) {
            return $version;
        }
    }

    return null;
}

function safeObservedVersions(array $vulnerabilityRows, array $observedVersions, string $currentVersion): array
{
    $safeVersions = [];

    foreach ($observedVersions as $observed) {
        if (!is_array($observed)) {
            continue;
        }

        $version = (string) ($observed['version'] ?? '');
        if ($version === '' || compareVersions($version, $currentVersion) <= 0) {
            continue;
        }

        if (findVulnerabilitiesForVersion($vulnerabilityRows, $version) !== []) {
            continue;
        }

        $safeVersions[] = $observed;
    }

    usort($safeVersions, static function (array $a, array $b): int {
        return compareVersions((string) ($a['version'] ?? ''), (string) ($b['version'] ?? ''));
    });

    return $safeVersions;
}

function loadVulnerabilitiesForAsset(DB $db, string $vulnTable, string $assetType, string $slug): array
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
        $vulnerabilities[] = [
            'id' => (string) $row['vulnerability_id'],
            'title' => (string) $row['title'],
            'cve' => $row['cve'] !== null ? (string) $row['cve'] : null,
            'cvss_score' => $row['cvss_score'] !== null ? (float) $row['cvss_score'] : null,
            'cvss_rating' => $row['cvss_rating'] !== null ? (string) $row['cvss_rating'] : null,
            'affected_versions' => is_array($ranges) ? $ranges : [],
            'patched_versions' => json_decode((string) $row['patched_versions_json'], true) ?: [],
            'remediation' => $row['remediation'] !== null ? (string) $row['remediation'] : null,
        ];
    }

    return $vulnerabilities;
}

function findVulnerabilitiesForVersion(array $vulnerabilityRows, string $version): array
{
    $vulnerabilities = [];
    foreach ($vulnerabilityRows as $row) {
        $ranges = is_array($row['affected_versions'] ?? null) ? $row['affected_versions'] : [];
        if ($ranges === [] || !versionMatchesAffectedRanges($version, $ranges)) {
            continue;
        }

        $match = $row;
        unset($match['affected_versions']);
        $vulnerabilities[] = $match;
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

function defaultDashboardJsonPath(string $sitePath, string $pluginDirectory): string
{
    $pluginDirectory = preg_replace('/[^A-Za-z0-9_.-]+/', '-', $pluginDirectory) ?: DEFAULT_DASHBOARD_PLUGIN;
    return rtrim($sitePath, DIRECTORY_SEPARATOR)
        . '/wp-content/plugins/'
        . $pluginDirectory
        . '/'
        . DEFAULT_DASHBOARD_JSON;
}

function writeJsonFile(string $path, array $data): void
{
    $directory = dirname($path);
    ensureDirectory($directory);
    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        throw new RuntimeException('Unable to encode policy JSON.');
    }

    $tmpFile = tempnam($directory, '.policy-');
    if ($tmpFile === false) {
        throw new RuntimeException("Unable to create temporary policy file in: {$directory}");
    }

    if (file_put_contents($tmpFile, $json . PHP_EOL) === false) {
        @unlink($tmpFile);
        throw new RuntimeException("Unable to write temporary policy file: {$tmpFile}");
    }

    if (!rename($tmpFile, $path)) {
        @unlink($tmpFile);
        throw new RuntimeException("Unable to move temporary policy file into place: {$path}");
    }

    if (!@chown($path, 'deploy')) {
        throw new RuntimeException("Unable to set JSON file owner to deploy: {$path}");
    }

    if (!@chgrp($path, 'www-data')) {
        throw new RuntimeException("Unable to set JSON file group to www-data: {$path}");
    }

    if (!@chmod($path, 0644)) {
        throw new RuntimeException("Unable to set JSON file permissions to 0644: {$path}");
    }
}

function writeDashboardJson(string $path, array $policy, ?array $wordfenceRefresh): array
{
    $directory = dirname($path);
    if (!is_dir($directory)) {
        return [
            'written' => false,
            'path' => $path,
            'reason' => 'missing_plugin_directory',
            'message' => "Dashboard JSON was not written because the plugin directory does not exist: {$directory}",
        ];
    }

    if (!is_writable($directory)) {
        return [
            'written' => false,
            'path' => $path,
            'reason' => 'plugin_directory_not_writable',
            'message' => "Dashboard JSON was not written because the plugin directory is not writable: {$directory}",
        ];
    }

    try {
        writeJsonFile($path, dashboardStatusForPolicy($policy, $wordfenceRefresh));
    } catch (RuntimeException $exception) {
        return [
            'written' => false,
            'path' => $path,
            'reason' => 'write_failed',
            'message' => 'Dashboard JSON could not be written: ' . $exception->getMessage(),
        ];
    }

    return [
        'written' => true,
        'path' => $path,
        'reason' => null,
        'message' => 'Dashboard JSON written.',
    ];
}

function dashboardStatusForPolicy(array $policy, ?array $wordfenceRefresh): array
{
    $counts = policyActionCounts($policy);
    $groups = policyUpdateEmailGroupsForPolicy($policy);
    $summary = policySubjectSummary($counts, $groups);

    return [
        'schema_version' => 1,
        'generated_at' => (string) ($policy['generated_at'] ?? ''),
        'site_key' => (string) ($policy['site_key'] ?? ''),
        'site_path' => (string) ($policy['site_path'] ?? ''),
        'summary' => $summary,
        'counts' => [
            'normal_update' => (int) ($counts['normal_update'] ?? 0),
            'emergency_update' => (int) ($counts['emergency_update'] ?? 0),
            'manual_review' => (int) ($counts['manual_review'] ?? 0),
            'hold' => (int) ($counts['hold'] ?? 0),
            'emergency_waiting' => count($groups['emergency_waiting'] ?? []),
            'normal_waiting' => count($groups['normal_waiting'] ?? []),
        ],
        'groups' => $groups,
        'rules' => is_array($policy['rules'] ?? null) ? $policy['rules'] : [],
        'wordfence_refresh' => $wordfenceRefresh,
    ];
}

function notifyPolicy(array $policy, string $outputPath, ?array $wordfenceRefresh, array $options, ?array $dashboardJson = null): array
{
    if (array_key_exists('no-notify', $options)) {
        return ['sent' => false, 'reason' => 'disabled'];
    }

    $email = notificationEmail($options);
    if ($email === '') {
        return ['sent' => false, 'reason' => 'missing_email'];
    }

    $counts = policyActionCounts($policy);
    $groups = policyUpdateEmailGroupsForPolicy($policy);
    $summary = policySubjectSummary($counts, $groups);
    if ($summary === 'no updates' && !policyEmailGroupsHaveAssets($groups) && !isNoUpdateNotificationWindow()) {
        return [
            'sent' => false,
            'reason' => 'no_updates_outside_9am',
            'counts' => $counts,
        ];
    }

    $subject = '[WordPress Update Policy] ' . (string) ($policy['site_key'] ?? 'site')
        . ' - ' . $summary;
    $body = policyEmailBody($policy, $outputPath, $wordfenceRefresh, $counts, $groups, $dashboardJson);
    $delivery = sendUpdaterEmail($email, $subject, $body);

    return [
        'sent' => $delivery['sent'],
        'to' => $email,
        'reason' => $delivery['reason'] ?? null,
        'transport' => $delivery['transport'] ?? null,
        'counts' => $counts,
    ];
}

function policyActionCounts(array $policy): array
{
    $counts = [
        'normal_update' => 0,
        'emergency_update' => 0,
        'manual_review' => 0,
        'hold' => 0,
    ];

    foreach (policyAssets($policy) as $asset) {
        $action = (string) ($asset['recommended_action'] ?? 'hold');
        if (!array_key_exists($action, $counts)) {
            $counts[$action] = 0;
        }

        $counts[$action]++;
    }

    return $counts;
}

function policyAssets(array $policy): array
{
    $assets = [];
    if (isset($policy['core']) && is_array($policy['core'])) {
        $assets[] = $policy['core'];
    }

    foreach (($policy['plugins'] ?? []) as $plugin) {
        if (is_array($plugin)) {
            $assets[] = $plugin;
        }
    }

    return $assets;
}

function isNoUpdateNotificationWindow(): bool
{
    // Intentionally use the PHP/server local timezone for the routine 9am no-update summary.
    return (int) date('G') === 9;
}

function policySubjectSummary(array $counts, array $groups = []): string
{
    if (($counts['manual_review'] ?? 0) > 0) {
        return $counts['manual_review'] . ' manual review';
    }

    if (($counts['emergency_update'] ?? 0) > 0) {
        return $counts['emergency_update'] . ' emergency update';
    }

    if (($counts['normal_update'] ?? 0) > 0) {
        return $counts['normal_update'] . ' normal update';
    }

    $pendingUpdates = count($groups['emergency_waiting'] ?? []) + count($groups['normal_waiting'] ?? []);
    if ($pendingUpdates > 0) {
        return $pendingUpdates . ' pending ' . ($pendingUpdates === 1 ? 'update' : 'updates');
    }

    return 'no updates';
}

function policyEmailBody(array $policy, string $outputPath, ?array $wordfenceRefresh, array $counts, ?array $groups = null, ?array $dashboardJson = null): string
{
    $rules = is_array($policy['rules'] ?? null) ? $policy['rules'] : [];
    $lines = [
        'WordPress update policy generated.',
        '',
        'Site: ' . (string) ($policy['site_key'] ?? ''),
        'Path: ' . (string) ($policy['site_path'] ?? ''),
        'Policy file: ' . $outputPath,
        'Generated: ' . (string) ($policy['generated_at'] ?? ''),
        '',
        'Rules:',
        '  Normal delay: ' . (string) ($rules['normal_delay_hours'] ?? '') . ' hours',
        '  Emergency delay: ' . (string) ($rules['emergency_delay_hours'] ?? '') . ' hours',
        '',
        'Recommended actions:',
        '  Normal updates: ' . (string) ($counts['normal_update'] ?? 0),
        '  Emergency updates: ' . (string) ($counts['emergency_update'] ?? 0),
        '  Manual review: ' . (string) ($counts['manual_review'] ?? 0),
        '  Hold: ' . (string) ($counts['hold'] ?? 0),
        '',
    ];

    if ($dashboardJson !== null) {
        $lines[] = 'Dashboard JSON:';
        $lines[] = '  Status: ' . (!empty($dashboardJson['written']) ? 'written' : 'not written');
        $lines[] = '  Path: ' . (string) ($dashboardJson['path'] ?? '');
        if (empty($dashboardJson['written'])) {
            $lines[] = '  Reason: ' . (string) ($dashboardJson['reason'] ?? 'unknown');
            $lines[] = '  Message: ' . (string) ($dashboardJson['message'] ?? 'Dashboard JSON could not be written.');
        }
        $lines[] = '';
    }

    if ($wordfenceRefresh !== null) {
        $lines[] = 'Wordfence refresh:';
        $lines[] = '  Feed: ' . (string) ($wordfenceRefresh['feed'] ?? '');
        $lines[] = '  Software: ' . (string) ($wordfenceRefresh['software'] ?? '');
        $lines[] = '  Saved rows: ' . (string) ($wordfenceRefresh['saved_rows'] ?? '');
        $lines[] = '  Skipped import: ' . (!empty($wordfenceRefresh['skipped_import']) ? 'yes' : 'no');
        $lines[] = '  Cache file: ' . (string) ($wordfenceRefresh['cache_file'] ?? '');
        $lines[] = '';
    }

    $groups = $groups ?? policyUpdateEmailGroupsForPolicy($policy);

    appendPolicyEmailGroup(
        $lines,
        'Assets with emergency updates but still within the ' . (string) ($rules['emergency_delay_hours'] ?? '') . ' hour delay:',
        $groups['emergency_waiting']
    );
    appendPolicyEmailGroup(
        $lines,
        'Assets eligible for emergency action (planned for the next emergency/all apply run):',
        $groups['emergency_action']
    );
    appendPolicyEmailGroup(
        $lines,
        'Assets with updates but still within the ' . (string) ($rules['normal_delay_hours'] ?? '') . ' hour delay:',
        $groups['normal_waiting']
    );
    appendPolicyEmailGroup(
        $lines,
        'Assets eligible for normal action (planned for the next normal/all apply run):',
        $groups['normal_action']
    );
    appendPolicyEmailGroup($lines, 'Assets requiring manual review:', $groups['manual_review']);

    return implode("\n", $lines);
}

function policyUpdateEmailGroupsForPolicy(array $policy): array
{
    $rules = is_array($policy['rules'] ?? null) ? $policy['rules'] : [];

    return policyUpdateEmailGroups(
        $policy,
        (int) ($rules['normal_delay_hours'] ?? 0),
        (int) ($rules['emergency_delay_hours'] ?? 0)
    );
}

function policyEmailGroupsHaveAssets(array $groups): bool
{
    foreach ($groups as $assets) {
        if (is_array($assets) && $assets !== []) {
            return true;
        }
    }

    return false;
}

function appendPolicyEmailGroup(array &$lines, string $heading, array $assets): void
{
    if ($assets === []) {
        return;
    }

    $lines[] = $heading;
    foreach ($assets as $asset) {
        $lines[] = '  - ' . policyEmailAssetLine($asset);
    }
    $lines[] = '';
}

function policyUpdateEmailGroups(array $policy, int $normalHours, int $emergencyHours): array
{
    $groups = [
        'emergency_waiting' => [],
        'emergency_action' => [],
        'normal_waiting' => [],
        'normal_action' => [],
        'manual_review' => [],
    ];

    foreach (policyAssets($policy) as $asset) {
        $action = (string) ($asset['recommended_action'] ?? 'hold');
        $currentVersion = (string) ($asset['current_version'] ?? '');
        $latestUpdate = newestSafeObservedUpdate($asset, $currentVersion);
        $currentIsVulnerable = !empty($asset['current_is_vulnerable']);

        if ($currentIsVulnerable) {
            $emergencyTarget = (string) ($asset['emergency_update_version'] ?? '');
            if ($emergencyTarget !== '') {
                $groups['emergency_action'][] = policyEmailAssetSummary($asset, $emergencyTarget, 'emergency_update');
            }

            if ($latestUpdate !== null && ($emergencyTarget === '' || compareVersions((string) $latestUpdate['version'], $emergencyTarget) > 0)) {
                $note = waitTimeSummary($latestUpdate, $emergencyHours);
                if (isDelayWaitingSummary($note)) {
                    $groups['emergency_waiting'][] = policyEmailAssetSummary(
                        $asset,
                        (string) $latestUpdate['version'],
                        'emergency_waiting',
                        $note
                    );
                }
            }

            if ($action === 'manual_review') {
                $groups['manual_review'][] = policyEmailAssetSummary($asset, null, $action);
            }

            continue;
        }

        $normalTarget = (string) ($asset['allowed_update_version'] ?? '');
        if ($normalTarget !== '') {
            $groups['normal_action'][] = policyEmailAssetSummary($asset, $normalTarget, 'normal_update');
        }

        if ($latestUpdate !== null && ($normalTarget === '' || compareVersions((string) $latestUpdate['version'], $normalTarget) > 0)) {
            $note = waitTimeSummary($latestUpdate, $normalHours);
            if (isDelayWaitingSummary($note)) {
                $groups['normal_waiting'][] = policyEmailAssetSummary(
                    $asset,
                    (string) $latestUpdate['version'],
                    'normal_waiting',
                    $note
                );
            }
        }

        if ($action === 'manual_review') {
            $groups['manual_review'][] = policyEmailAssetSummary($asset, null, $action);
        }
    }

    return $groups;
}

function isDelayWaitingSummary(string $summary): bool
{
    return $summary !== '' && $summary !== 'delay elapsed';
}

function newestSafeObservedUpdate(array $asset, string $currentVersion): ?array
{
    $updates = [];
    foreach (($asset['safe_observed_versions'] ?? []) as $observed) {
        if (!is_array($observed)) {
            continue;
        }

        $version = (string) ($observed['version'] ?? '');
        if ($version === '' || compareVersions($version, $currentVersion) <= 0) {
            continue;
        }

        $updates[] = $observed;
    }

    if ($updates === []) {
        return null;
    }

    usort($updates, static function (array $a, array $b): int {
        return compareVersions((string) ($b['version'] ?? ''), (string) ($a['version'] ?? ''));
    });

    return $updates[0];
}

function waitTimeSummary(array $observed, int $delayHours): string
{
    $firstSeen = strtotime((string) ($observed['first_seen_at'] ?? ''));
    if ($firstSeen === false || $delayHours < 1) {
        return '';
    }

    $readyAt = $firstSeen + ($delayHours * 3600);
    $remainingSeconds = $readyAt - time();
    if ($remainingSeconds <= 0) {
        return 'delay elapsed';
    }

    $remainingHours = (int) ceil($remainingSeconds / 3600);
    return 'about ' . $remainingHours . 'h remaining';
}

function policyEmailAssetSummary(array $asset, ?string $targetVersion, string $action, string $note = ''): array
{
    return [
        'type' => (string) ($asset['type'] ?? 'asset'),
        'slug' => (string) ($asset['slug'] ?? ''),
        'current_version' => (string) ($asset['current_version'] ?? ''),
        'target_version' => $targetVersion,
        'action' => $action,
        'note' => $note,
    ];
}

function policyEmailAssetLine(array $asset): string
{
    $line = strtoupper((string) ($asset['type'] ?? 'asset'))
        . ' ' . (string) ($asset['slug'] ?? '')
        . ' ' . (string) ($asset['current_version'] ?? '')
        . ' => ' . (string) ($asset['action'] ?? '');

    if (!empty($asset['target_version'])) {
        $line .= ' to ' . (string) $asset['target_version'];
    }

    if (!empty($asset['note'])) {
        $line .= ' (' . (string) $asset['note'] . ')';
    }

    return $line;
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

function compareVersions(string $a, string $b): int
{
    return version_compare(normalizeVersion($a), normalizeVersion($b));
}

function normalizeVersion(string $version): string
{
    return preg_replace('/[^0-9A-Za-z.+_-]/', '', trim($version)) ?: '0';
}
