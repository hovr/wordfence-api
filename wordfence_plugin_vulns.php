<?php
declare(strict_types=1);

/**
 * Fetch the Wordfence Intelligence v3 vulnerability feed and save either all
 * plugin vulnerabilities or a locally filtered plugin subset.
 *
 * Usage:
 *   php wordfence_plugin_vulns.php --plugin=woocommerce
 *   php wordfence_plugin_vulns.php --all
 *   php wordfence_plugin_vulns.php --plugin=woocommerce --feed=scanner
 *
 * Notes:
 *   Wordfence v3 production/scanner endpoints return the complete feed and do
 *   not accept filter parameters, so plugin filtering is performed client-side.
 *   The API key and database credentials are loaded from wp-config.php.
 */

const WORDFENCE_PRODUCTION_ENDPOINT = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production';
const WORDFENCE_SCANNER_ENDPOINT = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner';
const DEFAULT_RESULTS_TABLE = 'wordfence_plugin_vulnerabilities';

main($argv);

function main(array $argv): void
{
    loadLocalConfig();

    $options = parseOptions($argv);

    $all = array_key_exists('all', $options);
    $pluginOption = trim((string) ($options['plugin'] ?? ''));

    if (!$all && $pluginOption === '') {
        fwrite(STDERR, "Missing required --plugin option, or use --all.\n\n");
        printUsage();
        exit(1);
    }

    $apiKey = trim((string) ($options['api-key'] ?? getConfiguredValue('WORDFENCE_API_KEY')));
    if ($apiKey === '') {
        fwrite(STDERR, "Missing API key. Define WORDFENCE_API_KEY in wp-config.php or pass --api-key.\n\n");
        printUsage();
        exit(1);
    }

    $feed = strtolower((string) ($options['feed'] ?? 'production'));
    $endpoint = null;
    if ($feed === 'production') {
        $endpoint = WORDFENCE_PRODUCTION_ENDPOINT;
    } elseif ($feed === 'scanner') {
        $endpoint = WORDFENCE_SCANNER_ENDPOINT;
    }

    if ($endpoint === null) {
        fwrite(STDERR, "Invalid --feed value. Use production or scanner.\n");
        exit(1);
    }

    $plugin = normalize($pluginOption);
    $exact = array_key_exists('exact', $options);
    $save = !array_key_exists('no-save', $options);
    $table = (string) ($options['table'] ?? DEFAULT_RESULTS_TABLE);
    $timeout = parsePositiveInt((string) ($options['timeout'] ?? '600'), 600);
    $cacheFile = (string) ($options['cache-file'] ?? defaultCacheFile($feed));
    $useCache = array_key_exists('use-cache', $options);

    try {
        $feedData = $useCache ? loadCachedJson($cacheFile) : fetchJson($endpoint, $apiKey, $timeout, $cacheFile);
        $matches = $all ? allPluginVulnerabilities($feedData) : filterPluginVulnerabilities($feedData, $plugin, $exact);
        $saved = $save ? saveMatchesToMysql($matches, $table, $all ? 'ALL' : $pluginOption, $feed) : 0;
    } catch (RuntimeException $exception) {
        fwrite(STDERR, $exception->getMessage() . "\n");
        exit(1);
    }

    $output = [
        'feed' => $feed,
        'mode' => $all ? 'all_plugins' : 'plugin_filter',
        'plugin_filter' => $all ? null : $pluginOption,
        'match_mode' => $all ? null : ($exact ? 'exact slug/name' : 'contains slug/name'),
        'count' => count($matches),
        'saved_to_mysql' => $save,
        'saved_rows' => $saved,
        'table' => $save ? $table : null,
        'vulnerabilities' => array_values(withoutRawRecords($matches)),
    ];

    echo json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
}

function printUsage(): void
{
    echo <<<TEXT
Usage:
  php wordfence_plugin_vulns.php --plugin=PLUGIN_SLUG_OR_NAME
  php wordfence_plugin_vulns.php --all

Options:
  --plugin=VALUE    Plugin slug or name to match.
  --all             Save all plugin vulnerabilities from the feed.
  --api-key=VALUE   Optional. Defaults to WORDFENCE_API_KEY from wp-config.php.
  --feed=VALUE      Optional. production or scanner. Default: production.
  --exact           Optional. Require exact slug/name match instead of contains match.
  --table=VALUE     Optional. MySQL table to save into. Default: wordfence_plugin_vulnerabilities.
  --timeout=SECONDS Optional. Download timeout. Default: 600.
  --cache-file=PATH Optional. Feed JSON cache path. Default: ./cache/wordfence-FEED.json.
  --use-cache       Optional. Skip download and read from cache file.
  --no-save         Optional. Print JSON without saving matches to MySQL.

TEXT;
}

function loadLocalConfig(): void
{
    $configPath = __DIR__ . '/wp-config.php';
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

function fetchJson(string $url, string $apiKey, int $timeout, string $cacheFile): array
{
    ensureDirectory(dirname($cacheFile));
    $tmpFile = $cacheFile . '.tmp';
    $handle = fopen($tmpFile, 'wb');
    if ($handle === false) {
        throw new RuntimeException("Unable to open temporary cache file for writing: {$tmpFile}");
    }

    $curl = curl_init($url);
    if ($curl === false) {
        fclose($handle);
        throw new RuntimeException('Unable to initialize cURL.');
    }

    curl_setopt_array($curl, [
        CURLOPT_FILE => $handle,
        CURLOPT_HTTPHEADER => [
            'Accept: application/json',
            'Authorization: Bearer ' . $apiKey,
        ],
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_USERAGENT => 'Wordfence Plugin Vulnerability Checker/1.0',
        CURLOPT_FOLLOWLOCATION => true,
    ]);

    $success = curl_exec($curl);
    $error = curl_error($curl);
    $statusCode = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
    fclose($handle);

    if ($success === false) {
        @unlink($tmpFile);
        throw new RuntimeException('Wordfence request failed: ' . $error);
    }

    if ($statusCode < 200 || $statusCode >= 300) {
        $body = is_file($tmpFile) ? substr((string) file_get_contents($tmpFile), 0, 1000) : '';
        @unlink($tmpFile);
        throw new RuntimeException("Wordfence request returned HTTP {$statusCode}: {$body}");
    }

    if (!rename($tmpFile, $cacheFile)) {
        @unlink($tmpFile);
        throw new RuntimeException("Unable to move temporary cache file into place: {$cacheFile}");
    }

    return loadCachedJson($cacheFile);
}

function loadCachedJson(string $cacheFile): array
{
    if (!is_file($cacheFile)) {
        throw new RuntimeException("Cache file does not exist: {$cacheFile}");
    }

    $response = file_get_contents($cacheFile);
    if ($response === false) {
        throw new RuntimeException("Unable to read cache file: {$cacheFile}");
    }

    $data = json_decode($response, true);
    if (!is_array($data)) {
        throw new RuntimeException("Cached Wordfence response was not valid JSON: {$cacheFile}");
    }

    return $data;
}

function defaultCacheFile(string $feed): string
{
    return __DIR__ . '/cache/wordfence-' . $feed . '.json';
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

function allPluginVulnerabilities(array $feedData): array
{
    $matches = [];

    foreach ($feedData as $id => $record) {
        if (!is_array($record) || !isset($record['software']) || !is_array($record['software'])) {
            continue;
        }

        $pluginSoftware = [];

        foreach ($record['software'] as $software) {
            if (is_array($software) && ($software['type'] ?? null) === 'plugin') {
                $pluginSoftware[] = $software;
            }
        }

        if ($pluginSoftware === []) {
            continue;
        }

        $matches[$id] = vulnerabilityOutputRecord($record, $id, $pluginSoftware);
    }

    return $matches;
}

function filterPluginVulnerabilities(array $feedData, string $plugin, bool $exact): array
{
    $matches = [];

    foreach ($feedData as $id => $record) {
        if (!is_array($record) || !isset($record['software']) || !is_array($record['software'])) {
            continue;
        }

        $matchingSoftware = [];

        foreach ($record['software'] as $software) {
            if (!is_array($software) || ($software['type'] ?? null) !== 'plugin') {
                continue;
            }

            $slug = normalize((string) ($software['slug'] ?? ''));
            $name = normalize((string) ($software['name'] ?? ''));

            $matched = $exact
                ? $plugin === $slug || $plugin === $name
                : contains($slug, $plugin) || contains($name, $plugin);

            if ($matched) {
                $matchingSoftware[] = $software;
            }
        }

        if ($matchingSoftware === []) {
            continue;
        }

        $matches[$id] = vulnerabilityOutputRecord($record, $id, $matchingSoftware);
    }

    return $matches;
}

function vulnerabilityOutputRecord(array $record, $fallbackId, array $software): array
{
    return [
        '_raw' => $record,
        'id' => $record['id'] ?? $fallbackId,
        'title' => $record['title'] ?? null,
        'published' => $record['published'] ?? null,
        'updated' => $record['updated'] ?? null,
        'cve' => $record['cve'] ?? null,
        'cvss' => $record['cvss'] ?? null,
        'references' => $record['references'] ?? [],
        'software' => $software,
    ];
}

function normalize(string $value): string
{
    return strtolower(trim($value));
}

function contains(string $haystack, string $needle): bool
{
    return $needle === '' || strpos($haystack, $needle) !== false;
}

function withoutRawRecords(array $matches): array
{
    foreach ($matches as &$match) {
        unset($match['_raw']);
    }
    unset($match);

    return $matches;
}

function saveMatchesToMysql(array $matches, string $table, string $pluginFilter, string $feed): int
{
    if (!preg_match('/^[A-Za-z0-9_]+$/', $table)) {
        throw new RuntimeException('Invalid table name. Use letters, numbers, and underscores only.');
    }

    requireDbClass();

    $db = new DB(
        getRequiredConfiguredValue('DB_NAME'),
        getRequiredConfiguredValue('DB_HOST'),
        getRequiredConfiguredValue('DB_USER'),
        getRequiredConfiguredValue('DB_PASSWORD')
    );

    createResultsTable($db, $table);

    $saved = 0;
    foreach ($matches as $record) {
        foreach ($record['software'] as $software) {
            saveMatchRow($db, $table, $record, $software, $pluginFilter, $feed);
            $saved++;
        }
    }

    return $saved;
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

function getRequiredConfiguredValue(string $constant): string
{
    $value = getConfiguredValue($constant);
    if ($value === '') {
        throw new RuntimeException("Missing {$constant} in wp-config.php.");
    }

    return $value;
}

function createResultsTable(DB $db, string $table): void
{
    $db->execute("
        CREATE TABLE IF NOT EXISTS `{$table}` (
            `vulnerability_id` varchar(64) NOT NULL,
            `software_slug` varchar(191) NOT NULL,
            `software_name` varchar(255) DEFAULT NULL,
            `plugin_filter` varchar(255) DEFAULT NULL,
            `feed` varchar(32) NOT NULL,
            `title` text,
            `cve` varchar(64) DEFAULT NULL,
            `cvss_score` decimal(3,1) DEFAULT NULL,
            `cvss_rating` varchar(32) DEFAULT NULL,
            `patched` tinyint(1) DEFAULT NULL,
            `published_at` datetime DEFAULT NULL,
            `updated_at` datetime DEFAULT NULL,
            `affected_versions_json` longtext,
            `patched_versions_json` longtext,
            `remediation` text,
            `references_json` longtext,
            `software_json` longtext,
            `raw_record_json` longtext,
            `last_seen_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (`vulnerability_id`, `software_slug`),
            KEY `idx_software_slug` (`software_slug`),
            KEY `idx_cve` (`cve`),
            KEY `idx_published_at` (`published_at`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");
}

function saveMatchRow(DB $db, string $table, array $record, array $software, string $pluginFilter, string $feed): void
{
    $vulnerabilityId = (string) ($record['id'] ?? '');
    if ($vulnerabilityId === '') {
        $vulnerabilityId = substr(sha1(json_encode($record, JSON_UNESCAPED_SLASHES)), 0, 32);
    }
    $softwareSlug = (string) ($software['slug'] ?? '');
    if ($softwareSlug === '') {
        $softwareSlug = substr(sha1((string) ($software['name'] ?? $vulnerabilityId)), 0, 16);
    }

    $cvss = is_array($record['cvss'] ?? null) ? $record['cvss'] : [];
    $publishedAt = sqlDateOrNull($record['published'] ?? null);
    $updatedAt = sqlDateOrNull($record['updated'] ?? null);
    $patched = array_key_exists('patched', $software) ? ((bool) $software['patched'] ? '1' : '0') : 'NULL';
    $cvssScore = isset($cvss['score']) && is_numeric($cvss['score']) ? (string) (float) $cvss['score'] : 'NULL';

    $values = [
        'vulnerability_id' => sqlString($db, $vulnerabilityId),
        'software_slug' => sqlString($db, $softwareSlug),
        'software_name' => sqlNullableString($db, $software['name'] ?? null),
        'plugin_filter' => sqlString($db, $pluginFilter),
        'feed' => sqlString($db, $feed),
        'title' => sqlNullableString($db, $record['title'] ?? null),
        'cve' => sqlNullableString($db, $record['cve'] ?? null),
        'cvss_score' => $cvssScore,
        'cvss_rating' => sqlNullableString($db, $cvss['rating'] ?? null),
        'patched' => $patched,
        'published_at' => $publishedAt,
        'updated_at' => $updatedAt,
        'affected_versions_json' => sqlJson($db, $software['affected_versions'] ?? null),
        'patched_versions_json' => sqlJson($db, $software['patched_versions'] ?? null),
        'remediation' => sqlNullableString($db, $software['remediation'] ?? null),
        'references_json' => sqlJson($db, $record['references'] ?? []),
        'software_json' => sqlJson($db, $software),
        'raw_record_json' => sqlJson($db, $record['_raw'] ?? $record),
    ];

    $db->execute("
        INSERT INTO `{$table}` (
            `vulnerability_id`,
            `software_slug`,
            `software_name`,
            `plugin_filter`,
            `feed`,
            `title`,
            `cve`,
            `cvss_score`,
            `cvss_rating`,
            `patched`,
            `published_at`,
            `updated_at`,
            `affected_versions_json`,
            `patched_versions_json`,
            `remediation`,
            `references_json`,
            `software_json`,
            `raw_record_json`
        ) VALUES (
            {$values['vulnerability_id']},
            {$values['software_slug']},
            {$values['software_name']},
            {$values['plugin_filter']},
            {$values['feed']},
            {$values['title']},
            {$values['cve']},
            {$values['cvss_score']},
            {$values['cvss_rating']},
            {$values['patched']},
            {$values['published_at']},
            {$values['updated_at']},
            {$values['affected_versions_json']},
            {$values['patched_versions_json']},
            {$values['remediation']},
            {$values['references_json']},
            {$values['software_json']},
            {$values['raw_record_json']}
        )
        ON DUPLICATE KEY UPDATE
            `software_name` = VALUES(`software_name`),
            `plugin_filter` = VALUES(`plugin_filter`),
            `feed` = VALUES(`feed`),
            `title` = VALUES(`title`),
            `cve` = VALUES(`cve`),
            `cvss_score` = VALUES(`cvss_score`),
            `cvss_rating` = VALUES(`cvss_rating`),
            `patched` = VALUES(`patched`),
            `published_at` = VALUES(`published_at`),
            `updated_at` = VALUES(`updated_at`),
            `affected_versions_json` = VALUES(`affected_versions_json`),
            `patched_versions_json` = VALUES(`patched_versions_json`),
            `remediation` = VALUES(`remediation`),
            `references_json` = VALUES(`references_json`),
            `software_json` = VALUES(`software_json`),
            `raw_record_json` = VALUES(`raw_record_json`),
            `last_seen_at` = CURRENT_TIMESTAMP
    ");
}

function sqlString(DB $db, string $value): string
{
    return "'" . $db->escapeString($value) . "'";
}

function sqlNullableString(DB $db, $value): string
{
    if ($value === null || $value === '') {
        return 'NULL';
    }

    return sqlString($db, (string) $value);
}

function sqlJson(DB $db, $value): string
{
    return sqlString($db, json_encode($value, JSON_UNESCAPED_SLASHES));
}

function sqlDateOrNull($value): string
{
    if (!is_string($value) || trim($value) === '') {
        return 'NULL';
    }

    $timestamp = strtotime($value);
    if ($timestamp === false) {
        return 'NULL';
    }

    return "'" . gmdate('Y-m-d H:i:s', $timestamp) . "'";
}
