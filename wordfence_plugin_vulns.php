<?php
declare(strict_types=1);

/**
 * Fetch the Wordfence Intelligence v3 vulnerability feed and save either all
 * WordPress software vulnerabilities or a locally filtered plugin subset.
 *
 * Usage:
 *   php wordfence_plugin_vulns.php --plugin=woocommerce
 *   php wordfence_plugin_vulns.php --all
 *   php wordfence_plugin_vulns.php --all --software=all
 *   php wordfence_plugin_vulns.php --plugin=woocommerce --feed=scanner
 *
 * Notes:
 *   Wordfence v3 production/scanner endpoints return the complete feed and do
 *   not accept filter parameters, so plugin filtering is performed client-side.
 *   The API key and database credentials are loaded from --site/wp-config.php
 *   first, then this script directory's wp-config.php as fallback.
 */

const WORDFENCE_PRODUCTION_ENDPOINT = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production';
const WORDFENCE_SCANNER_ENDPOINT = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner';
const DEFAULT_RESULTS_TABLE = 'wordfence_plugin_vulnerabilities';

main($argv);

function main(array $argv): void
{
    $options = parseOptions($argv);
    loadConfigForOptions($options);

    $all = array_key_exists('all', $options);
    $pluginOption = trim((string) ($options['plugin'] ?? ''));

    if (!$all && $pluginOption === '') {
        fwrite(STDERR, "Missing required --plugin option, or use --all.\n\n");
        printUsage();
        exit(1);
    }

    $useCache = array_key_exists('use-cache', $options);
    $apiKey = trim((string) ($options['api-key'] ?? getConfiguredValue('WORDFENCE_API_KEY')));
    if (!$useCache && $apiKey === '') {
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
    $softwareType = strtolower((string) ($options['software'] ?? 'plugin'));

    if (!in_array($softwareType, ['plugin', 'core', 'theme', 'all'], true)) {
        fwrite(STDERR, "Invalid --software value. Use plugin, core, theme, or all.\n");
        exit(1);
    }

    try {
        if (!$useCache) {
            downloadJsonToCache($endpoint, $apiKey, $timeout, $cacheFile);
        }

        $result = processCachedFeed($cacheFile, $all, $plugin, $exact, $save, $table, $all ? 'ALL' : $pluginOption, $feed, $softwareType);
    } catch (RuntimeException $exception) {
        fwrite(STDERR, $exception->getMessage() . "\n");
        exit(1);
    }

    $output = [
        'feed' => $feed,
        'mode' => $all ? 'all_software' : 'plugin_filter',
        'software' => $all ? $softwareType : 'plugin',
        'plugin_filter' => $all ? null : $pluginOption,
        'match_mode' => $all ? null : ($exact ? 'exact slug/name' : 'contains slug/name'),
        'count' => $result['matched_records'],
        'matched_software_rows' => $result['matched_software_rows'],
        'saved_to_mysql' => $save,
        'saved_rows' => $result['saved_rows'],
        'table' => $save ? $table : null,
        'cache_file' => $cacheFile,
        'vulnerabilities' => $all ? [] : array_values(withoutRawRecords($result['matches'])),
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
  --all             Save all matching software vulnerabilities from the feed.
  --software=VALUE  Optional with --all. plugin, core, theme, or all. Default: plugin.
  --site=PATH       Optional. Load wp-config.php from this WordPress path first.
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

function downloadJsonToCache(string $url, string $apiKey, int $timeout, string $cacheFile): void
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
}

function processCachedFeed(
    string $cacheFile,
    bool $all,
    string $plugin,
    bool $exact,
    bool $save,
    string $table,
    string $pluginFilter,
    string $feed,
    string $softwareType
): array
{
    if (!is_file($cacheFile)) {
        throw new RuntimeException("Cache file does not exist: {$cacheFile}");
    }

    $db = null;
    if ($save) {
        validateTableName($table);
        requireDbClass();
        $db = createDatabase();
        createResultsTable($db, $table);
    }

    $matches = [];
    $matchedRecords = 0;
    $matchedSoftwareRows = 0;
    $savedRows = 0;

    foreach (streamTopLevelJsonObject($cacheFile) as $id => $record) {
        if (!is_array($record) || !isset($record['software']) || !is_array($record['software'])) {
            continue;
        }

        $softwareMatches = $all
            ? matchingSoftwareByType($record['software'], $softwareType)
            : matchingFilteredPluginSoftware($record['software'], $plugin, $exact);

        if ($softwareMatches === []) {
            continue;
        }

        $outputRecord = vulnerabilityOutputRecord($record, $id, $softwareMatches);
        $matchedRecords++;
        $matchedSoftwareRows += count($softwareMatches);

        if ($save && $db instanceof DB) {
            foreach ($softwareMatches as $software) {
                saveMatchRow($db, $table, $outputRecord, $software, $pluginFilter, $feed);
                $savedRows++;
            }
        }

        if (!$all) {
            $matches[$id] = $outputRecord;
        }
    }

    return [
        'matched_records' => $matchedRecords,
        'matched_software_rows' => $matchedSoftwareRows,
        'saved_rows' => $savedRows,
        'matches' => $matches,
    ];
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

function streamTopLevelJsonObject(string $cacheFile): Generator
{
    $handle = fopen($cacheFile, 'rb');
    if ($handle === false) {
        throw new RuntimeException("Unable to open cache file: {$cacheFile}");
    }

    try {
        skipJsonWhitespace($handle);
        $first = readJsonChar($handle);
        if ($first !== '{') {
            throw new RuntimeException("Cached Wordfence response was not a JSON object: {$cacheFile}");
        }

        while (true) {
            skipJsonWhitespace($handle);
            $char = readJsonChar($handle);

            if ($char === '}') {
                break;
            }

            if ($char === null) {
                throw new RuntimeException("Unexpected end of JSON while reading {$cacheFile}");
            }

            if ($char !== '"') {
                throw new RuntimeException("Expected vulnerability id string in {$cacheFile}");
            }

            $id = readJsonStringAfterOpeningQuote($handle);
            skipJsonWhitespace($handle);

            if (readJsonChar($handle) !== ':') {
                throw new RuntimeException("Expected colon after vulnerability id {$id}");
            }

            skipJsonWhitespace($handle);
            $rawValue = readJsonValue($handle);
            $record = json_decode($rawValue, true);
            if (!is_array($record)) {
                throw new RuntimeException("Invalid JSON record for vulnerability id {$id}");
            }

            yield $id => $record;

            skipJsonWhitespace($handle);
            $separator = readJsonChar($handle);
            if ($separator === '}') {
                break;
            }

            if ($separator !== ',') {
                throw new RuntimeException("Expected comma after vulnerability id {$id}");
            }
        }
    } finally {
        fclose($handle);
    }
}

function skipJsonWhitespace($handle): void
{
    while (($char = readJsonChar($handle)) !== null) {
        if (!ctype_space($char)) {
            fseek($handle, -1, SEEK_CUR);
            return;
        }
    }
}

function readJsonChar($handle): ?string
{
    $char = fgetc($handle);
    return $char === false ? null : $char;
}

function readJsonStringAfterOpeningQuote($handle): string
{
    $raw = '"';
    $escaped = false;

    while (($char = readJsonChar($handle)) !== null) {
        $raw .= $char;

        if ($escaped) {
            $escaped = false;
            continue;
        }

        if ($char === '\\') {
            $escaped = true;
            continue;
        }

        if ($char === '"') {
            $decoded = json_decode($raw, true);
            if (!is_string($decoded)) {
                throw new RuntimeException('Invalid JSON object key.');
            }

            return $decoded;
        }
    }

    throw new RuntimeException('Unexpected end of JSON while reading object key.');
}

function readJsonValue($handle): string
{
    $raw = '';
    $inString = false;
    $escaped = false;
    $depth = 0;
    $started = false;

    while (($char = readJsonChar($handle)) !== null) {
        if (!$started) {
            if (ctype_space($char)) {
                continue;
            }

            $started = true;
        }

        $raw .= $char;

        if ($inString) {
            if ($escaped) {
                $escaped = false;
            } elseif ($char === '\\') {
                $escaped = true;
            } elseif ($char === '"') {
                $inString = false;
            }

            continue;
        }

        if ($char === '"') {
            $inString = true;
            continue;
        }

        if ($char === '{' || $char === '[') {
            $depth++;
            continue;
        }

        if ($char === '}' || $char === ']') {
            $depth--;
            if ($depth === 0) {
                return $raw;
            }
        }
    }

    throw new RuntimeException('Unexpected end of JSON while reading value.');
}

function matchingSoftwareByType(array $softwareItems, string $softwareType): array
{
    $matches = [];

    foreach ($softwareItems as $software) {
        if (!is_array($software)) {
            continue;
        }

        if ($softwareType === 'all' || ($software['type'] ?? null) === $softwareType) {
            $matches[] = $software;
        }
    }

    return $matches;
}

function matchingFilteredPluginSoftware(array $softwareItems, string $plugin, bool $exact): array
{
    $matches = [];

    foreach ($softwareItems as $software) {
        if (!is_array($software) || ($software['type'] ?? null) !== 'plugin') {
            continue;
        }

        $slug = normalize((string) ($software['slug'] ?? ''));
        $name = normalize((string) ($software['name'] ?? ''));

        $matched = $exact
            ? $plugin === $slug || $plugin === $name
            : contains($slug, $plugin) || contains($name, $plugin);

        if ($matched) {
            $matches[] = $software;
        }
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
    validateTableName($table);
    requireDbClass();

    $db = createDatabase();

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

function validateTableName(string $table): void
{
    if (!preg_match('/^[A-Za-z0-9_]+$/', $table)) {
        throw new RuntimeException('Invalid table name. Use letters, numbers, and underscores only.');
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
            `software_type` varchar(20) NOT NULL DEFAULT 'plugin',
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
            PRIMARY KEY (`vulnerability_id`, `software_type`, `software_slug`),
            KEY `idx_software_slug` (`software_slug`),
            KEY `idx_software_type_slug` (`software_type`, `software_slug`),
            KEY `idx_cve` (`cve`),
            KEY `idx_published_at` (`published_at`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    migrateResultsTable($db, $table);
}

function migrateResultsTable(DB $db, string $table): void
{
    if (!tableColumnExists($db, $table, 'software_type')) {
        $db->execute("ALTER TABLE `{$table}` ADD COLUMN `software_type` varchar(20) NOT NULL DEFAULT 'plugin' AFTER `vulnerability_id`");
    }

    $primaryKeyColumns = primaryKeyColumns($db, $table);
    if ($primaryKeyColumns !== ['vulnerability_id', 'software_type', 'software_slug']) {
        $db->execute("ALTER TABLE `{$table}` DROP PRIMARY KEY, ADD PRIMARY KEY (`vulnerability_id`, `software_type`, `software_slug`)");
    }

    if (!indexExists($db, $table, 'idx_software_type_slug')) {
        $db->execute("ALTER TABLE `{$table}` ADD KEY `idx_software_type_slug` (`software_type`, `software_slug`)");
    }
}

function tableColumnExists(DB $db, string $table, string $column): bool
{
    $result = $db->query("
        SELECT COUNT(*) AS `count`
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = " . sqlString($db, $table) . "
          AND COLUMN_NAME = " . sqlString($db, $column) . "
    ");
    $row = mysqli_fetch_assoc($result);

    return isset($row['count']) && (int) $row['count'] > 0;
}

function primaryKeyColumns(DB $db, string $table): array
{
    $result = $db->query("SHOW KEYS FROM `{$table}` WHERE Key_name = 'PRIMARY' ORDER BY Seq_in_index ASC");
    $columns = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $columns[] = (string) $row['Column_name'];
    }

    return $columns;
}

function indexExists(DB $db, string $table, string $index): bool
{
    $result = $db->query("SHOW KEYS FROM `{$table}` WHERE Key_name = " . sqlString($db, $index));

    return mysqli_fetch_assoc($result) !== null;
}

function saveMatchRow(DB $db, string $table, array $record, array $software, string $pluginFilter, string $feed): void
{
    $vulnerabilityId = (string) ($record['id'] ?? '');
    if ($vulnerabilityId === '') {
        $vulnerabilityId = substr(sha1(json_encode($record, JSON_UNESCAPED_SLASHES)), 0, 32);
    }
    $softwareType = (string) ($software['type'] ?? 'plugin');
    if (!in_array($softwareType, ['plugin', 'core', 'theme'], true)) {
        $softwareType = 'unknown';
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
        'software_type' => sqlString($db, $softwareType),
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
            `software_type`,
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
            {$values['software_type']},
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
