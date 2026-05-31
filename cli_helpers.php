<?php
declare(strict_types=1);

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

function loadOptionsWithSettings(array $cliOptions, string $settingsOption = 'policy-settings', string $settingsLabel = 'policy settings'): array
{
    $settingsPath = (string) ($cliOptions[$settingsOption] ?? '');
    if ($settingsPath === '') {
        return $cliOptions;
    }

    if (!is_file($settingsPath)) {
        throw new RuntimeException("Missing {$settingsLabel} file: {$settingsPath}");
    }

    $json = file_get_contents($settingsPath);
    if ($json === false) {
        throw new RuntimeException("Unable to read {$settingsLabel} file: {$settingsPath}");
    }

    $settings = json_decode($json, true);
    if (!is_array($settings)) {
        throw new RuntimeException("Invalid {$settingsLabel} JSON: {$settingsPath}");
    }

    $options = [];
    foreach ($settings as $key => $value) {
        $optionKey = str_replace('_', '-', (string) $key);
        if (is_bool($value)) {
            if ($value) {
                $options[$optionKey] = true;
            }
            continue;
        }

        $options[$optionKey] = $value;
    }

    foreach ($cliOptions as $key => $value) {
        $options[$key] = $value;
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
    if (!empty($options['config'])) {
        $paths[] = (string) $options['config'];
    }

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

function createWordfenceVulnerabilityTable(DB $db, string $table): void
{
    validateTableName($table);

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
            `import_cache_sha256` char(64) DEFAULT NULL,
            `last_seen_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (`vulnerability_id`, `software_type`, `software_slug`),
            KEY `idx_software_slug` (`software_slug`),
            KEY `idx_software_type_slug` (`software_type`, `software_slug`),
            KEY `idx_cve` (`cve`),
            KEY `idx_published_at` (`published_at`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    ensureWordfenceVulnerabilityTableCompatible($db, $table);
}

function wordfenceUpsertVulnerabilityRow(DB $db, string $table, array $row): void
{
    validateTableName($table);

    $values = [
        'vulnerability_id' => sqlString($db, (string) $row['vulnerability_id']),
        'software_type' => sqlString($db, (string) $row['software_type']),
        'software_slug' => sqlString($db, (string) $row['software_slug']),
        'software_name' => wordfenceSqlNullableString($db, $row['software_name'] ?? null),
        'plugin_filter' => wordfenceSqlNullableString($db, $row['plugin_filter'] ?? null),
        'feed' => sqlString($db, (string) $row['feed']),
        'title' => wordfenceSqlNullableString($db, $row['title'] ?? null),
        'cve' => wordfenceSqlNullableString($db, $row['cve'] ?? null),
        'cvss_score' => wordfenceSqlNullableNumber($row['cvss_score'] ?? null),
        'cvss_rating' => wordfenceSqlNullableString($db, $row['cvss_rating'] ?? null),
        'patched' => wordfenceSqlNullableInt($row['patched'] ?? null),
        'published_at' => wordfenceSqlNullableString($db, $row['published_at'] ?? null),
        'updated_at' => wordfenceSqlNullableString($db, $row['updated_at'] ?? null),
        'affected_versions_json' => wordfenceSqlNullableString($db, $row['affected_versions_json'] ?? null),
        'patched_versions_json' => wordfenceSqlNullableString($db, $row['patched_versions_json'] ?? null),
        'remediation' => wordfenceSqlNullableString($db, $row['remediation'] ?? null),
        'references_json' => wordfenceSqlNullableString($db, $row['references_json'] ?? null),
        'software_json' => wordfenceSqlNullableString($db, $row['software_json'] ?? null),
        'raw_record_json' => wordfenceSqlNullableString($db, $row['raw_record_json'] ?? null),
        'import_cache_sha256' => wordfenceSqlNullableString($db, $row['import_cache_sha256'] ?? null),
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
            `raw_record_json`,
            `import_cache_sha256`
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
            {$values['raw_record_json']},
            {$values['import_cache_sha256']}
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
            `import_cache_sha256` = VALUES(`import_cache_sha256`),
            `last_seen_at` = CURRENT_TIMESTAMP
    ");
}

function wordfenceImportedRowCount(DB $db, string $table, string $feed, string $softwareType, string $cacheHash): int
{
    validateTableName($table);

    $where = "WHERE `feed` = " . sqlString($db, $feed)
        . " AND `import_cache_sha256` = " . sqlString($db, $cacheHash);
    if ($softwareType !== 'all') {
        $where .= " AND `software_type` = " . sqlString($db, $softwareType);
    }

    $result = $db->query("
        SELECT COUNT(*) AS `count`
        FROM `{$table}`
        {$where}
    ");
    $row = mysqli_fetch_assoc($result);

    return isset($row['count']) ? (int) $row['count'] : 0;
}

function wordfenceVulnerabilityRowCount(DB $db, string $table, string $feed, string $softwareType): int
{
    validateTableName($table);

    $where = "WHERE `feed` = " . sqlString($db, $feed);
    if ($softwareType !== 'all') {
        $where .= " AND `software_type` = " . sqlString($db, $softwareType);
    }

    $result = $db->query("
        SELECT COUNT(*) AS `count`
        FROM `{$table}`
        {$where}
    ");
    $row = mysqli_fetch_assoc($result);

    return isset($row['count']) ? (int) $row['count'] : 0;
}

function wordfenceJsonValue($value): string
{
    $json = json_encode($value, JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        throw new RuntimeException('Unable to encode Wordfence vulnerability row JSON.');
    }

    return $json;
}

function wordfenceSqlNullableString(DB $db, $value): string
{
    if ($value === null || $value === '') {
        return 'NULL';
    }

    return sqlString($db, (string) $value);
}

function wordfenceSqlNullableNumber($value): string
{
    return is_numeric($value) ? (string) (float) $value : 'NULL';
}

function wordfenceSqlNullableInt($value): string
{
    return $value === null || $value === '' ? 'NULL' : (string) (int) $value;
}

function acquireWordfenceVulnerabilityLock(DB $db, string $table, int $timeoutSeconds = 30): string
{
    validateTableName($table);
    $lockName = 'wordfence_vuln_' . substr(sha1($table), 0, 40);
    $timeoutSeconds = max(0, $timeoutSeconds);
    $result = $db->query('SELECT GET_LOCK(' . sqlString($db, $lockName) . ", {$timeoutSeconds}) AS `locked`");
    $row = mysqli_fetch_assoc($result);

    if (!isset($row['locked']) || (int) $row['locked'] !== 1) {
        throw new RuntimeException("Unable to acquire Wordfence vulnerability table lock for {$table}.");
    }

    return $lockName;
}

function releaseWordfenceVulnerabilityLock(DB $db, string $lockName): void
{
    $db->query('SELECT RELEASE_LOCK(' . sqlString($db, $lockName) . ')');
}

function runCommand(array $command, ?string &$stderr = null, ?int &$status = null, bool $throwOnFailure = true, string $stderrPrefix = 'cli-stderr-'): string
{
    $escaped = array_map('escapeshellarg', $command);
    $stderrFile = tempnam(sys_get_temp_dir(), $stderrPrefix);
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

function ensureWordfenceVulnerabilityTableCompatible(DB $db, string $table): void
{
    validateTableName($table);

    if (!tableExists($db, $table)) {
        throw new RuntimeException("Wordfence vulnerability table does not exist: {$table}. Run with --refresh-wordfence first.");
    }

    if (!tableColumnExists($db, $table, 'software_type')) {
        $db->execute("ALTER TABLE `{$table}` ADD COLUMN `software_type` varchar(20) NULL DEFAULT NULL AFTER `vulnerability_id`");
    }

    if (!tableColumnExists($db, $table, 'import_cache_sha256')) {
        $db->execute("ALTER TABLE `{$table}` ADD COLUMN `import_cache_sha256` char(64) DEFAULT NULL AFTER `raw_record_json`");
    }

    backfillWordfenceSoftwareType($db, $table);

    $primaryKeyColumns = primaryKeyColumns($db, $table);
    if ($primaryKeyColumns !== ['vulnerability_id', 'software_type', 'software_slug']) {
        $db->execute("ALTER TABLE `{$table}` DROP PRIMARY KEY, ADD PRIMARY KEY (`vulnerability_id`, `software_type`, `software_slug`)");
    }

    if (!indexExists($db, $table, 'idx_software_type_slug')) {
        $db->execute("ALTER TABLE `{$table}` ADD KEY `idx_software_type_slug` (`software_type`, `software_slug`)");
    }
}

function backfillWordfenceSoftwareType(DB $db, string $table): void
{
    $db->execute("
        UPDATE `{$table}`
        SET `software_type` = CASE
            WHEN JSON_UNQUOTE(JSON_EXTRACT(`software_json`, '$.type')) IN ('plugin', 'core', 'theme')
                THEN JSON_UNQUOTE(JSON_EXTRACT(`software_json`, '$.type'))
            ELSE 'plugin'
        END
        WHERE `software_type` IS NULL
           OR `software_type` = ''
           OR JSON_UNQUOTE(JSON_EXTRACT(`software_json`, '$.type')) IN ('core', 'theme')
    ");

    $db->execute("ALTER TABLE `{$table}` MODIFY COLUMN `software_type` varchar(20) NOT NULL DEFAULT 'plugin'");
}

function tableExists(DB $db, string $table): bool
{
    $result = $db->query("
        SELECT COUNT(*) AS `count`
        FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = " . sqlString($db, $table) . "
    ");
    $row = mysqli_fetch_assoc($result);

    return isset($row['count']) && (int) $row['count'] > 0;
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
    $result = $db->query("
        SELECT COLUMN_NAME
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = " . sqlString($db, $table) . "
          AND INDEX_NAME = 'PRIMARY'
        ORDER BY SEQ_IN_INDEX ASC
    ");
    $columns = [];
    while ($row = mysqli_fetch_assoc($result)) {
        $columns[] = (string) $row['COLUMN_NAME'];
    }

    return $columns;
}

function indexExists(DB $db, string $table, string $index): bool
{
    $result = $db->query("
        SELECT COUNT(*) AS `count`
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = " . sqlString($db, $table) . "
          AND INDEX_NAME = " . sqlString($db, $index) . "
    ");
    $row = mysqli_fetch_assoc($result);

    return isset($row['count']) && (int) $row['count'] > 0;
}

function sqlString(DB $db, string $value): string
{
    return "'" . $db->escapeString($value) . "'";
}
