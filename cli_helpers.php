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



function ensureWordfenceVulnerabilityTableCompatible(DB $db, string $table): void
{
    validateTableName($table);

    if (!tableExists($db, $table)) {
        throw new RuntimeException("Wordfence vulnerability table does not exist: {$table}. Run with --refresh-wordfence first.");
    }

    if (!tableColumnExists($db, $table, 'software_type')) {
        $db->execute("ALTER TABLE `{$table}` ADD COLUMN `software_type` varchar(20) NULL DEFAULT NULL AFTER `vulnerability_id`");
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

function sqlString(DB $db, string $value): string
{
    return "'" . $db->escapeString($value) . "'";
}
