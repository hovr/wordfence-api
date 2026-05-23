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

function sqlString(DB $db, string $value): string
{
    return "'" . $db->escapeString($value) . "'";
}
