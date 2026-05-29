<?php
declare(strict_types=1);

/**
 * Sync Wordfence vulnerability rows from a central read-only MySQL database
 * into the local vulnerability table used by wp_update_policy.php.
 *
 * Usage:
 *   php sync_wordfence_db.php --remote-host=db.example.com --remote-db=central --remote-user=reader --remote-password=secret
 *
 * Remote config can also be supplied by constants:
 *   WORDFENCE_REMOTE_DB_HOST
 *   WORDFENCE_REMOTE_DB_NAME
 *   WORDFENCE_REMOTE_DB_USER
 *   WORDFENCE_REMOTE_DB_PASSWORD
 *   WORDFENCE_REMOTE_DB_TABLE
 */

const DEFAULT_VULN_TABLE = 'wordfence_plugin_vulnerabilities';

require_once __DIR__ . '/cli_helpers.php';

main($argv);

function main(array $argv): void
{
    $options = parseOptions($argv);
    if (array_key_exists('help', $options)) {
        printUsage();
        exit(0);
    }

    loadConfigForOptions($options);
    requireDbClass();

    $localTable = (string) ($options['local-table'] ?? DEFAULT_VULN_TABLE);
    $remoteTable = (string) ($options['remote-table'] ?? getConfiguredValue('WORDFENCE_REMOTE_DB_TABLE') ?: DEFAULT_VULN_TABLE);
    $batchSize = parsePositiveInt((string) ($options['batch-size'] ?? '1000'), 1000);

    validateTableName($localTable);
    validateTableName($remoteTable);

    try {
        $localDb = createDatabase();
        createLocalWordfenceTable($localDb, $localTable);

        $remote = remoteConnectionSettings($options);
        $remoteLink = mysqli_connect($remote['host'], $remote['user'], $remote['password'], $remote['database']);
        if (!$remoteLink) {
            throw new RuntimeException('Unable to connect to remote Wordfence database: ' . mysqli_connect_error());
        }

        mysqli_set_charset($remoteLink, 'utf8mb4');
        $remoteCount = remoteRowCount($remoteLink, $remoteTable);
        $synced = syncRows($remoteLink, $localDb, $remoteTable, $localTable, $batchSize);
        mysqli_close($remoteLink);
    } catch (RuntimeException $exception) {
        fwrite(STDERR, $exception->getMessage() . "\n");
        exit(1);
    }

    echo json_encode([
        'remote_table' => $remoteTable,
        'local_table' => $localTable,
        'remote_rows' => $remoteCount,
        'synced_rows' => $synced,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
}

function printUsage(): void
{
    echo <<<TEXT
Usage:
  php sync_wordfence_db.php --remote-host=HOST --remote-db=DB --remote-user=USER --remote-password=PASSWORD

Options:
  --config=PATH              Optional private config file.
  --local-table=VALUE        Optional local table. Default: wordfence_plugin_vulnerabilities.
  --remote-table=VALUE       Optional remote table. Default: wordfence_plugin_vulnerabilities.
  --remote-host=HOST         Remote MySQL host. Or WORDFENCE_REMOTE_DB_HOST.
  --remote-db=DB             Remote MySQL database. Or WORDFENCE_REMOTE_DB_NAME.
  --remote-user=USER         Remote MySQL user. Or WORDFENCE_REMOTE_DB_USER.
  --remote-password=PASSWORD Remote MySQL password. Or WORDFENCE_REMOTE_DB_PASSWORD.
  --batch-size=N             Optional rows per batch. Default: 1000.

TEXT;
}

function remoteConnectionSettings(array $options): array
{
    $settings = [
        'host' => (string) ($options['remote-host'] ?? getConfiguredValue('WORDFENCE_REMOTE_DB_HOST')),
        'database' => (string) ($options['remote-db'] ?? getConfiguredValue('WORDFENCE_REMOTE_DB_NAME')),
        'user' => (string) ($options['remote-user'] ?? getConfiguredValue('WORDFENCE_REMOTE_DB_USER')),
        'password' => (string) ($options['remote-password'] ?? getConfiguredValue('WORDFENCE_REMOTE_DB_PASSWORD')),
    ];

    foreach (['host', 'database', 'user'] as $key) {
        if ($settings[$key] === '') {
            throw new RuntimeException("Missing remote DB setting: {$key}");
        }
    }

    return $settings;
}

function createLocalWordfenceTable(DB $db, string $table): void
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

    ensureWordfenceVulnerabilityTableCompatible($db, $table);
}

function remoteRowCount(mysqli $remoteLink, string $remoteTable): int
{
    $result = mysqli_query($remoteLink, "SELECT COUNT(*) AS `count` FROM `{$remoteTable}`");
    if (!$result) {
        throw new RuntimeException('Remote count query failed: ' . mysqli_error($remoteLink));
    }

    $row = mysqli_fetch_assoc($result);
    return isset($row['count']) ? (int) $row['count'] : 0;
}

function syncRows(mysqli $remoteLink, DB $localDb, string $remoteTable, string $localTable, int $batchSize): int
{
    $offset = 0;
    $synced = 0;

    while (true) {
        $result = mysqli_query($remoteLink, remoteSelectSql($remoteTable, $batchSize, $offset));
        if (!$result) {
            throw new RuntimeException('Remote select query failed: ' . mysqli_error($remoteLink));
        }

        $rows = [];
        while ($row = mysqli_fetch_assoc($result)) {
            $rows[] = $row;
        }

        if ($rows === []) {
            break;
        }

        foreach ($rows as $row) {
            upsertLocalVulnerabilityRow($localDb, $localTable, $row);
            $synced++;
        }

        if (count($rows) < $batchSize) {
            break;
        }

        $offset += $batchSize;
    }

    return $synced;
}

function remoteSelectSql(string $remoteTable, int $limit, int $offset): string
{
    return "
        SELECT
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
        FROM `{$remoteTable}`
        ORDER BY `vulnerability_id`, `software_type`, `software_slug`
        LIMIT {$limit} OFFSET {$offset}
    ";
}

function upsertLocalVulnerabilityRow(DB $db, string $table, array $row): void
{
    $values = [
        'vulnerability_id' => sqlString($db, (string) $row['vulnerability_id']),
        'software_type' => sqlString($db, (string) $row['software_type']),
        'software_slug' => sqlString($db, (string) $row['software_slug']),
        'software_name' => sqlNullableString($db, $row['software_name'] ?? null),
        'plugin_filter' => sqlNullableString($db, $row['plugin_filter'] ?? null),
        'feed' => sqlString($db, (string) $row['feed']),
        'title' => sqlNullableString($db, $row['title'] ?? null),
        'cve' => sqlNullableString($db, $row['cve'] ?? null),
        'cvss_score' => sqlNullableNumber($row['cvss_score'] ?? null),
        'cvss_rating' => sqlNullableString($db, $row['cvss_rating'] ?? null),
        'patched' => sqlNullableInt($row['patched'] ?? null),
        'published_at' => sqlNullableString($db, $row['published_at'] ?? null),
        'updated_at' => sqlNullableString($db, $row['updated_at'] ?? null),
        'affected_versions_json' => sqlNullableString($db, $row['affected_versions_json'] ?? null),
        'patched_versions_json' => sqlNullableString($db, $row['patched_versions_json'] ?? null),
        'remediation' => sqlNullableString($db, $row['remediation'] ?? null),
        'references_json' => sqlNullableString($db, $row['references_json'] ?? null),
        'software_json' => sqlNullableString($db, $row['software_json'] ?? null),
        'raw_record_json' => sqlNullableString($db, $row['raw_record_json'] ?? null),
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

function sqlNullableString(DB $db, $value): string
{
    if ($value === null || $value === '') {
        return 'NULL';
    }

    return sqlString($db, (string) $value);
}

function sqlNullableNumber($value): string
{
    return is_numeric($value) ? (string) (float) $value : 'NULL';
}

function sqlNullableInt($value): string
{
    return $value === null || $value === '' ? 'NULL' : (string) (int) $value;
}
