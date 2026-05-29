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
    $stagingTable = stagingTableName($localTable);
    $backupTable = backupTableName($localTable);

    validateTableName($localTable);
    validateTableName($remoteTable);
    validateTableName($stagingTable);
    validateTableName($backupTable);

    $remoteLink = null;
    $localDb = null;
    $lockName = null;

    try {
        $localDb = createDatabase();
        $lockName = acquireWordfenceVulnerabilityLock($localDb, $localTable);
        createWordfenceVulnerabilityTable($localDb, $localTable);
        prepareStagingTable($localDb, $stagingTable, $backupTable);

        $remote = remoteConnectionSettings($options);
        $remoteLink = mysqli_connect($remote['host'], $remote['user'], $remote['password'], $remote['database']);
        if (!$remoteLink) {
            throw new RuntimeException('Unable to connect to remote Wordfence database: ' . mysqli_connect_error());
        }
        if (!mysqli_set_charset($remoteLink, 'utf8mb4')) {
            throw new RuntimeException('Unable to set remote charset: ' . mysqli_error($remoteLink));
        }

        beginRemoteSnapshot($remoteLink);
        try {
            $remoteCount = remoteRowCount($remoteLink, $remoteTable);
            $synced = syncRows($remoteLink, $localDb, $remoteTable, $stagingTable, $batchSize);
            commitRemoteSnapshot($remoteLink);
        } catch (RuntimeException $exception) {
            rollbackRemoteSnapshot($remoteLink);
            throw $exception;
        }

        validateMirrorCounts($remoteCount, $synced, array_key_exists('allow-empty', $options));
        replaceLocalTableWithStaging($localDb, $localTable, $stagingTable, $backupTable);
        if ($lockName !== null) {
            releaseWordfenceVulnerabilityLock($localDb, $lockName);
            $lockName = null;
        }
        mysqli_close($remoteLink);
    } catch (RuntimeException $exception) {
        if ($localDb instanceof DB && $lockName !== null) {
            releaseWordfenceVulnerabilityLock($localDb, $lockName);
        }
        if ($remoteLink instanceof mysqli) {
            @mysqli_close($remoteLink);
        }
        fwrite(STDERR, $exception->getMessage() . "\n");
        exit(1);
    }

    echo json_encode([
        'remote_table' => $remoteTable,
        'local_table' => $localTable,
        'remote_rows' => $remoteCount,
        'synced_rows' => $synced,
        'mirrored' => true,
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
  --allow-empty              Permit replacing the local table with an empty remote mirror.

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

function stagingTableName(string $localTable): string
{
    return temporaryTableName($localTable, 'sync');
}

function backupTableName(string $localTable): string
{
    return temporaryTableName($localTable, 'old');
}

function temporaryTableName(string $baseTable, string $suffix): string
{
    $prefix = substr($baseTable, 0, 48);
    return $prefix . '_' . $suffix . '_' . substr(sha1($baseTable), 0, 8);
}

function validateMirrorCounts(int $remoteCount, int $synced, bool $allowEmpty): void
{
    if ($synced !== $remoteCount) {
        throw new RuntimeException("Synced {$synced} rows but remote count was {$remoteCount}; refusing to replace local table.");
    }

    if ($remoteCount === 0 && !$allowEmpty) {
        throw new RuntimeException('Remote Wordfence table is empty; refusing to replace local table without --allow-empty.');
    }
}

function prepareStagingTable(DB $db, string $stagingTable, string $backupTable): void
{
    $db->execute("DROP TABLE IF EXISTS `{$stagingTable}`");
    $db->execute("DROP TABLE IF EXISTS `{$backupTable}`");
    createWordfenceVulnerabilityTable($db, $stagingTable);
}

function replaceLocalTableWithStaging(DB $db, string $localTable, string $stagingTable, string $backupTable): void
{
    $db->execute("DROP TABLE IF EXISTS `{$backupTable}`");
    $db->execute("RENAME TABLE `{$localTable}` TO `{$backupTable}`, `{$stagingTable}` TO `{$localTable}`");
    $db->execute("DROP TABLE IF EXISTS `{$backupTable}`");
}

function beginRemoteSnapshot(mysqli $remoteLink): void
{
    if (!mysqli_query($remoteLink, 'START TRANSACTION READ ONLY')) {
        throw new RuntimeException('Unable to start remote snapshot transaction: ' . mysqli_error($remoteLink));
    }
}

function commitRemoteSnapshot(mysqli $remoteLink): void
{
    if (!mysqli_query($remoteLink, 'COMMIT')) {
        throw new RuntimeException('Unable to commit remote snapshot transaction: ' . mysqli_error($remoteLink));
    }
}

function rollbackRemoteSnapshot(mysqli $remoteLink): void
{
    @mysqli_query($remoteLink, 'ROLLBACK');
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
    $lastKey = null;
    $synced = 0;

    while (true) {
        $result = mysqli_query($remoteLink, remoteSelectSql($remoteLink, $remoteTable, $batchSize, $lastKey));
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
            wordfenceUpsertVulnerabilityRow($localDb, $localTable, $row);
            $synced++;
        }

        $lastRow = $rows[count($rows) - 1];
        $lastKey = [
            'vulnerability_id' => (string) $lastRow['vulnerability_id'],
            'software_type' => (string) $lastRow['software_type'],
            'software_slug' => (string) $lastRow['software_slug'],
        ];

        if (count($rows) < $batchSize) {
            break;
        }
    }

    return $synced;
}

function remoteSelectSql(mysqli $remoteLink, string $remoteTable, int $limit, ?array $lastKey): string
{
    $where = '';
    if ($lastKey !== null) {
        $vulnerabilityId = remoteSqlString($remoteLink, $lastKey['vulnerability_id']);
        $softwareType = remoteSqlString($remoteLink, $lastKey['software_type']);
        $softwareSlug = remoteSqlString($remoteLink, $lastKey['software_slug']);
        $where = "
            WHERE `vulnerability_id` > {$vulnerabilityId}
               OR (`vulnerability_id` = {$vulnerabilityId} AND `software_type` > {$softwareType})
               OR (`vulnerability_id` = {$vulnerabilityId} AND `software_type` = {$softwareType} AND `software_slug` > {$softwareSlug})
        ";
    }

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
        {$where}
        ORDER BY `vulnerability_id`, `software_type`, `software_slug`
        LIMIT {$limit}
    ";
}

function remoteSqlString(mysqli $remoteLink, string $value): string
{
    return "'" . mysqli_real_escape_string($remoteLink, $value) . "'";
}
