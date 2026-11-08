<?php

require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/recycle_bin_items.php';

function get_all_users(PDO $pdo): array
{
    $stmt = $pdo->query('SELECT id, name, username, email, role, status FROM users ORDER BY name ASC');
    return $stmt->fetchAll();
}

function create_user(PDO $pdo, array $data): array
{
    $name = trim((string) ($data['name'] ?? ''));
    $username = trim((string) ($data['username'] ?? ''));
    $email = trim((string) ($data['email'] ?? ''));

    if ($name === '' || $username === '' || $email === '') {
        return ['status' => 'error', 'message' => 'ALL FIELDS ARE REQUIRED.'];
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['status' => 'error', 'message' => 'PLEASE ENTER A VALID EMAIL ADDRESS.'];
    }

    try {
        $stmt = $pdo->prepare(
            'INSERT INTO users (name, username, email, password, role) VALUES (:name, :username, :email, NULL, "user")'
        );
        $stmt->execute([
            'name' => $name,
            'username' => $username,
            'email' => $email,
        ]);
    } catch (\PDOException $e) {
        if ($e->getCode() === '23000') {
            return ['status' => 'error', 'message' => 'A USER WITH THIS USERNAME OR EMAIL ALREADY EXISTS.'];
        }
        throw $e;
    }

    return ['status' => 'success', 'message' => 'USER CREATED SUCCESSFULLY.', 'id' => (int) $pdo->lastInsertId()];
}

function set_user_status(PDO $pdo, int $id, string $status): array
{
    if (!in_array($status, ['active', 'disabled'], true)) {
        return ['status' => 'error', 'message' => 'INVALID STATUS.'];
    }

    $stmt = $pdo->prepare('UPDATE users SET status = :status WHERE id = :id');
    $stmt->execute(['status' => $status, 'id' => $id]);

    return ['status' => 'success', 'message' => 'STATUS UPDATED.'];
}

function remove_user(PDO $pdo, int $id, int $requestingUserId): array
{
    if ($id === $requestingUserId) {
        return ['status' => 'error', 'message' => 'YOU CANNOT REMOVE YOUR OWN ACCOUNT.'];
    }

    $targetStmt = $pdo->prepare('SELECT name, role FROM users WHERE id = :id');
    $targetStmt->execute(['id' => $id]);
    $target = $targetStmt->fetch();
    if ($target === false) {
        return ['status' => 'error', 'message' => 'USER NOT FOUND.'];
    }

    if ($target['role'] === 'administrator') {
        return ['status' => 'error', 'message' => 'ADMINISTRATOR ACCOUNTS CANNOT BE REMOVED.'];
    }

    $uploadCountStmt = $pdo->prepare('SELECT COUNT(*) FROM latin_honor_uploads WHERE uploaded_by = :id');
    $uploadCountStmt->execute(['id' => $id]);
    $uploadCount = (int) $uploadCountStmt->fetchColumn();

    if ($uploadCount > 0) {
        return ['status' => 'error', 'message' => 'CANNOT REMOVE — THIS USER HAS UPLOADED ' . $uploadCount . ' FILE(S).'];
    }

    try {
        $pdo->beginTransaction();

        // Moved to the recycle bin, not destroyed (restore brings the account
        // back under the same id and re-attaches its activity-log entries).
        $rowStmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
        $rowStmt->execute(['id' => $id]);
        $row = $rowStmt->fetch();
        $logStmt = $pdo->prepare('SELECT id FROM activity_log WHERE user_id = :id');
        $logStmt->execute(['id' => $id]);
        archive_item(
            $pdo,
            'user',
            $id,
            (string) $target['name'],
            '@' . $row['username'] . ' · ' . $row['email'] . ' · ' . mb_strtoupper((string) $row['role']),
            ['user' => $row, 'activity_ids' => array_map('intval', $logStmt->fetchAll(PDO::FETCH_COLUMN))],
            $requestingUserId,
            'USER REMOVED'
        );

        // activity_log.user_id is nullable specifically to allow this: the
        // audit trail survives the account being removed, just with its
        // actor anonymized, rather than blocking removal on login history
        // that virtually every account will have.
        $pdo->prepare('UPDATE activity_log SET user_id = NULL WHERE user_id = :id')->execute(['id' => $id]);
        $pdo->prepare('DELETE FROM users WHERE id = :id')->execute(['id' => $id]);
        $pdo->commit();
    } catch (\Throwable $e) {
        try {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
        } catch (\Throwable $rollbackError) {
            error_log('remove_user rollback failed: ' . $rollbackError->getMessage());
        }
        error_log('remove_user failed: ' . $e->getMessage());
        return ['status' => 'error', 'message' => recycle_bin_missing_table_message($e) ?? 'THE USER COULD NOT BE REMOVED. PLEASE TRY AGAIN.'];
    }

    return ['status' => 'success', 'message' => 'USER REMOVED.', 'name' => $target['name']];
}
