<?php

require_once __DIR__ . '/../config/imis.php';

/**
 * IMIS sign-in. IMIS puts a one-time ?sso_token= on the launch URL; sso.php redeems it
 * here, server-to-server, for who the person is and the role they hold in HGE
 * (role_code: "administrator" or "user"). Passwords exist only in IMIS.
 */

function imis_sso_enabled(): bool
{
    return imis_sso_url() !== '' && imis_sso_audience() !== '';
}

/**
 * Redeems a token at IMIS. Returns IMIS's user array (id, username, fname, lname, email,
 * role_code, sid, ...) or null when the token is unknown, expired, already used,
 * meant for another system, or IMIS cannot be reached.
 *
 * @param (callable(string, array<string, string>): ?array)|null $http test seam: (url, form fields) -> decoded JSON body
 */
function imis_redeem_token(string $token, ?callable $http = null): ?array
{
    if (!imis_sso_enabled() || $token === '') {
        return null;
    }

    $fields = ['token' => $token, 'audience' => imis_sso_audience()];
    $body = $http !== null ? $http(imis_sso_url(), $fields) : imis_post_form(imis_sso_url(), $fields);

    if (!is_array($body) || ($body['success'] ?? false) !== true || !is_array($body['user'] ?? null)) {
        return null;
    }

    $user = $body['user'];

    if (!is_int($user['id'] ?? null) || !is_string($user['username'] ?? null) || $user['username'] === '') {
        return null;
    }

    return $user;
}

/** @param array<string, string> $fields */
function imis_post_form(string $url, array $fields): ?array
{
    $curl = curl_init($url);
    curl_setopt_array($curl, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($fields),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_HTTPHEADER => ['Accept: application/json'],
    ]);
    $response = curl_exec($curl);
    $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    curl_close($curl);

    if (!is_string($response) || $status !== 200) {
        return null;
    }

    $decoded = json_decode($response, true);

    return is_array($decoded) ? $decoded : null;
}

/** The HGE role for an IMIS role code, or null when the person has no HGE role. */
function imis_hge_role(mixed $roleCode): ?string
{
    return in_array($roleCode, ['administrator', 'user'], true) ? $roleCode : null;
}

/**
 * Finds or creates the HGE account of an IMIS person and rewrites its name, email and
 * role from IMIS, so a role changed in IMIS applies at the next sign-in. An account made
 * before IMIS (no imis_user_id yet) is linked by username, then email, which keeps its
 * uploads and activity history. Returns the account, or null when it cannot be used
 * (disabled here, or its username belongs to a different account).
 *
 * @param array<string, mixed> $imis
 * @return array{id: int, name: string, username: string, role: string}|null
 */
function imis_sync_user(PDO $pdo, array $imis, string $role): ?array
{
    $imisId = (int) $imis['id'];
    $username = mb_substr(trim((string) $imis['username']), 0, 50);
    $name = trim(trim((string) ($imis['fname'] ?? '')) . ' ' . trim((string) ($imis['lname'] ?? '')));
    $name = mb_substr($name !== '' ? $name : $username, 0, 150);
    $email = mb_substr(trim((string) ($imis['email'] ?? '')), 0, 150);

    $find = function (string $sql, array $params) use ($pdo): ?array {
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    };

    $existing = $find('SELECT id, status FROM users WHERE imis_user_id = :id', ['id' => $imisId])
        ?? $find('SELECT id, status FROM users WHERE username = :u AND imis_user_id IS NULL', ['u' => $username])
        ?? ($email !== '' ? $find('SELECT id, status FROM users WHERE email = :e AND imis_user_id IS NULL', ['e' => $email]) : null);

    if ($existing !== null && $existing['status'] !== 'active') {
        return null;
    }

    $ownId = $existing['id'] ?? 0;

    // The username is unique; refuse rather than take over another account.
    if ($find('SELECT id FROM users WHERE username = :u AND id <> :id', ['u' => $username, 'id' => $ownId]) !== null) {
        return null;
    }

    // The email is unique too; fall back to a placeholder when IMIS has none or another account holds it.
    $emailTaken = $email !== '' && $find('SELECT id FROM users WHERE email = :e AND id <> :id', ['e' => $email, 'id' => $ownId]) !== null;
    if ($email === '' || $emailTaken) {
        $email = $username . '@imis.local';
    }

    if ($existing === null) {
        $stmt = $pdo->prepare(
            "INSERT INTO users (name, username, email, password, role, status, imis_user_id)
             VALUES (:name, :username, :email, NULL, :role, 'active', :imis_id)"
        );
        $stmt->execute(['name' => $name, 'username' => $username, 'email' => $email, 'role' => $role, 'imis_id' => $imisId]);
        $id = (int) $pdo->lastInsertId();
    } else {
        $id = (int) $existing['id'];
        $stmt = $pdo->prepare(
            'UPDATE users SET name = :name, username = :username, email = :email, role = :role, imis_user_id = :imis_id WHERE id = :id'
        );
        $stmt->execute(['name' => $name, 'username' => $username, 'email' => $email, 'role' => $role, 'imis_id' => $imisId, 'id' => $id]);
    }

    return ['id' => $id, 'name' => $name, 'username' => $username, 'role' => $role];
}

// ---- Single sign-out. IMIS gives each sign-in a secret `sid` and calls sso/logout with it
// when the person signs out of IMIS. Only its hash is kept here.

function imis_sid_hash(string $sid): string
{
    return hash('sha256', $sid);
}

/** Records an open IMIS sign-in and returns the hash to keep in the PHP session. */
function imis_session_open(PDO $pdo, string $sid, int $userId): string
{
    $hash = imis_sid_hash($sid);
    $pdo->prepare('INSERT INTO imis_sessions (sid_hash, user_id, created_at) VALUES (:h, :u, :c) ON DUPLICATE KEY UPDATE user_id = VALUES(user_id)')
        ->execute(['h' => $hash, 'u' => $userId, 'c' => date('Y-m-d H:i:s')]);
    $pdo->exec('DELETE FROM imis_sessions WHERE created_at < (NOW() - INTERVAL 30 DAY)');

    return $hash;
}

function imis_session_alive(PDO $pdo, string $sidHash): bool
{
    $stmt = $pdo->prepare('SELECT 1 FROM imis_sessions WHERE sid_hash = :h');
    $stmt->execute(['h' => $sidHash]);

    return $stmt->fetchColumn() !== false;
}

function imis_session_end(PDO $pdo, string $sidHash): void
{
    $pdo->prepare('DELETE FROM imis_sessions WHERE sid_hash = :h')->execute(['h' => $sidHash]);
}
