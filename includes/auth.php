<?php

require_once __DIR__ . '/imis_sso.php';

function csrf_token(): string
{
    ensure_session();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_verify(?string $token): bool
{
    ensure_session();
    return is_string($token) && isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function user_has_role(?array $user, string $role): bool
{
    if ($user === null) {
        return false;
    }
    return $user['role'] === $role || $user['role'] === 'administrator';
}

function current_user(): ?array
{
    ensure_session();
    return $_SESSION['user'] ?? null;
}

function fetch_current_role_and_status(PDO $pdo, int $userId): ?array
{
    $stmt = $pdo->prepare('SELECT role, status FROM users WHERE id = :id');
    $stmt->execute(['id' => $userId]);
    $row = $stmt->fetch();
    return $row === false ? null : $row;
}

/**
 * Starts the session of a signed-in person. $imisSidHash is the hash of the sid IMIS gave
 * this sign-in (see imis_session_open()); require_login() ends the session once IMIS
 * reports the person signed out and that row is gone.
 */
function login_user(array $user, ?string $imisSidHash = null): void
{
    ensure_session();
    session_regenerate_id(true);
    unset($_SESSION['csrf_token']);
    $_SESSION['user'] = [
        'id' => $user['id'],
        'name' => $user['name'],
        'username' => $user['username'],
        'role' => $user['role'],
    ];
    $_SESSION['last_activity'] = time();

    if ($imisSidHash !== null) {
        $_SESSION['imis_sid_hash'] = $imisSidHash;
    }
}

function logout_user(): void
{
    ensure_session();
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }

    session_destroy();
}

function require_login(): void
{
    $user = current_user();
    if ($user === null) {
        redirect(APP_BASE_URL . '/login.php');
    }

    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_IDLE_TIMEOUT) {
        logout_user();
        redirect(APP_BASE_URL . '/login.php?timeout=1');
    }
    $_SESSION['last_activity'] = time();

    $fresh = fetch_current_role_and_status(get_pdo(), (int) $user['id']);

    if ($fresh === null || $fresh['status'] !== 'active') {
        logout_user();
        redirect(APP_BASE_URL . '/login.php');
    }

    // Signed out of IMIS (or the sign-in expired there): IMIS told sso_logout.php to drop the row.
    if (isset($_SESSION['imis_sid_hash']) && !imis_session_alive(get_pdo(), (string) $_SESSION['imis_sid_hash'])) {
        logout_user();
        redirect(APP_BASE_URL . '/login.php');
    }

    if ($fresh['role'] !== $user['role']) {
        $_SESSION['user']['role'] = $fresh['role'];
    }
}

function require_role(string $role): void
{
    require_login();
    $user = current_user();
    if (!user_has_role($user, $role)) {
        http_response_code(403);

        // api/*.php callers always expect JSON (every endpoint sets that
        // Content-Type and every frontend caller does response.json()) —
        // but this check runs before an endpoint gets a chance to set that
        // header itself, so without this branch a role failure on an API
        // request would send a plain-text body a JSON parser chokes on.
        if (str_contains($_SERVER['SCRIPT_NAME'] ?? '', '/api/')) {
            header('Content-Type: application/json');
            die(json_encode(['status' => 'error', 'message' => 'YOU DO NOT HAVE PERMISSION TO ACCESS THIS PAGE.']));
        }

        die('YOU DO NOT HAVE PERMISSION TO ACCESS THIS PAGE.');
    }
}

