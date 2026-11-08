<?php

require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/imis_sso.php';

/**
 * Called by IMIS (server-to-server, POST /sso/logout) when someone signs out of IMIS.
 * The 64-character `sid` is the only credential: it ends the matching HGE sign-in, so
 * that person's next request here asks them to sign in again. No cookies, no CSRF.
 */
header('Content-Type: application/json');
header('Cache-Control: no-store');

if (!imis_sso_enabled()) {
    http_response_code(404);
    echo json_encode(['success' => false]);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false]);
    exit;
}

$input = json_decode((string) file_get_contents('php://input'), true);
$sid = is_array($input) ? ($input['sid'] ?? null) : ($_POST['sid'] ?? null);

if (is_string($sid) && strlen($sid) === 64) {
    imis_session_end(get_pdo(), imis_sid_hash($sid));
}

echo json_encode(['success' => true]);
