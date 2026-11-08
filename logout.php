<?php

require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/auth.php';

require_once __DIR__ . '/includes/imis_sso.php';

ensure_session();
if (isset($_SESSION['imis_sid_hash'])) {
    imis_session_end(get_pdo(), (string) $_SESSION['imis_sid_hash']);
}

logout_user();

$reason = $_GET['reason'] ?? '';
redirect(APP_BASE_URL . '/login.php' . ($reason === 'idle' ? '?timeout=1' : ''));
