<?php

require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/imis_sso.php';

/**
 * Where IMIS sends the browser with a one-time ?sso_token=. Redeems it, finds or
 * creates the HGE account, signs the person in and opens the dashboard.
 */
function sso_refuse(string $message): never
{
    http_response_code(403);
    $portal = imis_portal_url();
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSC-HGE VERIFY — Sign in</title>
    <link rel="stylesheet" href="<?= e(asset_url('assets/css/app.css')) ?>">
</head>
<body class="min-h-screen bg-gray-50 text-gray-900 antialiased dark:bg-surface-950 dark:text-white">
    <main class="flex min-h-screen items-center justify-center px-4 py-10">
        <div class="auth-glass-card text-center">
            <h1 class="text-xl font-semibold tracking-wide">CSC-HGE VERIFY</h1>
            <div class="auth-error my-5" role="alert"><span><?= e($message) ?></span></div>
            <?php if ($portal !== ''): ?>
                <a class="auth-btn-primary inline-block" href="<?= e($portal) ?>">OPEN IMIS</a>
            <?php endif; ?>
        </div>
    </main>
</body>
</html>
    <?php
    exit;
}

if (current_user() !== null) {
    redirect(APP_BASE_URL . '/admin/dashboard.php');
}

if (!imis_sso_enabled()) {
    sso_refuse('SINGLE SIGN-ON IS NOT AVAILABLE. PLEASE CONTACT YOUR SYSTEM ADMINISTRATOR.');
}

$token = $_GET['sso_token'] ?? '';

if (!is_string($token) || $token === '') {
    sso_refuse('PLEASE OPEN HGE FROM IMIS.');
}

$imis = imis_redeem_token($token);

if ($imis === null) {
    sso_refuse('YOUR IMIS SIGN-IN COULD NOT BE USED. PLEASE OPEN HGE FROM IMIS AGAIN.');
}

$role = imis_hge_role($imis['role_code'] ?? null);

if ($role === null) {
    sso_refuse('YOU HAVE NOT BEEN GIVEN AN HGE ROLE IN IMIS. PLEASE CONTACT YOUR ADMINISTRATOR.');
}

$pdo = get_pdo();
$user = imis_sync_user($pdo, $imis, $role);

if ($user === null) {
    sso_refuse('YOUR HGE ACCOUNT IS DISABLED OR CLASHES WITH ANOTHER ACCOUNT. PLEASE CONTACT YOUR ADMINISTRATOR.');
}

$sid = is_string($imis['sid'] ?? null) && strlen($imis['sid']) === 64 ? $imis['sid'] : null;

login_user($user, $sid !== null ? imis_session_open($pdo, $sid, $user['id']) : null);

try {
    log_activity($pdo, $user['id'], 'login', 'method=imis');
} catch (\Throwable $e) {
    error_log('sso: activity log failed: ' . $e->getMessage());
}

redirect(APP_BASE_URL . '/admin/dashboard.php');
