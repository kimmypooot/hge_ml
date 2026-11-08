<?php

// Sign-in through the IMIS portal. Staff never type a password here: IMIS sends the
// browser to sso.php with a one-time ?sso_token=, which sso.php redeems server-to-server.
// Read on each call (not defined once) so a test can change them with putenv().

/** IMIS endpoint that redeems a token (POST /api/v1/sso/validate). Blank = sign-in is off. */
function imis_sso_url(): string
{
    return (string) (getenv('IMIS_SSO_URL') ?: '');
}

/** This system's own host[:port], exactly as registered in IMIS (SSO_HUB_HOSTS). */
function imis_sso_audience(): string
{
    return (string) (getenv('IMIS_SSO_AUDIENCE') ?: ($_SERVER['HTTP_HOST'] ?? ''));
}

/** Where people go to open HGE from IMIS (shown on the login page). */
function imis_portal_url(): string
{
    return (string) (getenv('IMIS_PORTAL_URL') ?: '');
}