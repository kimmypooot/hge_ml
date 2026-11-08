<?php

namespace Tests\Includes;

use PHPUnit\Framework\TestCase;
use Tests\TestDb;

require_once __DIR__ . '/../../includes/functions.php';
require_once __DIR__ . '/../../includes/auth.php';

class ImisSsoTest extends TestCase
{
    protected function setUp(): void
    {
        $_SESSION = [];
        putenv('IMIS_SSO_URL=https://imis.test/api/v1/sso/validate');
        putenv('IMIS_SSO_AUDIENCE=hge.test');
        TestDb::resetSchema();
    }

    protected function tearDown(): void
    {
        putenv('IMIS_SSO_URL');
        putenv('IMIS_SSO_AUDIENCE');
    }

    /** @return array<string, mixed> */
    private function imisUser(array $overrides = []): array
    {
        return array_merge([
            'id' => 42,
            'username' => 'jdelacruz',
            'fname' => 'Juan',
            'lname' => 'Dela Cruz',
            'email' => 'juan@example.test',
            'role_code' => 'administrator',
            'sid' => str_repeat('a', 64),
        ], $overrides);
    }

    public function testRedeemSendsTheTokenAndAudienceAndReturnsTheUser(): void
    {
        $seen = null;
        $user = imis_redeem_token('tok123', function (string $url, array $fields) use (&$seen): array {
            $seen = [$url, $fields];
            return ['success' => true, 'user' => $this->imisUser()];
        });

        $this->assertSame(['https://imis.test/api/v1/sso/validate', ['token' => 'tok123', 'audience' => 'hge.test']], $seen);
        $this->assertSame('jdelacruz', $user['username']);
    }

    public function testRedeemRefusesAFailedOrMalformedAnswer(): void
    {
        $this->assertNull(imis_redeem_token('tok', fn () => null));
        $this->assertNull(imis_redeem_token('tok', fn () => ['success' => false]));
        $this->assertNull(imis_redeem_token('tok', fn () => ['success' => true, 'user' => ['id' => 'x', 'username' => 'a']]));
        $this->assertNull(imis_redeem_token('', fn () => ['success' => true, 'user' => $this->imisUser()]));
    }

    public function testOnlyTheTwoHgeRolesAreAccepted(): void
    {
        $this->assertSame('administrator', imis_hge_role('administrator'));
        $this->assertSame('user', imis_hge_role('user'));
        $this->assertNull(imis_hge_role('guest'));
        $this->assertNull(imis_hge_role(null));
    }

    public function testFirstSignInCreatesAPasswordlessAccountFromImis(): void
    {
        $pdo = TestDb::pdo();
        $account = imis_sync_user($pdo, $this->imisUser(), 'administrator');

        $row = $pdo->query("SELECT * FROM users WHERE id = {$account['id']}")->fetch();
        $this->assertSame('Juan Dela Cruz', $row['name']);
        $this->assertSame('jdelacruz', $row['username']);
        $this->assertSame('administrator', $row['role']);
        $this->assertSame('active', $row['status']);
        $this->assertSame(42, (int) $row['imis_user_id']);
        $this->assertNull($row['password']);
    }

    public function testASecondSignInReusesTheAccountAndAppliesTheNewRole(): void
    {
        $pdo = TestDb::pdo();
        $first = imis_sync_user($pdo, $this->imisUser(), 'administrator');
        $second = imis_sync_user($pdo, $this->imisUser(['fname' => 'Johnny']), 'user');

        $this->assertSame($first['id'], $second['id']);
        $this->assertSame(1, (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
        $row = $pdo->query("SELECT name, role FROM users WHERE id = {$first['id']}")->fetch();
        $this->assertSame('Johnny Dela Cruz', $row['name']);
        $this->assertSame('user', $row['role']);
    }

    public function testAnAccountMadeBeforeImisIsLinkedByUsernameAndKeepsItsId(): void
    {
        $pdo = TestDb::pdo();
        $pdo->exec("INSERT INTO users (name, username, email, password, role) VALUES ('Old Juan', 'jdelacruz', 'old@hge.local', 'x', 'user')");
        $oldId = (int) $pdo->lastInsertId();

        $account = imis_sync_user($pdo, $this->imisUser(), 'administrator');

        $this->assertSame($oldId, $account['id']);
        $this->assertSame(42, (int) $pdo->query("SELECT imis_user_id FROM users WHERE id = {$oldId}")->fetchColumn());
    }

    public function testAnAccountMadeBeforeImisIsLinkedByEmailWhenTheUsernameDiffers(): void
    {
        $pdo = TestDb::pdo();
        $pdo->exec("INSERT INTO users (name, username, email, password, role) VALUES ('Old Juan', 'juan.old', 'juan@example.test', 'x', 'user')");
        $oldId = (int) $pdo->lastInsertId();

        $account = imis_sync_user($pdo, $this->imisUser(), 'user');

        $this->assertSame($oldId, $account['id']);
        $this->assertSame('jdelacruz', $pdo->query("SELECT username FROM users WHERE id = {$oldId}")->fetchColumn());
    }

    public function testADisabledAccountCannotSignIn(): void
    {
        $pdo = TestDb::pdo();
        $pdo->exec("INSERT INTO users (name, username, email, password, role, status) VALUES ('Off', 'jdelacruz', 'o@hge.local', 'x', 'user', 'disabled')");

        $this->assertNull(imis_sync_user($pdo, $this->imisUser(), 'user'));
    }

    public function testAUsernameHeldByAnotherImisPersonIsRefused(): void
    {
        $pdo = TestDb::pdo();
        imis_sync_user($pdo, $this->imisUser(['id' => 1]), 'user');

        $this->assertNull(imis_sync_user($pdo, $this->imisUser(['id' => 2, 'email' => 'other@example.test']), 'user'));
        $this->assertSame(1, (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
    }

    public function testAMissingOrSharedEmailGetsAPlaceholder(): void
    {
        $pdo = TestDb::pdo();
        imis_sync_user($pdo, $this->imisUser(['id' => 1, 'username' => 'a', 'email' => 'same@example.test']), 'user');
        $account = imis_sync_user($pdo, $this->imisUser(['id' => 2, 'username' => 'b', 'email' => 'same@example.test']), 'user');

        $this->assertSame('b@imis.local', $pdo->query("SELECT email FROM users WHERE id = {$account['id']}")->fetchColumn());
    }

    public function testSigningOutOfImisEndsTheHgeSession(): void
    {
        $pdo = TestDb::pdo();
        $account = imis_sync_user($pdo, $this->imisUser(), 'administrator');
        $sid = str_repeat('b', 64);

        $hash = imis_session_open($pdo, $sid, $account['id']);
        login_user($account, $hash);

        $this->assertNotSame($sid, $hash);
        $this->assertSame($hash, $_SESSION['imis_sid_hash']);
        $this->assertTrue(imis_session_alive($pdo, $hash));

        imis_session_end($pdo, imis_sid_hash($sid));

        $this->assertFalse(imis_session_alive($pdo, $hash));
    }
}
