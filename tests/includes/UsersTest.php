<?php

namespace Tests\Includes;

use PHPUnit\Framework\TestCase;
use Tests\TestDb;

require_once __DIR__ . '/../../includes/users.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/functions.php';

class UsersTest extends TestCase
{
    protected function setUp(): void
    {
        TestDb::resetSchema();
    }

    public function testGetAllUsersReturnsAllOrderedByName(): void
    {
        $pdo = TestDb::pdo();
        $pdo->exec("INSERT INTO users (name, username, email, password, role) VALUES ('Zed Cruz', 'zed', 'zed@a.com', 'x', 'user')");
        $pdo->exec("INSERT INTO users (name, username, email, password, role) VALUES ('Ana Reyes', 'ana', 'ana@a.com', 'x', 'administrator')");

        $users = get_all_users($pdo);

        $this->assertCount(2, $users);
        $this->assertSame('Ana Reyes', $users[0]['name']);
        $this->assertSame('Zed Cruz', $users[1]['name']);
        $this->assertArrayNotHasKey('password', $users[0]);
    }

    public function testCreateUserInsertsNewUser(): void
    {
        $pdo = TestDb::pdo();

        $result = create_user($pdo, [
            'name' => 'Ana Reyes',
            'username' => 'ana',
            'email' => 'ana@a.com',
            'role' => 'user',
        ]);

        $this->assertSame('success', $result['status']);
        $this->assertArrayHasKey('id', $result);

        $count = (int) $pdo->query("SELECT COUNT(*) FROM users WHERE username = 'ana'")->fetchColumn();
        $this->assertSame(1, $count);
    }

    public function testCreateUserAlwaysMakesAPlainUser(): void
    {
        // The role comes from IMIS at the first sign-in; a role passed in here is ignored.
        $pdo = TestDb::pdo();
        create_user($pdo, ['name' => 'Ana', 'username' => 'ana', 'email' => 'ana@a.com', 'role' => 'administrator']);

        $this->assertSame('user', $pdo->query("SELECT role FROM users WHERE username = 'ana'")->fetchColumn());
    }

    public function testCreateUserKeepsNoLocalPassword(): void
    {
        $pdo = TestDb::pdo();
        create_user($pdo, ['name' => 'Ana Reyes', 'username' => 'ana', 'email' => 'ana@a.com', 'role' => 'user']);

        $user = $pdo->query("SELECT role, password FROM users WHERE username = 'ana'")->fetch();
        $this->assertNotFalse($user);
        $this->assertSame('user', $user['role']);
        $this->assertNull($user['password']);
    }

    public function testCreateUserRejectsMissingFields(): void
    {
        $result = create_user(TestDb::pdo(), ['name' => '', 'username' => 'ana', 'email' => 'ana@a.com']);
        $this->assertSame('error', $result['status']);
    }

    public function testCreateUserRejectsInvalidEmail(): void
    {
        $result = create_user(TestDb::pdo(), ['name' => 'Ana', 'username' => 'ana', 'email' => 'not-an-email']);
        $this->assertSame('error', $result['status']);
    }

    public function testCreateUserRejectsDuplicateUsername(): void
    {
        $pdo = TestDb::pdo();
        create_user($pdo, ['name' => 'Ana', 'username' => 'ana', 'email' => 'ana1@a.com']);

        $result = create_user($pdo, ['name' => 'Another Ana', 'username' => 'ana', 'email' => 'ana2@a.com']);

        $this->assertSame('error', $result['status']);
        $count = (int) $pdo->query("SELECT COUNT(*) FROM users WHERE username = 'ana'")->fetchColumn();
        $this->assertSame(1, $count);
    }

    public function testCreateUserRejectsDuplicateEmail(): void
    {
        $pdo = TestDb::pdo();
        create_user($pdo, ['name' => 'Ana', 'username' => 'ana1', 'email' => 'ana@a.com']);

        $result = create_user($pdo, ['name' => 'Another', 'username' => 'ana2', 'email' => 'ana@a.com']);

        $this->assertSame('error', $result['status']);
    }

    public function testSetUserStatusTogglesStatus(): void
    {
        $pdo = TestDb::pdo();
        $created = create_user($pdo, ['name' => 'Ana', 'username' => 'ana', 'email' => 'ana@a.com']);

        $result = set_user_status($pdo, $created['id'], 'disabled');

        $this->assertSame('success', $result['status']);
        $this->assertSame('disabled', $pdo->query("SELECT status FROM users WHERE username = 'ana'")->fetchColumn());
    }

    public function testSetUserStatusRejectsInvalidStatus(): void
    {
        $result = set_user_status(TestDb::pdo(), 1, 'archived');
        $this->assertSame('error', $result['status']);
    }

    private function createAdmin(string $username): int
    {
        $pdo = TestDb::pdo();
        $stmt = $pdo->prepare(
            'INSERT INTO users (name, username, email, password, role) VALUES (:name, :username, :email, NULL, "administrator")'
        );
        $stmt->execute([
            'name' => 'Admin',
            'username' => $username,
            'email' => $username . '@a.com',
        ]);

        return (int) $pdo->lastInsertId();
    }

    public function testRemoveUserDeletesTheAccount(): void
    {
        $pdo = TestDb::pdo();
        $adminId = $this->createAdmin('admin');
        $created = create_user($pdo, ['name' => 'Ana', 'username' => 'ana', 'email' => 'ana@a.com']);

        $result = remove_user($pdo, $created['id'], $adminId);

        $this->assertSame('success', $result['status']);
        $count = (int) $pdo->query("SELECT COUNT(*) FROM users WHERE username = 'ana'")->fetchColumn();
        $this->assertSame(0, $count);
    }

    public function testRemoveUserRejectsRemovingYourself(): void
    {
        $pdo = TestDb::pdo();
        $adminId = $this->createAdmin('admin');

        $result = remove_user($pdo, $adminId, $adminId);

        $this->assertSame('error', $result['status']);
    }

    public function testRemoveUserRejectsAdministratorTargets(): void
    {
        $pdo = TestDb::pdo();
        $adminId = $this->createAdmin('admin');
        $otherAdminId = $this->createAdmin('other-admin');

        $result = remove_user($pdo, $otherAdminId, $adminId);

        $this->assertSame('error', $result['status']);
        $count = (int) $pdo->query('SELECT COUNT(*) FROM users WHERE role = "administrator"')->fetchColumn();
        $this->assertSame(2, $count);
    }

    public function testRemoveUserBlockedWhenTheUserHasUploadedFiles(): void
    {
        $pdo = TestDb::pdo();
        $adminId = $this->createAdmin('admin');
        $created = create_user($pdo, ['name' => 'Ana', 'username' => 'ana', 'email' => 'ana@a.com']);
        $pdo->exec("INSERT INTO schools (school_name) VALUES ('ABC University')");
        $pdo->prepare(
            'INSERT INTO latin_honor_uploads (school_id, school_year, original_filename, stored_filename, file_path, file_size, file_hash, uploaded_by, upload_number)
             VALUES (1, "2025", "a.pdf", "ABC_UNIVERSITY_2025_1.pdf", "/x/a.pdf", 10, SHA2("a", 256), :uploaded_by, 1)'
        )->execute(['uploaded_by' => $created['id']]);

        $result = remove_user($pdo, $created['id'], $adminId);

        $this->assertSame('error', $result['status']);
        $count = (int) $pdo->query("SELECT COUNT(*) FROM users WHERE username = 'ana'")->fetchColumn();
        $this->assertSame(1, $count);
    }

    public function testRemoveUserPreservesActivityLogHistoryWithAnonymizedActor(): void
    {
        $pdo = TestDb::pdo();
        $adminId = $this->createAdmin('admin');
        $created = create_user($pdo, ['name' => 'Ana', 'username' => 'ana', 'email' => 'ana@a.com']);
        log_activity($pdo, $created['id'], 'login', null);

        remove_user($pdo, $created['id'], $adminId);

        $row = $pdo->query('SELECT user_id, action FROM activity_log WHERE action = "login"')->fetch();
        $this->assertNotFalse($row);
        $this->assertNull($row['user_id']);
    }
}
