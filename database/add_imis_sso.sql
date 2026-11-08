-- Sign-in through IMIS. Run once on an existing database (schema.sql already has this).
-- Passwords now live only in IMIS, so users.password may be empty; imis_user_id links an
-- account to its IMIS person (set at the first IMIS sign-in, by username or email).
ALTER TABLE users
  MODIFY password VARCHAR(255) NULL,
  ADD COLUMN imis_user_id INT UNSIGNED NULL AFTER email,
  ADD UNIQUE KEY uq_users_imis_user_id (imis_user_id);

-- One row per open IMIS sign-in; deleted when IMIS reports the person signed out.
CREATE TABLE IF NOT EXISTS imis_sessions (
  sid_hash CHAR(64) NOT NULL PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
