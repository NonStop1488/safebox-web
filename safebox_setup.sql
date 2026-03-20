-- ============================================================
--  SafeBox Password Manager — Database Setup Script
--  MySQL 8.0+  |  InnoDB  |  utf8mb4
--  Zero-Knowledge Architecture
-- ============================================================
--  Як запустити:
--    mysql -u root -p < safebox_setup.sql
--  або відкрити у phpMyAdmin → SQL → вставити і виконати
-- ============================================================

-- 1. Створити базу даних
CREATE DATABASE IF NOT EXISTS safebox
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE safebox;

-- ============================================================
--  ТАБЛИЦЯ: users
--  Облікові записи користувачів.
--  Master password НІКОЛИ не зберігається у відкритому вигляді.
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
  id                        CHAR(36)         NOT NULL,
  email                     VARCHAR(255)     NOT NULL,

  -- Хеш master password (Argon2id або bcrypt) — тільки для входу,
  -- НЕ використовується для шифрування/розшифрування vault
  master_password_hash      VARCHAR(255)     NOT NULL,

  -- PBKDF2 параметри (зберігаються відкрито — це нормально)
  kdf_salt                  VARBINARY(32)    NOT NULL,   -- 256-bit випадкова сіль
  kdf_iterations            INT UNSIGNED     NOT NULL DEFAULT 600000,
  kdf_algorithm             ENUM('PBKDF2','Argon2id') NOT NULL DEFAULT 'PBKDF2',

  -- Vault key зашифрований master key-ом клієнта.
  -- Без master password розшифрувати неможливо.
  protected_symmetric_key   TEXT             NOT NULL,

  -- RSA ключі для майбутнього функціоналу sharing паролів
  public_key                TEXT,
  private_key_encrypted     TEXT,

  -- Двофакторна аутентифікація (TOTP)
  two_factor_secret         VARCHAR(64),
  two_factor_enabled        TINYINT(1)       NOT NULL DEFAULT 0,

  -- Стан акаунту
  email_verified            TINYINT(1)       NOT NULL DEFAULT 0,
  is_active                 TINYINT(1)       NOT NULL DEFAULT 1,

  -- Timestamps (UTC)
  created_at                DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at                DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP
                                             ON UPDATE CURRENT_TIMESTAMP,
  last_login_at             DATETIME,

  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email),
  INDEX idx_users_active (is_active)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Облікові записи користувачів SafeBox';

-- ============================================================
--  ТАБЛИЦЯ: folders
--  Папки/категорії для організації паролів.
--  Назва папки зашифрована (захист метаданих).
--  Підтримується вкладеність через parent_id (self-reference).
-- ============================================================
CREATE TABLE IF NOT EXISTS folders (
  id               CHAR(36)        NOT NULL,
  user_id          CHAR(36)        NOT NULL,
  parent_id        CHAR(36),                          -- NULL = коренева папка

  -- Зашифровані поля
  name_encrypted   TEXT            NOT NULL,          -- AES-256-GCM
  name_iv          VARBINARY(16)   NOT NULL,          -- 96-bit IV
  name_auth_tag    VARBINARY(16)   NOT NULL,          -- GCM authentication tag

  -- Відкриті поля (не чутливі)
  color            CHAR(7),                           -- HEX колір (#3FE08A)
  icon             VARCHAR(64),                       -- slug іконки
  sort_order       SMALLINT        NOT NULL DEFAULT 0,

  -- Soft delete — не видаляємо фізично (потрібно для sync)
  is_deleted       TINYINT(1)      NOT NULL DEFAULT 0,

  created_at       DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
                                   ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (id),
  FOREIGN KEY fk_folders_user   (user_id)   REFERENCES users(id)   ON DELETE CASCADE,
  FOREIGN KEY fk_folders_parent (parent_id) REFERENCES folders(id) ON DELETE SET NULL,
  INDEX idx_folders_user    (user_id),
  INDEX idx_folders_sync    (user_id, updated_at)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Папки для організації паролів';

-- ============================================================
--  ТАБЛИЦЯ: passwords
--  Головна таблиця — зашифровані записи паролів.
--
--  data_encrypted містить зашифрований JSON:
--  {
--    "username": "...",
--    "password": "...",
--    "url":      "...",
--    "totp_secret": "...",
--    "notes":    "...",
--    "custom_fields": [{"name":"PIN","value":"1234"}]
--  }
--
--  ЖОДЕН чутливий рядок не зберігається у відкритому вигляді.
-- ============================================================
CREATE TABLE IF NOT EXISTS passwords (
  id                   CHAR(36)        NOT NULL,
  user_id              CHAR(36)        NOT NULL,
  folder_id            CHAR(36),                      -- NULL = без папки

  -- Тип запису
  type                 ENUM('login','note','card','identity')
                                       NOT NULL DEFAULT 'login',

  -- Зашифрована назва запису (окремо від data для пошуку по назві без розшифрування всього)
  name_encrypted       TEXT            NOT NULL,
  name_iv              VARBINARY(16)   NOT NULL,
  name_auth_tag        VARBINARY(16)   NOT NULL,

  -- Зашифрований JSON з усіма чутливими даними
  data_encrypted       MEDIUMTEXT      NOT NULL,
  data_iv              VARBINARY(16)   NOT NULL,      -- УНІКАЛЬНИЙ при кожному збереженні!
  auth_tag             VARBINARY(16)   NOT NULL,      -- GCM authentication tag (цілісність)

  -- Версія ключа (для майбутньої ротації ключів)
  key_version          TINYINT UNSIGNED NOT NULL DEFAULT 1,

  -- UI-метадані (не чутливі)
  is_pinned            TINYINT(1)      NOT NULL DEFAULT 0,
  is_favorite          TINYINT(1)      NOT NULL DEFAULT 0,

  -- Soft delete
  is_deleted           TINYINT(1)      NOT NULL DEFAULT 0,

  -- Коли востаннє змінювався пароль (для аудиту слабких/старих паролів)
  password_changed_at  DATETIME,

  created_at           DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at           DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
                                       ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (id),
  FOREIGN KEY fk_passwords_user   (user_id)   REFERENCES users(id)   ON DELETE CASCADE,
  FOREIGN KEY fk_passwords_folder (folder_id) REFERENCES folders(id) ON DELETE SET NULL,
  INDEX idx_pw_user         (user_id),
  INDEX idx_pw_folder       (folder_id),
  INDEX idx_pw_sync         (user_id, updated_at),
  INDEX idx_pw_user_active  (user_id, is_deleted, updated_at),
  INDEX idx_pw_pinned       (user_id, is_pinned, is_deleted)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Зашифровані записи паролів (vault items)';

-- ============================================================
--  ТАБЛИЦЯ: devices
--  Зареєстровані пристрої користувача.
--  Потрібна для delta-синхронізації vault між пристроями.
-- ============================================================
CREATE TABLE IF NOT EXISTS devices (
  id                  CHAR(36)        NOT NULL,
  user_id             CHAR(36)        NOT NULL,

  device_name         VARCHAR(200)    NOT NULL,       -- "Windows PC", "iPhone 15"
  device_type         ENUM('web','windows','android','ios','cli')
                                      NOT NULL DEFAULT 'web',
  push_token          TEXT,                           -- для push-повідомлень

  -- Синхронізація: timestamp останнього успішного pull
  last_sync_at        DATETIME,

  -- Рівень довіри (untrusted = потрібна 2FA при вході)
  trust_level         ENUM('trusted','untrusted')
                                      NOT NULL DEFAULT 'untrusted',

  -- Bcrypt-хеш refresh-токену (сам токен зберігається тільки у клієнта)
  session_token_hash  VARCHAR(255),

  ip_address          VARCHAR(45),                   -- IPv4 або IPv6
  user_agent          TEXT,

  is_active           TINYINT(1)      NOT NULL DEFAULT 1,

  created_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
                                      ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (id),
  FOREIGN KEY fk_devices_user (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_devices_user        (user_id),
  INDEX idx_devices_user_active (user_id, is_active)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Зареєстровані пристрої для синхронізації';

-- ============================================================
--  ТАБЛИЦЯ: audit_log
--  Незмінний журнал усіх важливих дій.
--  Виявляє підозрілу активність та порушення.
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
  id           BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
  user_id      CHAR(36),                              -- NULL = системна дія
  device_id    CHAR(36),

  -- Тип події (константи — визначаються на рівні застосунку)
  action       VARCHAR(100)     NOT NULL,
  -- Приклади: LOGIN_SUCCESS, LOGIN_FAILED, PASSWORD_CREATED,
  --           PASSWORD_DELETED, PASSWORD_EXPORTED, MASTER_PW_CHANGED,
  --           DEVICE_ADDED, DEVICE_REVOKED, ACCOUNT_DELETED

  target_id    CHAR(36),                              -- ID пароля/папки/пристрою
  target_type  VARCHAR(50),                           -- 'password', 'folder', 'device'

  ip_address   VARCHAR(45),
  user_agent   TEXT,

  -- Додаткові деталі без чутливих даних
  -- Приклад: {"country": "UA", "fail_reason": "wrong_password"}
  metadata     JSON,

  created_at   DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (id),
  FOREIGN KEY fk_audit_user (user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_audit_user        (user_id, created_at),
  INDEX idx_audit_action      (action, created_at),
  INDEX idx_audit_user_action (user_id, action)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Журнал аудиту — незмінний лог подій';

-- ============================================================
--  ОКРЕМИЙ MySQL-КОРИСТУВАЧ (рекомендовано для продакшну)
--  Дає мінімальні права — тільки SELECT/INSERT/UPDATE/DELETE
--  Запустити від root: mysql -u root -p < safebox_setup.sql
-- ============================================================
-- CREATE USER IF NOT EXISTS 'safebox_app'@'localhost'
--   IDENTIFIED BY 'ЗАМІНІТЬ_НА_СВІЙ_СИЛЬНИЙ_ПАРОЛЬ';
--
-- GRANT SELECT, INSERT, UPDATE, DELETE ON safebox.* TO 'safebox_app'@'localhost';
-- FLUSH PRIVILEGES;
--
-- ↑ Розкоментуйте ці рядки і замініть пароль перед запуском у продакшні

-- ============================================================
--  ПЕРЕВІРКА — переглянути створені таблиці
-- ============================================================
SHOW TABLES;
