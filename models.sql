PRAGMA foreign_keys = ON;

-------------------------------------------------------------------
-- 1. users (root entity + credentials + basic profile)
-------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name     TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    is_blocked    INTEGER NOT NULL DEFAULT 0,  -- for admin block
    is_active     INTEGER NOT NULL DEFAULT 1,  -- soft delete flag
    created_at    TEXT NOT NULL
);

-------------------------------------------------------------------
-- 2. roles
-------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    role_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name   TEXT NOT NULL UNIQUE
);

-------------------------------------------------------------------
-- 3. permissions
-------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS permissions (
    permission_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    code           TEXT NOT NULL UNIQUE
);

-------------------------------------------------------------------
-- 4. user_roles (M:N users ↔ roles)
-------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_roles (
    user_id   INTEGER NOT NULL,
    role_id   INTEGER NOT NULL,
    PRIMARY KEY(user_id, role_id),
    FOREIGN KEY(user_id) REFERENCES users(user_id)
        ON DELETE CASCADE,
    FOREIGN KEY(role_id) REFERENCES roles(role_id)
        ON DELETE CASCADE
);

-------------------------------------------------------------------
-- 5. role_permissions (M:N roles ↔ permissions)
-------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id        INTEGER NOT NULL,
    permission_id  INTEGER NOT NULL,
    PRIMARY KEY(role_id, permission_id),
    FOREIGN KEY(role_id) REFERENCES roles(role_id)
        ON DELETE CASCADE,
    FOREIGN KEY(permission_id) REFERENCES permissions(permission_id)
        ON DELETE CASCADE
);

-------------------------------------------------------------------
-- 6. refresh_tokens (per user)
-------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    token       TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    is_revoked  INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
);

-------------------------------------------------------------------
-- 7. access_tokens (opaque random tokens)
-------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_tokens (
    token       TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(user_id)
        ON DELETE CASCADE
);
