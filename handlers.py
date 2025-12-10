import uuid
import datetime

from db import get_conn
from util import http_response, error_json
from auth import hash_password, verify_password, authenticate
from permissions import require_permission


ACCESS_TOKEN_TTL_MINUTES = 15
REFRESH_TOKEN_TTL_DAYS = 30


# --------------------------
# Token creation helpers
# --------------------------

def create_access_token(user_id: int):
    token = uuid.uuid4().hex
    now = datetime.datetime.utcnow().isoformat()
    expires = (datetime.datetime.utcnow() +
               datetime.timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)).isoformat()

    with get_conn() as conn:
        conn.execute(
            "INSERT INTO access_tokens (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, now, expires)
        )
    return token


def create_refresh_token(user_id: int):
    token = uuid.uuid4().hex
    now = datetime.datetime.utcnow().isoformat()
    expires = (datetime.datetime.utcnow() +
               datetime.timedelta(days=REFRESH_TOKEN_TTL_DAYS)).isoformat()

    with get_conn() as conn:
        conn.execute(
            "INSERT INTO refresh_tokens (user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (user_id, token, now, expires)
        )
    return token


# --------------------------
# Register
# --------------------------

def handle_register(body, headers):
    if not all(k in body for k in ("email", "password", "full_name")):
        return error_json(400, "Missing fields")

    email = body["email"].strip().lower()
    full_name = body["full_name"].strip()
    pwd_hash, salt = hash_password(body["password"])
    now = datetime.datetime.utcnow().isoformat()

    with get_conn() as conn:
        try:
            cur = conn.execute(
                "INSERT INTO users (full_name, email, password_hash, salt, is_blocked, is_active, created_at) "
                "VALUES (?, ?, ?, ?, 0, 1, ?)",
                (full_name, email, pwd_hash, salt, now)
            )
        except Exception:
            return error_json(400, "Email already registered")

    return http_response(201, {"user_id": cur.lastrowid})


# --------------------------
# Login
# --------------------------

def handle_login(body, headers):
    if "email" not in body or "password" not in body:
        return error_json(400, "Missing fields")

    email = body["email"].strip().lower()
    pwd = body["password"]

    with get_conn() as conn:
        row = conn.execute(
            "SELECT user_id, password_hash, salt, is_active, is_blocked FROM users WHERE email = ?",
            (email,)
        ).fetchone()

    if not row or not verify_password(pwd, row["password_hash"], row["salt"]):
        return error_json(401, "Invalid credentials")

    if not row["is_active"]:
        return error_json(403, "Account deactivated")
    if row["is_blocked"]:
        return error_json(403, "Account blocked")

    user_id = row["user_id"]
    return http_response(200, {
        "access_token": create_access_token(user_id),
        "refresh_token": create_refresh_token(user_id),
        "user_id": user_id
    })


# --------------------------
# Refresh token
# --------------------------

def handle_refresh(body, headers):
    if "refresh_token" not in body:
        return error_json(400, "Missing refresh_token")

    token = body["refresh_token"]

    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT r.user_id, r.expires_at, u.is_active, u.is_blocked
            FROM refresh_tokens r
            JOIN users u ON u.user_id = r.user_id
            WHERE r.token = ?
            """,
            (token,)
        ).fetchone()

    if not row:
        return error_json(401, "Invalid refresh token")

    if not row["is_active"]:
        return error_json(403, "Account deactivated")
    if row["is_blocked"]:
        return error_json(403, "Account blocked")

    if datetime.datetime.fromisoformat(row["expires_at"]) < datetime.datetime.utcnow():
        return error_json(401, "Refresh token expired")

    user_id = row["user_id"]
    return http_response(200, {
        "access_token": create_access_token(user_id),
        "refresh_token": create_refresh_token(user_id)
    })


# --------------------------
# Logout
# --------------------------

def handle_logout(body, headers):
    user_id, err = authenticate(headers)
    if err:
        return error_json(401, err)

    with get_conn() as conn:
        conn.execute("DELETE FROM access_tokens WHERE user_id = ?", (user_id,))

    return http_response(200, {"status": "logged out"})


# --------------------------
# /me
# --------------------------

def handle_me(body, headers):
    user_id, err = authenticate(headers)
    if err:
        return error_json(401, err)

    with get_conn() as conn:
        row = conn.execute(
            "SELECT user_id, full_name, email, is_blocked, is_active, created_at FROM users WHERE user_id = ?",
            (user_id,)
        ).fetchone()

    return http_response(200, dict(row))


# --------------------------
# Update profile
# --------------------------

def handle_profile_update(body, headers):
    user_id, err = authenticate(headers)
    if err:
        return error_json(401, err)

    if "full_name" not in body:
        return error_json(400, "Nothing to update")

    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET full_name = ? WHERE user_id = ?",
            (body["full_name"].strip(), user_id)
        )

    return http_response(200, {"status": "updated"})


# --------------------------
# Change password
# --------------------------

def handle_password_change(body, headers):
    user_id, err = authenticate(headers)
    if err:
        return error_json(401, err)

    if not all(k in body for k in ("old_password", "new_password")):
        return error_json(400, "Missing fields")

    with get_conn() as conn:
        row = conn.execute(
            "SELECT password_hash, salt FROM users WHERE user_id = ?",
            (user_id,)
        ).fetchone()

    if not verify_password(body["old_password"], row["password_hash"], row["salt"]):
        return error_json(401, "Invalid old password")

    new_hash, new_salt = hash_password(body["new_password"])

    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE user_id = ?",
            (new_hash, new_salt, user_id)
        )

    return http_response(200, {"status": "password changed"})


# --------------------------
# Password reset
# --------------------------

def handle_password_reset(body, headers):
    if "email" not in body:
        return error_json(400, "Missing email")

    email = body["email"].strip().lower()
    temp_pwd = "Temp1234"

    with get_conn() as conn:
        row = conn.execute("SELECT user_id FROM users WHERE email = ?", (email,)).fetchone()

    if not row:
        return http_response(200, {"status": "reset issued"})

    new_hash, new_salt = hash_password(temp_pwd)

    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE user_id = ?",
            (new_hash, new_salt, row["user_id"])
        )

    return http_response(200, {"temp_password": temp_pwd})


# --------------------------
# Soft delete account
# --------------------------

def handle_delete_account(body, headers):
    user_id, err = authenticate(headers)
    if err:
        return error_json(401, err)

    with get_conn() as conn:
        conn.execute("UPDATE users SET is_active = 0 WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM access_tokens WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (user_id,))

    return http_response(200, {"status": "account deactivated"})


# --------------------------
# Admin: list all users
# --------------------------

def handle_admin_users(body, headers):
    user_id, resp = require_permission(headers, "admin.view_users")
    if resp:
        return resp

    with get_conn() as conn:
        users = conn.execute(
            "SELECT user_id, full_name, email, is_blocked, is_active, created_at FROM users ORDER BY user_id"
        ).fetchall()

    return http_response(200, {"users": [dict(u) for u in users]})
