import os
import hashlib
import hmac
import base64
import datetime
from typing import Optional

from db import get_conn


ITERATIONS = 100_000


# --------------------------
# Password hashing utilities
# --------------------------

def hash_password(password: str, salt: Optional[bytes] = None):
    if salt is None:
        salt = os.urandom(16)

    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        ITERATIONS
    )

    hash_b64 = base64.b64encode(dk).decode()
    salt_b64 = base64.b64encode(salt).decode()
    return hash_b64, salt_b64


def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    salt = base64.b64decode(stored_salt)
    new_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(new_hash, stored_hash)


# --------------------------
# Access token authentication
# --------------------------

def authenticate(headers):
    auth = headers.get("authorization")
    if not auth or not auth.startswith("Bearer "):
        return None, "Missing Authorization header"

    token = auth.split(" ", 1)[1].strip()

    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT u.user_id, u.is_active, u.is_blocked, t.expires_at
            FROM access_tokens t
            JOIN users u ON u.user_id = t.user_id
            WHERE t.token = ?
            """,
            (token,)
        ).fetchone()

    if not row:
        return None, "Invalid access token"

    if row["is_active"] == 0:
        return None, "Account is deactivated"

    if row["is_blocked"] == 1:
        return None, "Account is blocked"

    if datetime.datetime.fromisoformat(row["expires_at"]) < datetime.datetime.utcnow():
        return None, "Access token expired"

    return row["user_id"], None
