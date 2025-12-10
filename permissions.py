from db import get_conn
from util import http_response, error_json
from auth import authenticate


# ---------------------------------------
# Load all permissions for a given user
# ---------------------------------------

def load_permissions(user_id: int):
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT p.code
            FROM user_roles ur
            JOIN role_permissions rp ON ur.role_id = rp.role_id
            JOIN permissions p ON p.permission_id = rp.permission_id
            WHERE ur.user_id = ?
            """,
            (user_id,)
        ).fetchall()

    return [r["code"] for r in rows]


# ---------------------------------------
# Require permission for protected routes
# ---------------------------------------

def require_permission(headers, perm: str):
    user_id, err = authenticate(headers)
    if err:
        return None, error_json(401, err)

    if perm not in load_permissions(user_id):
        return None, error_json(403, f"Missing permission: {perm}")

    return user_id, None


# ---------------------------------------
# List roles
# ---------------------------------------

def list_roles():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT role_id, role_name FROM roles ORDER BY role_id"
        ).fetchall()

    return [dict(r) for r in rows]


# ---------------------------------------
# List permissions
# ---------------------------------------

def list_permissions():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT permission_id, code FROM permissions ORDER BY permission_id"
        ).fetchall()

    return [dict(r) for r in rows]


# ---------------------------------------
# Assign role to user
# ---------------------------------------

def assign_role(user_id: int, role_id: int):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
            (user_id, role_id)
        )


# ---------------------------------------
# Handlers
# ---------------------------------------

def handle_list_roles(body, headers):
    _, err = require_permission(headers, "admin.view_users")
    if err:
        return err
    return http_response(200, {"roles": list_roles()})


def handle_list_permissions(body, headers):
    _, err = require_permission(headers, "admin.view_users")
    if err:
        return err
    return http_response(200, {"permissions": list_permissions()})


def handle_assign_role(body, headers):
    _, err = require_permission(headers, "admin.manage_roles")
    if err:
        return err

    if "user_id" not in body or "role_id" not in body:
        return error_json(400, "Missing user_id or role_id")

    assign_role(body["user_id"], body["role_id"])
    return http_response(200, {"status": "role assigned"})
