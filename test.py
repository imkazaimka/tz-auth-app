import socket
import json
import time
import sqlite3

DB_PATH = "auth.db"
HOST = "127.0.0.1"
PORT = 8080


# ===============================
# HTTP client
# ===============================

def send_http(method, path, body=None, headers=None):
    headers = headers or {}
    body_bytes = b""

    if body is not None:
        body_bytes = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"

    headers["Content-Length"] = str(len(body_bytes))
    headers["Host"] = f"{HOST}:{PORT}"
    headers["Connection"] = "close"

    req = [f"{method} {path} HTTP/1.1"]
    for k, v in headers.items():
        req.append(f"{k}: {v}")
    req.append("")
    req.append("")

    raw = "\r\n".join(req).encode() + body_bytes

    s = socket.socket()
    s.connect((HOST, PORT))
    s.sendall(raw)
    resp = s.recv(65535)
    s.close()

    text = resp.decode("utf-8", errors="ignore")

    if "\r\n\r\n" not in text:
        return 0, {"error": "Invalid response", "raw": text}

    head, body = text.split("\r\n\r\n", 1)
    status = int(head.split(" ")[1])

    try:
        body_json = json.loads(body)
    except:
        body_json = {"raw": body}

    return status, body_json


def section(name):
    print(f"\n=== {name} ===")


# ===============================
# Test runner
# ===============================

print("\n========== STARTING TESTS ==========\n")

# Register
section("Register")
email = f"user{int(time.time())}@test.com"
password = "123456"
status, body = send_http("POST", "/register", {
    "email": email,
    "password": password,
    "full_name": "Test User"
})
print(status, body)
assert status == 201
user_id = body["user_id"]

status, _ = send_http("POST", "/register", {
    "email": email,
    "password": password,
    "full_name": "Duplicate"
})
print("Duplicate:", status)
assert status == 400

# Login
section("Login")
status, body = send_http("POST", "/login", {
    "email": email,
    "password": password
})
print(status, body)
assert status == 200
access = body["access_token"]
refresh = body["refresh_token"]

status, _ = send_http("POST", "/login", {
    "email": email,
    "password": "wrong"
})
print("Wrong password:", status)
assert status == 401

# /me
section("/me")
status, body = send_http("GET", "/me",
    headers={"Authorization": f"Bearer {access}"}
)
print(status, body)
assert status == 200

status, _ = send_http("GET", "/me")
print("No token:", status)
assert status == 401

# Profile update
section("Profile update")
status, body = send_http(
    "POST", "/profile/update",
    {"full_name": "Updated Name"},
    headers={"Authorization": f"Bearer {access}"}
)
print(status, body)
assert status == 200

status, _ = send_http(
    "POST", "/profile/update",
    {"unknown": 123},
    headers={"Authorization": f"Bearer {access}"}
)
print("Invalid update:", status)
assert status == 400

# Password change
section("Password change")
status, _ = send_http("POST", "/password/change",
    {"old_password": password, "new_password": "newpass"},
    headers={"Authorization": f"Bearer {access}"}
)
print(status)
assert status == 200

status, _ = send_http("POST", "/password/change",
    {"old_password": "wrong", "new_password": "newpass"},
    headers={"Authorization": f"Bearer {access}"}
)
print("Wrong old:", status)
assert status == 401

# Password reset
section("Password reset")
status, body = send_http("POST", "/password/reset", {"email": email})
print(status, body)
assert status == 200

# Roles before assignment
section("Roles BEFORE assignment")
status, _ = send_http("GET", "/roles",
    headers={"Authorization": f"Bearer {access}"}
)
print(status)
assert status == 403

# Assign role
section("Assign role")
status, body = send_http("POST", "/roles/assign",
    {"user_id": user_id, "role_id": 1},
    headers={"Authorization": f"Bearer {access}"}
)
print(status, body)
assert status in (200, 403)

# Roles after assignment
section("Roles AFTER assignment")
status, body = send_http("GET", "/roles",
    headers={"Authorization": f"Bearer {access}"}
)
print(status, body)

# Admin users
section("Admin users")
status, body = send_http(
    "GET", "/admin/users",
    headers={"Authorization": f"Bearer {access}"}
)
print(status, body)

# Refresh token
section("Refresh token")
status, body = send_http("POST", "/token/refresh",
    {"refresh_token": refresh}
)
print(status, body)
assert status == 200
new_access = body["access_token"]

# Logout
section("Logout")
status, body = send_http(
    "POST", "/logout",
    headers={"Authorization": f"Bearer {new_access}"}
)
print(status, body)
assert status == 200

# /me after logout
section("/me AFTER logout")
status, body = send_http(
    "GET", "/me",
    headers={"Authorization": f"Bearer {new_access}"}
)
print(status, body)
assert status == 401

print("\nВСЕ ТЕСТЫ ПРОЙДЕНЫ")
