import socket
from handlers import (
    handle_register, handle_login, handle_logout, handle_me,
    handle_refresh, handle_profile_update, handle_password_change,
    handle_password_reset, handle_admin_users
)
from permissions import (
    handle_list_roles, handle_list_permissions, handle_assign_role
)
from util import http_response, parse_http_request


HOST = "0.0.0.0"
PORT = 8080


def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)

    print(f"Server running: http://{HOST}:{PORT}")

    while True:
        client, addr = s.accept()
        try:
            data = client.recv(65535)
            if not data:
                client.close()
                continue

            req = parse_http_request(data)
            if req is None:
                client.sendall(http_response(400, {"error": "Bad Request"}))
                client.close()
                continue

            method = req["method"]
            path   = req["path"]
            body   = req["body"]
            headers = req["headers"]

            # ---------------- ROUTES ----------------

            if method == "POST" and path == "/register":
                resp = handle_register(body, headers)

            elif method == "POST" and path == "/login":
                resp = handle_login(body, headers)

            elif method == "POST" and path == "/logout":
                resp = handle_logout(body, headers)

            elif method == "POST" and path == "/token/refresh":
                resp = handle_refresh(body, headers)

            elif method == "GET" and path == "/me":
                resp = handle_me(body, headers)

            elif method == "POST" and path == "/profile/update":
                resp = handle_profile_update(body, headers)

            elif method == "POST" and path == "/password/change":
                resp = handle_password_change(body, headers)

            elif method == "POST" and path == "/password/reset":
                resp = handle_password_reset(body, headers)

            elif method == "GET" and path == "/admin/users":
                resp = handle_admin_users(body, headers)

            # RBAC
            elif method == "GET" and path == "/roles":
                resp = handle_list_roles(body, headers)

            elif method == "GET" and path == "/permissions":
                resp = handle_list_permissions(body, headers)

            elif method == "POST" and path == "/roles/assign":
                resp = handle_assign_role(body, headers)

            # Homepage
            elif method == "GET" and path == "/":
                html = (
                    "<html><body><h1>Auth Server</h1>"
                    "<p>Raw socket server is running.</p></body></html>"
                )
                resp = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    f"Content-Length: {len(html.encode())}\r\n"
                    "Connection: close\r\n\r\n"
                    f"{html}"
                ).encode()

            else:
                resp = http_response(404, {"error": "Not found"})

            client.sendall(resp)
            client.close()

        except Exception as e:
            client.sendall(http_response(500, {"error": str(e)}))
            client.close()


if __name__ == "__main__":
    start_server()
