import json
from typing import Optional


HTTP_STATUS = {
    200: "OK",
    201: "Created",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
}


def http_response(code: int, body: Optional[dict]):
    reason = HTTP_STATUS.get(code, "Unknown")

    body_bytes = b""
    if body is not None:
        body_bytes = json.dumps(body).encode()

    headers = (
        f"HTTP/1.1 {code} {reason}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        "Connection: close\r\n\r\n"
    )

    return headers.encode() + body_bytes


def error_json(code: int, msg: str):
    return http_response(code, {"error": msg})


def parse_http_request(raw: bytes):
    try:
        text = raw.decode("utf-8", errors="ignore")

        if "\r\n\r\n" not in text:
            return None

        head, body = text.split("\r\n\r\n", 1)
        lines = head.split("\r\n")
        req = lines[0].split()

        if len(req) < 2:
            return None

        method, path = req[0], req[1]

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        parsed_body = {}
        if body.strip():
            try:
                parsed_body = json.loads(body)
            except:
                parsed_body = {}

        return {
            "method": method,
            "path": path,
            "headers": headers,
            "body": parsed_body
        }

    except:
        return None
