"""PBKDF2 password hashing and session-based authentication handlers."""
import hashlib
import secrets
import json
from server.app.models import (
    create_user, get_user_by_username, create_session,
    validate_session_token, delete_session
)
from server.shared.response import Response


def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 210000)
    return dk.hex(), salt


def extract_session_cookie(headers: dict) -> str | None:
    cookie = headers.get("cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("wc_session="):
            return part.split("=", 1)[1]
    return None


def handle_register(body: bytes) -> Response:
    try:
        data = json.loads(body)
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
        display_name = data.get("display_name", "").strip()
    except json.JSONDecodeError:
        return Response(400, body=b'{"error":"invalid JSON"}',
                       headers={"content-type": "application/json"})

    if not username or not password:
        return Response(400, body=json.dumps({"error": "username and password required"}).encode(),
                       headers={"content-type": "application/json"})
    if len(username) > 64 or len(password) < 4:
        return Response(422, body=json.dumps({"error": "invalid username or password length"}).encode(),
                       headers={"content-type": "application/json"})
    if get_user_by_username(username):
        return Response(409, body=json.dumps({"error": "username taken"}).encode(),
                       headers={"content-type": "application/json"})

    pw_hash, pw_salt = hash_password(password)
    user_id = create_user(username, pw_hash, pw_salt, display_name or username)
    token = create_session(user_id)

    body_data = json.dumps({"id": user_id, "username": username, "display_name": display_name or username})
    response = Response(201, body=body_data.encode(),
                       headers={"content-type": "application/json"})
    response.headers["set-cookie"] = f"wc_session={token}; HttpOnly; Secure; SameSite=Lax; Path=/"
    return response


def handle_login(body: bytes) -> Response:
    try:
        data = json.loads(body)
        username = data.get("username", "").strip()
        password = data.get("password", "").strip()
    except json.JSONDecodeError:
        return Response(400, body=b'{"error":"invalid JSON"}',
                       headers={"content-type": "application/json"})

    if not username or not password:
        return Response(400, body=json.dumps({"error": "username and password required"}).encode(),
                       headers={"content-type": "application/json"})

    user = get_user_by_username(username)
    if user is None:
        return Response(401, body=json.dumps({"error": "invalid credentials"}).encode(),
                       headers={"content-type": "application/json"})

    pw_hash, _ = hash_password(password, user["password_salt"])
    if pw_hash != user["password_hash"]:
        return Response(401, body=json.dumps({"error": "invalid credentials"}).encode(),
                       headers={"content-type": "application/json"})

    token = create_session(user["id"])
    body_data = json.dumps({"id": user["id"], "username": user["username"], "display_name": user["display_name"]})
    response = Response(200, body=body_data.encode(),
                       headers={"content-type": "application/json"})
    response.headers["set-cookie"] = f"wc_session={token}; HttpOnly; Secure; SameSite=Lax; Path=/"
    return response


def handle_logout(token: str | None) -> Response:
    if token:
        delete_session(token)
    response = Response(200, body=b'{"message":"logged out"}',
                       headers={"content-type": "application/json"})
    response.headers["set-cookie"] = "wc_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
    return response


def handle_me(token: str | None) -> Response:
    if not token:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(),
                       headers={"content-type": "application/json"})
    user = validate_session_token(token)
    if user is None:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(),
                       headers={"content-type": "application/json"})
    return Response(200, body=json.dumps(user).encode(),
                   headers={"content-type": "application/json"})
