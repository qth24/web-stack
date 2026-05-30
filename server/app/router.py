"""App backend route dispatcher."""
import json
from server.shared.parser import parse_request
from server.shared.response import Response
from server.shared.security import waf_inspect
from server.shared.static import serve_static
from server.app.auth import extract_session_cookie, handle_register, handle_login, handle_logout, handle_me
from server.app.models import add_history, get_history, add_message, get_messages


def route(raw_request: bytes) -> Response:
    req = parse_request(raw_request)
    reason = waf_inspect(req)
    if reason:
        return Response(403, body=json.dumps({"error": "forbidden", "reason": reason}).encode(),
                       headers={"content-type": "application/json"})

    target = req["target"]
    path = target.split("?")[0]
    method = req["method"]
    body = req.get("body_bytes", b"")

    if method == "GET" and path == "/health":
        return Response(200, body=b'{"status":"ok"}', headers={"content-type": "application/json"})

    if path.startswith("/static/"):
        result = serve_static(target)
        if result:
            return result
        return Response(404, body=json.dumps({"error": "not found"}).encode(),
                       headers={"content-type": "application/json"})

    if method == "GET" and path == "/login":
        return _serve_page("Login")
    if method == "GET" and path == "/register":
        return _serve_page("Register")

    if method == "POST" and path == "/auth/register":
        return handle_register(body)
    if method == "POST" and path == "/auth/login":
        return handle_login(body)
    if method == "POST" and path == "/auth/logout":
        token = extract_session_cookie(req.get("headers", {}))
        return handle_logout(token)
    if method == "GET" and path == "/auth/me":
        token = extract_session_cookie(req.get("headers", {}))
        return handle_me(token)

    if method == "GET" and path == "/api/history":
        return _api_history_get(req)
    if method == "POST" and path == "/api/history":
        return _api_history_post(req)
    if method == "GET" and path == "/api/messages":
        return _api_messages_get(req)
    if method == "POST" and path == "/api/messages":
        return _api_messages_post(req)

    return Response(404, body=json.dumps({"error": "not found"}).encode(),
                   headers={"content-type": "application/json"})


def _api_history_get(req):
    user = _get_auth_user(req)
    if user is None:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(),
                       headers={"content-type": "application/json"})
    entries = get_history(user["id"])
    return Response(200, body=json.dumps(entries).encode(),
                   headers={"content-type": "application/json"})


def _api_history_post(req):
    user = _get_auth_user(req)
    if user is None:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(),
                       headers={"content-type": "application/json"})
    try:
        data = json.loads(req.get("body", "{}"))
        add_history(user["id"], data.get("url", ""), data.get("title"))
        return Response(201, body=json.dumps({"status": "ok"}).encode(),
                       headers={"content-type": "application/json"})
    except json.JSONDecodeError:
        return Response(400, body=json.dumps({"error": "invalid JSON"}).encode(),
                       headers={"content-type": "application/json"})


def _api_messages_get(req):
    user = _get_auth_user(req)
    if user is None:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(),
                       headers={"content-type": "application/json"})
    entries = get_messages(user["id"])
    return Response(200, body=json.dumps(entries).encode(),
                   headers={"content-type": "application/json"})


def _api_messages_post(req):
    user = _get_auth_user(req)
    if user is None:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(),
                       headers={"content-type": "application/json"})
    try:
        data = json.loads(req.get("body", "{}"))
        content = data.get("content", "")
        if content:
            add_message(user["id"], content)
        return Response(201, body=json.dumps({"status": "ok"}).encode(),
                       headers={"content-type": "application/json"})
    except json.JSONDecodeError:
        return Response(400, body=json.dumps({"error": "invalid JSON"}).encode(),
                       headers={"content-type": "application/json"})


def _get_auth_user(req):
    from server.app.models import validate_session_token
    token = extract_session_cookie(req.get("headers", {}))
    return validate_session_token(token) if token else None


def _serve_page(title: str) -> Response:
    html = f"<!DOCTYPE html><html><head><title>{title}</title></head><body><h1>{title}</h1></body></html>"
    return Response(200, body=html.encode(), headers={"content-type": "text/html; charset=utf-8"})
