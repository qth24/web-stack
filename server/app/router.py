"""App backend route dispatcher."""
import asyncio
import json
from urllib.parse import urlparse

from server.shared.parser import parse_request
from server.shared.response import Response
from server.shared.security import waf_inspect
from server.shared.static import serve_static
from server.app.auth import (
    extract_session_cookie,
    handle_login,
    handle_logout,
    handle_me,
    handle_register,
    render_auth_page,
)
from server.app.models import (
    add_history,
    add_message,
    apply_browser_profile_entry_changes,
    get_browser_profile_key,
    get_history,
    get_messages,
    list_browser_profile_entries,
    upsert_browser_profile_key,
)


async def route(raw_request: bytes) -> Response:
    req = parse_request(raw_request)
    reason = waf_inspect(req)
    if reason:
        return Response(403, body=json.dumps({"error": "forbidden", "reason": reason}).encode(),
                       headers={"content-type": "application/json"})

    target = req["target"]
    path = target.split("?")[0]
    method = req["method"]
    body = req.get("body_bytes", b"")
    query = urlparse(target).query

    if method == "GET" and path == "/health":
        return Response(200, body=b'{"status":"ok"}', headers={"content-type": "application/json"})

    if method == "GET" and path == "/":
        result = await _serve_static("/index.html")
        if result:
            return result

    if path.startswith("/static/"):
        result = await _serve_static(target)
        if result:
            return result
        return Response(404, body=json.dumps({"error": "not found"}).encode(),
                       headers={"content-type": "application/json"})

    if method == "GET":
        result = await _serve_static(target)
        if result:
            return result

    if method == "GET" and path == "/login":
        next_url = _query_value(query, "next", "/")
        return render_auth_page("login", next_url=next_url)
    if method == "GET" and path == "/register":
        next_url = _query_value(query, "next", "/")
        return render_auth_page("register", next_url=next_url)

    if method == "POST" and path == "/auth/register":
        return await handle_register(body, headers=req.get("headers", {}), target=target)
    if method == "POST" and path == "/auth/login":
        return await handle_login(body, headers=req.get("headers", {}), target=target)
    if method == "POST" and path == "/auth/logout":
        token = extract_session_cookie(req.get("headers", {}))
        return await handle_logout(token)
    if method == "GET" and path == "/auth/me":
        token = extract_session_cookie(req.get("headers", {}))
        return await handle_me(token)
    if method == "GET" and path == "/api/profile/bootstrap":
        return await _api_profile_bootstrap(req)
    if method == "POST" and path == "/api/profile/key":
        return await _api_profile_key(req)
    if method == "POST" and path == "/api/profile/entries":
        return await _api_profile_entries(req)

    if method == "GET" and path == "/api/history":
        return await _api_history_get(req)
    if method == "POST" and path == "/api/history":
        return await _api_history_post(req)
    if method == "GET" and path == "/api/messages":
        return await _api_messages_get(req)
    if method == "POST" and path == "/api/messages":
        return await _api_messages_post(req)

    return Response(404, body=json.dumps({"error": "not found"}).encode(),
                   headers={"content-type": "application/json"})


async def _api_history_get(req):
    user = await _get_auth_user(req)
    if user is None:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(),
                       headers={"content-type": "application/json"})
    entries = await get_history(user["id"])
    return Response(200, body=json.dumps(entries).encode(),
                   headers={"content-type": "application/json"})


async def _api_history_post(req):
    user = await _get_auth_user(req)
    if user is None:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(),
                       headers={"content-type": "application/json"})
    try:
        data = json.loads(req.get("body", "{}"))
        await add_history(user["id"], data.get("url", ""), data.get("title"))
        return Response(201, body=json.dumps({"status": "ok"}).encode(),
                       headers={"content-type": "application/json"})
    except json.JSONDecodeError:
        return Response(400, body=json.dumps({"error": "invalid JSON"}).encode(),
                       headers={"content-type": "application/json"})


async def _api_messages_get(req):
    user = await _get_auth_user(req)
    if user is None:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(),
                       headers={"content-type": "application/json"})
    entries = await get_messages(user["id"])
    return Response(200, body=json.dumps(entries).encode(),
                   headers={"content-type": "application/json"})


async def _api_messages_post(req):
    user = await _get_auth_user(req)
    if user is None:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(),
                       headers={"content-type": "application/json"})
    try:
        data = json.loads(req.get("body", "{}"))
        content = data.get("content", "")
        if content:
            await add_message(user["id"], content)
        return Response(201, body=json.dumps({"status": "ok"}).encode(),
                       headers={"content-type": "application/json"})
    except json.JSONDecodeError:
        return Response(400, body=json.dumps({"error": "invalid JSON"}).encode(),
                       headers={"content-type": "application/json"})


async def _api_profile_bootstrap(req):
    user = await _get_auth_user(req)
    if user is None:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(),
                       headers={"content-type": "application/json"})
    key_record = await get_browser_profile_key(user["id"])
    entries = await list_browser_profile_entries(user["id"])
    return Response(
        200,
        body=json.dumps({"user": user, "profile_key": key_record, "entries": entries}).encode(),
        headers={"content-type": "application/json"},
    )


async def _api_profile_key(req):
    user = await _get_auth_user(req)
    if user is None:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(),
                       headers={"content-type": "application/json"})
    try:
        data = json.loads(req.get("body", "{}"))
    except json.JSONDecodeError:
        return Response(400, body=json.dumps({"error": "invalid JSON"}).encode(),
                       headers={"content-type": "application/json"})
    wrapped_profile_key = str(data.get("wrapped_profile_key", "")).strip()
    wrap_salt = str(data.get("wrap_salt", "")).strip()
    wrap_kdf_version = str(data.get("wrap_kdf_version", "")).strip()
    profile_schema_version = str(data.get("profile_schema_version", "")).strip()
    if not all([wrapped_profile_key, wrap_salt, wrap_kdf_version, profile_schema_version]):
        return Response(400, body=json.dumps({"error": "missing profile key fields"}).encode(),
                       headers={"content-type": "application/json"})
    record = await upsert_browser_profile_key(
        user["id"],
        wrapped_profile_key,
        wrap_salt,
        wrap_kdf_version,
        profile_schema_version,
    )
    return Response(200, body=json.dumps(record).encode(), headers={"content-type": "application/json"})


async def _api_profile_entries(req):
    user = await _get_auth_user(req)
    if user is None:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(),
                       headers={"content-type": "application/json"})
    try:
        data = json.loads(req.get("body", "{}"))
    except json.JSONDecodeError:
        return Response(400, body=json.dumps({"error": "invalid JSON"}).encode(),
                       headers={"content-type": "application/json"})
    raw_entries = data.get("entries", [])
    if not isinstance(raw_entries, list):
        return Response(400, body=json.dumps({"error": "entries must be a list"}).encode(),
                       headers={"content-type": "application/json"})

    allowed_collections = {"settings", "bookmarks", "shortcuts", "history"}
    entries: list[dict] = []
    for item in raw_entries:
        if not isinstance(item, dict):
            return Response(400, body=json.dumps({"error": "invalid entry payload"}).encode(),
                           headers={"content-type": "application/json"})
        collection = str(item.get("collection", "")).strip()
        entry_id = str(item.get("entry_id", "")).strip()
        deleted = bool(item.get("deleted", False))
        ciphertext = item.get("ciphertext")
        if collection not in allowed_collections or not entry_id:
            return Response(400, body=json.dumps({"error": "invalid collection or entry id"}).encode(),
                           headers={"content-type": "application/json"})
        if not deleted and not str(ciphertext or "").strip():
            return Response(400, body=json.dumps({"error": "ciphertext required for upserts"}).encode(),
                           headers={"content-type": "application/json"})
        entries.append(
            {
                "collection": collection,
                "entry_id": entry_id,
                "ciphertext": str(ciphertext) if ciphertext is not None else None,
                "deleted": deleted,
            }
        )

    results = await apply_browser_profile_entry_changes(user["id"], entries)
    return Response(200, body=json.dumps({"entries": results}).encode(), headers={"content-type": "application/json"})


async def _get_auth_user(req):
    from server.app.models import validate_session_token
    token = extract_session_cookie(req.get("headers", {}))
    return await validate_session_token(token) if token else None


async def _serve_static(target: str) -> Response | None:
    return await asyncio.to_thread(serve_static, target)


def _query_value(query: str, key: str, default: str = "") -> str:
    from urllib.parse import parse_qs

    values = parse_qs(query, keep_blank_values=True)
    if key not in values or not values[key]:
        return default
    return str(values[key][-1])
