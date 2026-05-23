import json

from config import CACHE_MAX_SIZE, CACHE_TTL, PUBLIC_DIR, SERVER_NAME
from http_response import build_response
from mime_types import get_mime_type
from static_cache import StaticCache, static_cache


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


def _add_security_headers(headers):
    merged = dict(headers)
    merged.update(SECURITY_HEADERS)
    return merged


def create_text_response(status_code: int, content: str) -> bytes:
    return build_response(
        status_code=status_code,
        headers=_add_security_headers({
            "Content-Type": "text/plain; charset=utf-8",
            "Server": SERVER_NAME,
        }),
        body=content,
    )


def create_json_response(status_code: int, payload: dict) -> bytes:
    return build_response(
        status_code=status_code,
        headers=_add_security_headers({
            "Content-Type": "application/json; charset=utf-8",
            "Server": SERVER_NAME,
        }),
        body=json.dumps(payload, indent=2),
    )


def resolve_static_path(target: str):
    normalized_target = "/index.html" if target == "/" else target.split("?")[0]
    candidate = (PUBLIC_DIR / normalized_target.lstrip("/")).resolve()

    if PUBLIC_DIR.resolve() not in [candidate, *candidate.parents]:
        return None

    return candidate


def serve_static_file(target: str, request_headers: dict = None) -> bytes:
    if request_headers is None:
        request_headers = {}

    file_path = resolve_static_path(target)

    if file_path is None or not file_path.exists() or not file_path.is_file():
        return create_text_response(404, "404 Not Found")

    content_bytes = file_path.read_bytes()
    etag = StaticCache.compute_etag(content_bytes)

    if_none_match = request_headers.get("if-none-match", "")
    if if_none_match and if_none_match == etag:
        return build_response(
            status_code=304,
            headers=_add_security_headers({
                "Server": SERVER_NAME,
                "ETag": etag,
            }),
            body=b"",
        )

    cached = static_cache.get(str(file_path))
    if cached is not None:
        content_bytes, cached_etag, _, content_type = cached
    else:
        content_type = get_mime_type(file_path)
        static_cache.put(str(file_path), content_bytes, etag, content_type)

    return build_response(
        status_code=200,
        headers=_add_security_headers({
            "Content-Type": content_type,
            "Server": SERVER_NAME,
            "Cache-Control": "public, max-age={}".format(CACHE_TTL),
            "ETag": etag,
        }),
        body=content_bytes,
    )


def handle_request(request: dict) -> bytes:
    if request["method"] != "GET":
        return create_text_response(405, "405 Method Not Allowed")

    if request["target"] == "/health":
        return create_json_response(
            200,
            {
                "status": "ok",
                "server": SERVER_NAME,
            },
        )

    return serve_static_file(request["target"], request.get("headers", {}))
