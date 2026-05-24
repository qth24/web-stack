import json

from config import CACHE_MAX_SIZE, CACHE_TTL, PUBLIC_DIR, SERVER_NAME, PROXY_ROUTES_FILE
from http_response import build_response
from mime_types import get_mime_type
from proxy import (
    ProxyRoundRobin,
    forward_request,
    load_proxy_routes,
    match_proxy_route,
)
from security import build_security_headers, waf_inspect
from static_cache import StaticCache, static_cache


_proxy_routes = None
_proxy_round_robin = ProxyRoundRobin()


def _get_proxy_routes():
    global _proxy_routes
    if _proxy_routes is None:
        _proxy_routes = load_proxy_routes(PROXY_ROUTES_FILE)
    return _proxy_routes


def _security_headers_for(request: dict) -> dict[str, str]:
    scheme = request.get("scheme", "http")
    return build_security_headers(scheme)


def _add_security_headers(headers, scheme: str = "http"):
    merged = dict(headers)
    merged.update(build_security_headers(scheme))
    return merged


def create_text_response(status_code: int, content: str, scheme: str = "http") -> bytes:
    return build_response(
        status_code=status_code,
        headers=_add_security_headers({
            "Content-Type": "text/plain; charset=utf-8",
            "Server": SERVER_NAME,
        }, scheme=scheme),
        body=content,
    )


def create_json_response(status_code: int, payload: dict, scheme: str = "http") -> bytes:
    return build_response(
        status_code=status_code,
        headers=_add_security_headers({
            "Content-Type": "application/json; charset=utf-8",
            "Server": SERVER_NAME,
        }, scheme=scheme),
        body=json.dumps(payload, indent=2),
    )


def resolve_static_path(target: str):
    normalized_target = "/index.html" if target == "/" else target.split("?")[0]
    candidate = (PUBLIC_DIR / normalized_target.lstrip("/")).resolve()

    if PUBLIC_DIR.resolve() not in [candidate, *candidate.parents]:
        return None

    return candidate


def serve_static_file(target: str, request_headers: dict = None, scheme: str = "http") -> bytes:
    if request_headers is None:
        request_headers = {}

    file_path = resolve_static_path(target)

    if file_path is None or not file_path.exists() or not file_path.is_file():
        return create_text_response(404, "404 Not Found", scheme=scheme)

    content_bytes = file_path.read_bytes()
    etag = StaticCache.compute_etag(content_bytes)

    if_none_match = request_headers.get("if-none-match", "")
    if if_none_match and if_none_match == etag:
        return build_response(
            status_code=304,
            headers=_add_security_headers({
                "Server": SERVER_NAME,
                "ETag": etag,
            }, scheme=scheme),
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
        }, scheme=scheme),
        body=content_bytes,
    )


def handle_request(request: dict) -> bytes:
    scheme = request.get("scheme", "http")

    block_reason = waf_inspect(request)
    if block_reason is not None:
        return create_text_response(403, f"403 Forbidden\n{block_reason}", scheme=scheme)

    routes = _get_proxy_routes()
    route_index = match_proxy_route(request, routes)
    if route_index is not None:
        client_ip = request.get("client_ip", "127.0.0.1")
        return forward_request(request, routes, route_index, client_ip, _proxy_round_robin)

    if request["method"] != "GET":
        return create_text_response(405, "405 Method Not Allowed", scheme=scheme)

    if request["target"] == "/health":
        return create_json_response(
            200,
            {
                "status": "ok",
                "server": SERVER_NAME,
            },
            scheme=scheme,
        )

    return serve_static_file(request["target"], request.get("headers", {}), scheme=scheme)
