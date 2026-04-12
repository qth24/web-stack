import json

from config import PUBLIC_DIR, SERVER_NAME
from http_response import build_response
from mime_types import get_mime_type


def create_text_response(status_code: int, content: str) -> bytes:
    return build_response(
        status_code=status_code,
        headers={
            "Content-Type": "text/plain; charset=utf-8",
            "Server": SERVER_NAME,
        },
        body=content,
    )


def create_json_response(status_code: int, payload: dict) -> bytes:
    return build_response(
        status_code=status_code,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Server": SERVER_NAME,
        },
        body=json.dumps(payload, indent=2),
    )


def resolve_static_path(target: str):
    normalized_target = "/index.html" if target == "/" else target.split("?")[0]
    candidate = (PUBLIC_DIR / normalized_target.lstrip("/")).resolve()

    if PUBLIC_DIR.resolve() not in [candidate, *candidate.parents]:
        return None

    return candidate


def serve_static_file(target: str) -> bytes:
    file_path = resolve_static_path(target)

    if file_path is None or not file_path.exists() or not file_path.is_file():
        return create_text_response(404, "404 Not Found")

    return build_response(
        status_code=200,
        headers={
            "Content-Type": get_mime_type(file_path),
            "Server": SERVER_NAME,
        },
        body=file_path.read_bytes(),
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

    return serve_static_file(request["target"])
