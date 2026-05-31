"""Static file serving with path-traversal protection."""
import os
import hashlib
from server.shared.mime import get_mime_type
from server.shared.response import Response

PUBLIC_DIR: str | None = None
MAX_FILE_SIZE = 16 * 1024 * 1024


def set_public_dir(path: str):
    global PUBLIC_DIR
    PUBLIC_DIR = path


def serve_static(target: str) -> Response | None:
    """Serve a static file from PUBLIC_DIR. Returns Response or None."""
    global PUBLIC_DIR
    if PUBLIC_DIR is None:
        return None
    clean_target = target.lstrip("/")
    if clean_target.startswith("static/"):
        clean_target = clean_target[len("static/"):]
    clean = os.path.normpath(clean_target)
    filepath = os.path.join(PUBLIC_DIR, clean)
    real = os.path.realpath(filepath)
    real_root = os.path.realpath(PUBLIC_DIR)
    if os.path.commonpath([real, real_root]) != real_root:
        return Response(403, body=b"Forbidden")
    if not os.path.isfile(real):
        return None
    if os.path.getsize(real) > MAX_FILE_SIZE:
        return Response(403, body=b"File too large")
    mime = get_mime_type(real)
    with open(real, "rb") as f:
        content = f.read()
    etag = '"' + hashlib.sha256(content).hexdigest() + '"'
    return Response(200, body=content, headers={
        "Content-Type": mime,
        "ETag": etag,
        "Cache-Control": "public, max-age=3600",
    })
