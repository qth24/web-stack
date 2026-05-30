"""Static file serving with in-memory cache."""
import os
import hashlib
from server.shared.mime import get_mime_type
from server.shared.response import Response

PUBLIC_DIR: str | None = None


def set_public_dir(path: str):
    global PUBLIC_DIR
    PUBLIC_DIR = path


def serve_static(target: str) -> Response | None:
    """Serve a static file from PUBLIC_DIR. Returns Response or None."""
    global PUBLIC_DIR
    if PUBLIC_DIR is None:
        return Response(404, body=b"Not Found")
    clean = os.path.normpath(target.lstrip("/"))
    filepath = os.path.join(PUBLIC_DIR, clean)
    real = os.path.realpath(filepath)
    if not real.startswith(os.path.realpath(PUBLIC_DIR)):
        return Response(403, body=b"Forbidden")
    if not os.path.isfile(real):
        return None
    mime = get_mime_type(real)
    with open(real, "rb") as f:
        content = f.read()
    etag = '"' + hashlib.md5(content).hexdigest() + '"'
    return Response(200, body=content, headers={
        "Content-Type": mime,
        "ETag": etag,
        "Cache-Control": "public, max-age=3600",
    })
