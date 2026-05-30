"""MIME type lookup by file extension."""
import os

MIME_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml; charset=utf-8",
    ".ico": "image/x-icon",
    ".txt": "text/plain; charset=utf-8",
}


def get_mime_type(file_path: str) -> str:
    """Return MIME type for a file path based on extension."""
    _, ext = os.path.splitext(file_path.lower())
    return MIME_TYPES.get(ext, "application/octet-stream")
