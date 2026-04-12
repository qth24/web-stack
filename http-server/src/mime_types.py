from pathlib import Path

MIME_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
}


def get_mime_type(file_path: Path) -> str:
    return MIME_TYPES.get(file_path.suffix.lower(), "application/octet-stream")
