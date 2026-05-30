from typing import Dict, Optional, Union, Iterator


STATUS_TEXT = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    422: "Unprocessable Content",
    429: "Too Many Requests",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


class BodyIterator:
    def __init__(self, iterable: Iterator[bytes]):
        self._iter = iterable

    def __iter__(self):
        return self._iter

    def __next__(self):
        return next(self._iter)


class Response:
    def __init__(self, status_code=200, body=b"", headers=None, body_iter=None):
        self.status_code = status_code
        self.body = body if not body_iter else None
        self.headers = headers or {}
        self.body_iter = body_iter


def stream_response(status_code: int, headers: dict, body_iter: BodyIterator) -> bytes:
    """Build initial response headers for streaming; caller handles body chunks."""
    return build_response(status_code, headers, body_iter=body_iter)


def build_response(
    status_code: int = 200,
    headers: Optional[Dict[str, str]] = None,
    body: Union[bytes, str] = b"",
    body_iter: Optional[BodyIterator] = None,
) -> bytes:
    final_headers = {}
    
    if body_iter is not None:
        final_headers["Transfer-Encoding"] = "chunked"
    else:
        response_body = body if isinstance(body, bytes) else body.encode("utf-8")
        final_headers["Content-Length"] = str(len(response_body))
    
    final_headers["Connection"] = "close"

    if headers:
        final_headers.update(headers)

    status_text = STATUS_TEXT.get(status_code, "Unknown")
    status_line = f"HTTP/1.1 {status_code} {status_text}"
    header_lines = "\r\n".join(f"{key}: {value}" for key, value in final_headers.items())
    head = f"{status_line}\r\n{header_lines}\r\n\r\n".encode("utf-8")
    
    if body_iter is not None:
        return head
    return head + (response_body if body_iter is None else b"")
