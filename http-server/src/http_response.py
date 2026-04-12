from typing import Dict, Optional, Union


STATUS_TEXT = {
    200: "OK",
    400: "Bad Request",
    404: "Not Found",
    405: "Method Not Allowed",
    500: "Internal Server Error",
}


def build_response(
    status_code: int = 200,
    headers: Optional[Dict[str, str]] = None,
    body: Union[bytes, str] = b"",
) -> bytes:
    response_body = body if isinstance(body, bytes) else body.encode("utf-8")
    final_headers = {
        "Content-Length": str(len(response_body)),
        "Connection": "close",
    }

    if headers:
        final_headers.update(headers)

    status_text = STATUS_TEXT.get(status_code, "Unknown")
    status_line = f"HTTP/1.1 {status_code} {status_text}"
    header_lines = "\r\n".join(f"{key}: {value}" for key, value in final_headers.items())
    head = f"{status_line}\r\n{header_lines}\r\n\r\n".encode("utf-8")
    return head + response_body
