def parse_request(raw_request: bytes) -> dict:
    if not raw_request:
        raise ValueError("Empty HTTP request")

    if b"\r\n\r\n" in raw_request:
        header_bytes, body_bytes = raw_request.split(b"\r\n\r\n", 1)
    elif b"\n\n" in raw_request:
        header_bytes, body_bytes = raw_request.split(b"\n\n", 1)
    else:
        raise ValueError("Invalid HTTP request format")

    try:
        header_text = header_bytes.decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise ValueError("Request headers are not valid") from exc

    lines = [line for line in header_text.replace("\r\n", "\n").split("\n") if line]

    if not lines:
        raise ValueError("Empty HTTP request")

    request_line_parts = lines[0].split(" ")
    if len(request_line_parts) != 3:
        raise ValueError("Invalid request line")

    method, target, http_version = request_line_parts
    headers = {}

    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    try:
        body_text = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        body_text = body_bytes.decode("utf-8", errors="replace")

    return {
        "method": method,
        "target": target,
        "http_version": http_version,
        "headers": headers,
        "body": body_text,
        "body_bytes": body_bytes,
    }


def decode_chunked_body(raw_body: bytes) -> bytes:
    """Decode HTTP chunked transfer-encoded body."""
    result = bytearray()
    pos = 0
    while pos < len(raw_body):
        line_end = raw_body.find(b"\r\n", pos)
        if line_end == -1:
            break
        try:
            chunk_size = int(raw_body[pos:line_end], 16)
        except ValueError:
            break
        if chunk_size == 0:
            break
        pos = line_end + 2
        if pos + chunk_size + 2 > len(raw_body):
            break
        result.extend(raw_body[pos:pos + chunk_size])
        pos += chunk_size + 2
    return bytes(result)
