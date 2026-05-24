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
