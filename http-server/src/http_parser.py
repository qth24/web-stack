def parse_request(raw_request: bytes) -> dict:
    try:
        request_text = raw_request.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Request is not valid UTF-8") from exc

    header_part, _, body = request_text.partition("\r\n\r\n")
    header_lines = [line for line in header_part.split("\r\n") if line]

    if not header_lines:
        raise ValueError("Empty HTTP request")

    request_line_parts = header_lines[0].split(" ")
    if len(request_line_parts) != 3:
        raise ValueError("Invalid request line")

    method, target, http_version = request_line_parts
    headers = {}

    for line in header_lines[1:]:
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    return {
        "method": method,
        "target": target,
        "http_version": http_version,
        "headers": headers,
        "body": body,
    }
