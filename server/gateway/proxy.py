import socket
from server.shared.response import Response
from server.gateway.balancer import BackendPool


def proxy_request(raw_request: bytes, pool: BackendPool, node_id: str) -> Response:
    max_retries = len([b for b in pool.status()["backends"]]) + 1
    for _ in range(max_retries):
        upstream = pool.next_backend()
        if upstream is None:
            return Response(502, body=b"Bad Gateway: no healthy backends")

        host, port_str = upstream.split(":")
        port = int(port_str)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((host, port))

            modified = _inject_header(raw_request, f"X-Upstream-Node: {node_id}")

            sock.sendall(modified)

            resp_data = _read_response(sock)
            sock.close()

            resp = _parse_upstream_response(resp_data)
            resp.headers["x-upstream-node"] = node_id
            return resp
        except Exception:
            pool.mark_down(upstream)
            continue

    return Response(502, body=b"Bad Gateway: all backends failed")


def _inject_header(raw: bytes, header_line: str) -> bytes:
    separator = b"\r\n\r\n"
    if separator in raw:
        headers, rest = raw.split(separator, 1)
        return headers + b"\r\n" + header_line.encode() + separator + rest
    return raw


def _read_response(sock: socket.socket) -> bytes:
    data = b""
    headers_complete = False
    content_length = None
    is_chunked = False
    header_end = 0
    no_length = False

    while True:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk

            if not headers_complete and b"\r\n\r\n" in data:
                headers_complete = True
                header_end = data.find(b"\r\n\r\n") + 4
                header_text = data[:header_end].decode("iso-8859-1").lower()

                for line in header_text.split("\r\n"):
                    if line.startswith("content-length:"):
                        content_length = int(line.split(":")[1].strip())
                    elif line.startswith("transfer-encoding:") and "chunked" in line:
                        is_chunked = True

                if content_length is None and not is_chunked:
                    no_length = True

            if headers_complete:
                if content_length is not None:
                    if len(data) - header_end >= content_length:
                        break
                elif is_chunked:
                    if data.endswith(b"0\r\n\r\n"):
                        break
                elif no_length:
                    pass
        except socket.timeout:
            break

    return data


def _extract_content_length(data: bytes) -> int | None:
    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return None
    headers = data[:header_end].decode("iso-8859-1").lower()
    for line in headers.split("\r\n"):
        if line.startswith("content-length:"):
            return int(line.split(":")[1].strip())
    return None


def _body_complete(data: bytes, content_length: int) -> bool:
    header_end = data.find(b"\r\n\r\n")
    return len(data) - header_end - 4 >= content_length


def _parse_upstream_response(data: bytes) -> Response:
    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return Response(502, body=b"Bad Gateway")
    header = data[:header_end].decode("iso-8859-1")
    body = data[header_end + 4:]
    lines = header.split("\r\n")
    status_line = lines[0]
    try:
        status_code = int(status_line.split(" ")[1])
    except (IndexError, ValueError):
        status_code = 502
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return Response(status_code, body=body, headers=headers)
