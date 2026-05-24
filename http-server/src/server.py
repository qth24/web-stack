import socket
import ssl
import subprocess
import os
import threading
from pathlib import Path

from config import BUFFER_SIZE, HOST, PORT, HTTPS_PORT
from http_parser import parse_request
from http_response import build_response
from router import handle_request
from security import build_security_headers

HTTP_DIR = Path(__file__).resolve().parent.parent
CERT_FILE = HTTP_DIR / "src" / "cert.pem"
KEY_FILE = HTTP_DIR / "src" / "key.pem"


def generate_cert() -> None:
    if CERT_FILE.exists() and KEY_FILE.exists():
        return

    print("Generating self-signed certificate...")
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:4096",
                "-keyout", str(KEY_FILE),
                "-out", str(CERT_FILE),
                "-days", "365", "-nodes",
                "-subj", "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"
            ],
            check=True,
            capture_output=True
        )
        print(f"Certificate generated: {CERT_FILE}, {KEY_FILE}")
    except subprocess.CalledProcessError as e:
        print(f"Error generating certificate: {e.stderr.decode()}")
    except Exception as e:
        print(f"Unexpected error generating certificate: {e}")


def receive_http_request(client_socket: socket.socket) -> bytes:
    raw_data = b""

    while b"\r\n\r\n" not in raw_data:
        try:
            chunk = client_socket.recv(BUFFER_SIZE)
            if not chunk:
                break
            raw_data += chunk
        except (socket.timeout, ConnectionResetError):
            break

    if b"\r\n\r\n" not in raw_data:
        return raw_data

    header_bytes, existing_body = raw_data.split(b"\r\n\r\n", 1)

    try:
        header_text = header_bytes.decode("iso-8859-1")
    except UnicodeDecodeError:
        return raw_data

    content_length = 0
    for line in header_text.split("\r\n"):
        if line.lower().startswith("content-length:"):
            try:
                content_length = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
            break

    if content_length > 0:
        body_bytes = existing_body
        while len(body_bytes) < content_length:
            needed = content_length - len(body_bytes)
            try:
                chunk = client_socket.recv(min(BUFFER_SIZE, needed))
                if not chunk:
                    break
                body_bytes += chunk
            except (socket.timeout, ConnectionResetError):
                break
        return header_bytes + b"\r\n\r\n" + body_bytes

    return raw_data


def _has_chunked_transfer(request: dict) -> bool:
    headers = request.get("headers", {})
    te = headers.get("transfer-encoding", "")
    return "chunked" in te.lower()


def run_server_loop(server_socket: socket.socket, protocol_name: str) -> None:
    print(f"{protocol_name} loop started.")
    scheme = protocol_name.lower()
    while True:
        try:
            client_socket, client_address = server_socket.accept()
        except Exception as e:
            print(f"Error accepting {protocol_name} connection: {e}")
            continue

        def handle_client():
            with client_socket:
                try:
                    raw_request = receive_http_request(client_socket)
                    if not raw_request:
                        return
                    request = parse_request(raw_request)
                    request["scheme"] = scheme
                    request["client_ip"] = client_address[0]
                    print(f"[{protocol_name}] {client_address[0]} {request['method']} {request['target']}")

                    if _has_chunked_transfer(request):
                        resp_headers = build_security_headers(scheme)
                        resp_headers["Content-Type"] = "text/plain; charset=utf-8"
                        response = build_response(
                            status_code=501,
                            headers=resp_headers,
                            body="501 Not Implemented\nTransfer-Encoding: chunked is not supported",
                        )
                    else:
                        response = handle_request(request)
                except ValueError as error:
                    resp_headers = build_security_headers(scheme)
                    resp_headers["Content-Type"] = "text/plain; charset=utf-8"
                    response = build_response(
                        status_code=400,
                        headers=resp_headers,
                        body=f"400 Bad Request\n{error}",
                    )
                except Exception as error:
                    resp_headers = build_security_headers(scheme)
                    resp_headers["Content-Type"] = "text/plain; charset=utf-8"
                    response = build_response(
                        status_code=500,
                        headers=resp_headers,
                        body=f"500 Internal Server Error\n{error}",
                    )

                try:
                    client_socket.sendall(response)
                except Exception as e:
                    print(f"Error sending response to {client_address}: {e}")

        threading.Thread(target=handle_client, daemon=True).start()


def start_server() -> None:
    generate_cert()

    # HTTP Socket
    http_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    http_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    http_socket.bind((HOST, PORT))
    http_socket.listen()
    print(f"HTTP server is listening on {HOST}:{PORT}")

    # HTTPS Socket
    https_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    https_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    https_socket.bind((HOST, HTTPS_PORT))
    https_socket.listen()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if CERT_FILE.exists() and KEY_FILE.exists():
        context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
        wrapped_https_socket = context.wrap_socket(https_socket, server_side=True)
        print(f"HTTPS server is listening on {HOST}:{HTTPS_PORT}")
    else:
        print("HTTPS server failed to start: certificate files missing.")
        wrapped_https_socket = None

    # Start loops
    http_thread = threading.Thread(target=run_server_loop, args=(http_socket, "HTTP"), daemon=True)
    http_thread.start()

    if wrapped_https_socket:
        run_server_loop(wrapped_https_socket, "HTTPS")
    else:
        http_thread.join()


if __name__ == "__main__":
    start_server()
