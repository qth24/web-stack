"""App backend HTTP server with ThreadPoolExecutor."""
import socket
import signal
import threading
from concurrent.futures import ThreadPoolExecutor
from server.shared.response import build_response
from server.shared.security import apply_security_headers
from server.app.router import route


class AppServer:
    def __init__(self, host: str, port: int, max_workers: int = 16):
        self._host = host
        self._port = port
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._shutdown = threading.Event()
        self._sock: socket.socket | None = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._host, self._port))
        self._sock.listen(128)
        self._sock.settimeout(1.0)
        print(f"[app] listening on {self._host}:{self._port}")
        try:
            signal.signal(signal.SIGTERM, lambda s, f: self.stop())
            signal.signal(signal.SIGINT, lambda s, f: self.stop())
        except ValueError:
            pass
        while not self._shutdown.is_set():
            try:
                conn, addr = self._sock.accept()
                self._executor.submit(self._handle_client, conn, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._shutdown.set()
        self._executor.shutdown(wait=True)
        if self._sock:
            self._sock.close()

    def _handle_client(self, conn: socket.socket, addr: tuple):
        try:
            conn.settimeout(30)
            raw = _recv_all(conn)
            if raw:
                resp = route(raw)
                apply_security_headers(resp.headers)
                response_bytes = build_response(
                    status_code=resp.status_code,
                    headers=resp.headers,
                    body=resp.body if resp.body is not None else b"",
                    body_iter=resp.body_iter,
                )
                conn.sendall(response_bytes)
        except Exception:
            pass
        finally:
            conn.close()


def _recv_all(conn: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        try:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break

    if b"\r\n\r\n" not in data:
        return data

    header_end = data.find(b"\r\n\r\n")
    headers_text = data[:header_end].decode("iso-8859-1", errors="replace").lower()
    content_length = 0
    for line in headers_text.split("\r\n"):
        if line.startswith("content-length:"):
            try:
                content_length = int(line.split(":")[1].strip())
            except (ValueError, IndexError):
                pass

    body_start = header_end + 4
    body_received = len(data) - body_start
    while body_received < content_length:
        try:
            chunk = conn.recv(min(65536, content_length - body_received))
            if not chunk:
                break
            data += chunk
            body_received += len(chunk)
        except socket.timeout:
            break

    return data
