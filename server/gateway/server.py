import socket
import ssl
import signal
import threading
import json
from concurrent.futures import ThreadPoolExecutor
from server.shared.response import Response, build_response
from server.gateway.proxy import proxy_request
from server.gateway.balancer import BackendPool
from server.gateway.metrics import Metrics


class GatewayServer:
    def __init__(self, host: str, port: int, backends: list[str],
                 tls_cert: str = None, tls_key: str = None,
                 node_id: str = "gateway-1", max_workers: int = 16):
        self._host = host
        self._port = port
        self._node_id = node_id
        self._pool = BackendPool(backends)
        self._metrics = Metrics()
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._shutdown = threading.Event()
        self._tls_cert = tls_cert
        self._tls_key = tls_key
        self._sock: socket.socket | None = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._host, self._port))
        self._sock.listen(128)
        self._sock.settimeout(1.0)

        if self._tls_cert and self._tls_key:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self._tls_cert, self._tls_key)
            self._sock = ctx.wrap_socket(self._sock, server_side=True)

        print(f"[gateway] listening on {self._host}:{self._port}")
        try:
            signal.signal(signal.SIGTERM, lambda s, f: self.stop())
            signal.signal(signal.SIGINT, lambda s, f: self.stop())
        except ValueError:
            pass

        while not self._shutdown.is_set():
            try:
                conn, addr = self._sock.accept()
                self._metrics.inc_connections()
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
            raw = self._recv_all(conn)
            if not raw:
                return
            self._metrics.inc_requests()

            target_line = raw.split(b"\r\n")[0]
            if b" /health" in target_line:
                resp = Response(200, body=b'{"status":"ok","node":"' + self._node_id.encode() + b'"}',
                               headers={"content-type": "application/json"})
            elif b" /status" in target_line:
                status_data = {
                    "node": self._node_id,
                    "backend_pool": self._pool.status(),
                    **self._metrics.snapshot(),
                }
                resp = Response(200, body=json.dumps(status_data).encode(),
                               headers={"content-type": "application/json"})
            else:
                resp = proxy_request(raw, self._pool, self._node_id)

            conn.sendall(build_response(
                status_code=resp.status_code,
                headers=resp.headers,
                body=resp.body or b"",
            ))
        except Exception:
            pass
        finally:
            self._metrics.dec_connections()
            conn.close()

    def _recv_all(self, conn: socket.socket) -> bytes:
        data = b""
        while True:
            try:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    content_len = _extract_content_length(data)
                    if content_len is not None:
                        header_end = data.find(b"\r\n\r\n") + 4
                        if len(data) - header_end >= content_len:
                            break
                    else:
                        break
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
