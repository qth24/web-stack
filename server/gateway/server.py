import asyncio
import json
import ssl
import time
import traceback
from server.shared.response import Response, build_response
from server.shared.security import apply_security_headers
from server.gateway.proxy import proxy_request
from server.gateway.balancer import BackendPool
from server.gateway.metrics import Metrics
from server.shared.access_log import log_access, log_event, request_line_from_raw


class GatewayServer:
    def __init__(self, host: str, port: int, backends: list[str],
                 tls_cert: str = None, tls_key: str = None,
                 node_id: str = "gateway-1", max_workers: int = 16):
        self._host = host
        self._port = port
        self._node_id = node_id
        self._pool = BackendPool(backends)
        self._metrics = Metrics()
        self._tls_cert = tls_cert
        self._tls_key = tls_key
        self._loop: asyncio.AbstractEventLoop | None = None
        self._shutdown: asyncio.Event | None = None
        self._server: asyncio.AbstractServer | None = None

    @property
    def loop(self) -> asyncio.AbstractEventLoop | None:
        return self._loop

    async def start(self):
        if self._server is not None:
            return
        self._loop = asyncio.get_running_loop()
        self._shutdown = asyncio.Event()
        ssl_ctx = None
        if self._tls_cert and self._tls_key:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(self._tls_cert, self._tls_key)
        self._server = await asyncio.start_server(
            self._handle_client,
            self._host,
            self._port,
            backlog=128,
            ssl=ssl_ctx,
        )

        tls_state = "on" if ssl_ctx is not None else "off"
        backend_urls = ",".join(item["url"] for item in self._pool.status()["backends"])
        log_event(
            "gateway",
            f"{self._node_id} listening on {self._host}:{self._port} "
            f"tls={tls_state} backends={backend_urls}",
        )

    async def serve_forever(self):
        await self.start()
        if self._shutdown is None:
            return
        try:
            await self._shutdown.wait()
        finally:
            await self.stop()

    async def stop(self):
        if self._shutdown is not None:
            self._shutdown.set()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        started_at = time.perf_counter()
        peer = writer.get_extra_info("peername")
        method = "-"
        target = "-"
        self._metrics.inc_connections()
        try:
            raw = await self._recv_all(reader)
            if not raw:
                return
            self._metrics.inc_requests()
            method, target = request_line_from_raw(raw)

            target_line = raw.split(b"\r\n")[0]
            log_extra = f"node={self._node_id} route=internal"
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
                proxy_result = await proxy_request(raw, self._pool, self._node_id)
                resp = proxy_result.response
                log_extra = (
                    f"node={self._node_id} route=proxy upstream={proxy_result.upstream or '-'} "
                    f"attempts={proxy_result.attempts}"
                )
                if proxy_result.error:
                    log_extra = f"{log_extra} error={proxy_result.error}"

            scheme = "https" if self._tls_cert and self._tls_key else "http"
            apply_security_headers(resp.headers, scheme=scheme)
            writer.write(build_response(
                status_code=resp.status_code,
                headers=resp.headers,
                body=resp.body or b"",
            ))
            await writer.drain()
            duration_ms = int((time.perf_counter() - started_at) * 1000)
            log_access("gateway", peer, method, target, resp.status_code, duration_ms, extra=log_extra)
        except Exception:
            duration_ms = int((time.perf_counter() - started_at) * 1000)
            log_access(
                "gateway",
                peer,
                method,
                target,
                "ERROR",
                duration_ms,
                extra=f"node={self._node_id}",
            )
            traceback.print_exc()
        finally:
            self._metrics.dec_connections()
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def _recv_all(self, reader: asyncio.StreamReader) -> bytes:
        data = b""
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=30)
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
            except TimeoutError:
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
