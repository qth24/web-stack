"""App backend HTTP server built on asyncio."""
import asyncio
import time
import traceback
from server.shared.response import build_response
from server.shared.security import apply_security_headers
from server.shared.access_log import log_access, log_event, request_line_from_raw
from server.app.router import route


class AppServer:
    def __init__(self, host: str, port: int, max_workers: int = 16, node_id: str = "app"):
        self._host = host
        self._port = port
        self._max_workers = max_workers
        self._node_id = node_id
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
        self._server = await asyncio.start_server(
            self._handle_client,
            self._host,
            self._port,
            backlog=128,
        )
        log_event("app", f"{self._node_id} listening on {self._host}:{self._port}")

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
        try:
            raw = await _recv_all(reader)
            if raw:
                method, target = request_line_from_raw(raw)
                resp = await route(raw)
                apply_security_headers(resp.headers)
                await _send_response(writer, resp)
                duration_ms = int((time.perf_counter() - started_at) * 1000)
                log_access(
                    "app",
                    peer,
                    method,
                    target,
                    resp.status_code,
                    duration_ms,
                    extra=f"node={self._node_id}",
                )
        except Exception:
            duration_ms = int((time.perf_counter() - started_at) * 1000)
            log_access(
                "app",
                peer,
                method,
                target,
                "ERROR",
                duration_ms,
                extra=f"node={self._node_id}",
            )
            traceback.print_exc()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


async def _recv_all(reader: asyncio.StreamReader) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        try:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=30)
            if not chunk:
                break
            data += chunk
        except TimeoutError:
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
            chunk = await asyncio.wait_for(reader.read(min(65536, content_length - body_received)), timeout=30)
            if not chunk:
                break
            data += chunk
            body_received += len(chunk)
        except TimeoutError:
            break

    return data


async def _send_response(writer: asyncio.StreamWriter, resp) -> None:
    response_head = build_response(
        status_code=resp.status_code,
        headers=resp.headers,
        body=resp.body if resp.body is not None else b"",
        body_iter=resp.body_iter,
    )
    writer.write(response_head)
    if resp.body_iter is not None:
        for chunk in resp.body_iter:
            if not chunk:
                continue
            writer.write(f"{len(chunk):X}\r\n".encode("ascii"))
            writer.write(chunk)
            writer.write(b"\r\n")
        writer.write(b"0\r\n\r\n")
    await writer.drain()
