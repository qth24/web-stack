"""Application-layer Mini VPN tunnel server.

The server accepts JSON-line tunnel frames from the custom browser, forwards the
embedded raw HTTP request to the requested upstream, then returns the raw HTTP
response in a JSON-line frame.
"""

import argparse
import asyncio
import ipaddress
import signal
import ssl
import sys
import time
from typing import Optional

try:
    from . import config
    from .protocol import (
        CONNECT_OPERATION,
        STATUS_ERROR,
        STATUS_FORBIDDEN,
        STATUS_UNAUTHORIZED,
        STATUS_UPSTREAM_ERROR,
        STREAM_CONNECT_OPERATION,
        VPNProtocolError,
        build_error_response,
        build_success_response,
        build_stream_ready_response,
        decode_frame,
        encode_frame,
        parse_connect_request,
        parse_stream_connect_request,
    )
except ImportError:
    import config
    from protocol import (
        CONNECT_OPERATION,
        STATUS_ERROR,
        STATUS_FORBIDDEN,
        STATUS_UNAUTHORIZED,
        STATUS_UPSTREAM_ERROR,
        STREAM_CONNECT_OPERATION,
        VPNProtocolError,
        build_error_response,
        build_success_response,
        build_stream_ready_response,
        decode_frame,
        encode_frame,
        parse_connect_request,
        parse_stream_connect_request,
    )


def _supports_color() -> bool:
    return sys.stdout.isatty()


def _colorize(text: str, code: Optional[str]) -> str:
    if not code or not _supports_color():
        return text
    return f"\033[{code}m{text}\033[0m"


def log_event(tag: str, message: str, color_code: Optional[str] = None) -> None:
    timestamp = time.strftime("%H:%M:%S")
    print(f"{timestamp} {_colorize(f'[{tag}]', color_code)} {message}")


class TunnelPolicy:
    def __init__(self, allow_private_targets: bool = True) -> None:
        self.allow_private_targets = allow_private_targets

    def is_allowed(self, host: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(host)
        except ValueError:
            return True
        if self.allow_private_targets:
            return True
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)


class VPNRequestHandler:
    def __init__(
        self,
        token: str,
        policy: Optional[TunnelPolicy] = None,
        connect_timeout: float = config.CONNECT_TIMEOUT,
        read_timeout: float = config.READ_TIMEOUT,
        buffer_size: int = config.BUFFER_SIZE,
    ) -> None:
        self.token = token
        self.policy = policy or TunnelPolicy(config.ALLOW_PRIVATE_TARGETS)
        self.connect_timeout = max(0.1, float(connect_timeout))
        self.read_timeout = max(0.1, float(read_timeout))
        self.buffer_size = max(256, int(buffer_size))

    async def handle_frame(self, frame_bytes: bytes) -> dict:
        request_id = None
        try:
            frame = decode_frame(frame_bytes)
            return await self.handle_connect_message(frame)
        except VPNProtocolError as exc:
            return build_error_response(exc.status, str(exc), exc.request_id)
        except Exception as exc:
            return build_error_response(STATUS_ERROR, str(exc), request_id)

    async def handle_connect_message(self, frame: dict) -> dict:
        request = parse_connect_request(frame)
        self._authorize(request.request_id, request.token, request.target_host)
        upstream_response = await self._forward_request(
            request.target_host,
            request.target_port,
            request.payload,
            request.use_tls,
            request.server_name or request.target_host,
        )
        return build_success_response(request.request_id, upstream_response)

    async def open_stream(
        self,
        frame: dict,
    ) -> tuple[str, str, int, asyncio.StreamReader, asyncio.StreamWriter]:
        request = parse_stream_connect_request(frame)
        self._authorize(request.request_id, request.token, request.target_host)
        reader, writer = await self._open_stream(request.target_host, request.target_port)
        return request.request_id, request.target_host, request.target_port, reader, writer

    def _authorize(self, request_id: str, token: str, target_host: str) -> None:
        if self.token and token != self.token:
            raise VPNProtocolError(STATUS_UNAUTHORIZED, "Invalid VPN token", request_id)
        if not self.policy.is_allowed(target_host):
            raise VPNProtocolError(STATUS_FORBIDDEN, "Target blocked by VPN policy", request_id)

    async def _forward_request(
        self,
        target_host: str,
        target_port: int,
        payload: bytes,
        use_tls: bool = False,
        server_name: str = "",
    ) -> bytes:
        writer = None
        try:
            ssl_context = ssl._create_unverified_context() if use_tls else None
            connect_coro = asyncio.open_connection(
                target_host,
                target_port,
                ssl=ssl_context,
                server_hostname=server_name or target_host if use_tls else None,
            )
            reader, writer = await asyncio.wait_for(connect_coro, timeout=self.connect_timeout)
            writer.write(payload)
            await writer.drain()
            chunks = []
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(self.buffer_size), timeout=self.read_timeout)
                except TimeoutError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            if not chunks:
                raise RuntimeError("Upstream returned empty response")
            return b"".join(chunks)
        except (OSError, ssl.SSLError, RuntimeError, TimeoutError) as exc:
            raise RuntimeError(f"{STATUS_UPSTREAM_ERROR}: {exc}") from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

    async def _open_stream(
        self,
        target_host: str,
        target_port: int,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port),
                timeout=self.connect_timeout,
            )
        except (OSError, TimeoutError) as exc:
            raise RuntimeError(f"{STATUS_UPSTREAM_ERROR}: {exc}") from exc


class MiniVPNServer:
    def __init__(
        self,
        host: str,
        port: int,
        handler: VPNRequestHandler,
        max_frame_bytes: int = config.MAX_FRAME_BYTES,
    ) -> None:
        self.host = host
        self.port = port
        self.handler = handler
        self.max_frame_bytes = max(1024, int(max_frame_bytes))
        self._loop: asyncio.AbstractEventLoop | None = None
        self._shutdown_event: asyncio.Event | None = None
        self._server: asyncio.AbstractServer | None = None

    @property
    def loop(self) -> asyncio.AbstractEventLoop | None:
        return self._loop

    @property
    def sockets(self):
        return self._server.sockets if self._server is not None else []

    async def start(self) -> None:
        if self._server is not None:
            return
        self._loop = asyncio.get_running_loop()
        self._shutdown_event = asyncio.Event()
        self._server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            backlog=128,
        )
        sockname = self._server.sockets[0].getsockname()
        self.port = sockname[1]
        log_event("INFO", f"VPN tunnel listening on {self.host}:{self.port}")

    async def serve_forever(self) -> None:
        await self.start()
        if self._shutdown_event is None:
            return
        try:
            await self._shutdown_event.wait()
        finally:
            await self.stop()

    async def stop(self) -> None:
        if self._shutdown_event is not None:
            self._shutdown_event.set()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client_addr = writer.get_extra_info("peername") or ("-", 0)
        try:
            try:
                frame_bytes = await self._read_frame(reader)
                frame = decode_frame(frame_bytes)
                if frame.get("op") == STREAM_CONNECT_OPERATION:
                    request_id, target_host, target_port, upstream_reader, upstream_writer = await self.handler.open_stream(frame)
                    try:
                        writer.write(encode_frame(build_stream_ready_response(request_id)))
                        await writer.drain()
                        log_event("TUNNEL", f"{client_addr[0]} -> STREAM {target_host}:{target_port}", "32")
                        await self._relay_stream(reader, writer, upstream_reader, upstream_writer)
                    finally:
                        upstream_writer.close()
                        try:
                            await upstream_writer.wait_closed()
                        except OSError:
                            pass
                elif frame.get("op") == CONNECT_OPERATION:
                    response = await self.handler.handle_connect_message(frame)
                    writer.write(encode_frame(response))
                    await writer.drain()
                    status = response.get("status", "-")
                    message = response.get("message", "")
                    suffix = f": {message}" if message else ""
                    log_event("TUNNEL", f"{client_addr[0]} -> {status}{suffix}", "32" if status == "OK" else "31")
                else:
                    raise VPNProtocolError(STATUS_ERROR, "Unsupported or missing operation", str(frame.get("id") or ""))
            except VPNProtocolError as exc:
                error = build_error_response(exc.status, str(exc), exc.request_id)
                try:
                    writer.write(encode_frame(error))
                    await writer.drain()
                except OSError:
                    pass
            except Exception as exc:
                error = build_error_response(STATUS_ERROR, str(exc))
                try:
                    writer.write(encode_frame(error))
                    await writer.drain()
                except OSError:
                    pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def _read_frame(self, reader: asyncio.StreamReader) -> bytes:
        data = bytearray()
        while not data.endswith(b"\n"):
            try:
                chunk = await asyncio.wait_for(
                    reader.read(min(config.BUFFER_SIZE, self.max_frame_bytes - len(data) + 1)),
                    timeout=self.handler.read_timeout,
                )
            except TimeoutError:
                break
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > self.max_frame_bytes:
                raise ValueError(f"VPN frame too large (max {self.max_frame_bytes} bytes)")
        return bytes(data)

    async def _relay_stream(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        tasks = {
            asyncio.create_task(self._pipe_stream(client_reader, upstream_writer)),
            asyncio.create_task(self._pipe_stream(upstream_reader, client_writer)),
        }
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.gather(*done, return_exceptions=True)

    async def _pipe_stream(
        self,
        source: asyncio.StreamReader,
        destination: asyncio.StreamWriter,
    ) -> None:
        while True:
            chunk = await source.read(self.handler.buffer_size)
            if not chunk:
                break
            destination.write(chunk)
            await destination.drain()
        try:
            destination.write_eof()
        except (AttributeError, OSError):
            pass


def build_server(args: argparse.Namespace) -> MiniVPNServer:
    handler = VPNRequestHandler(
        token=args.token,
        policy=TunnelPolicy(args.allow_private_targets),
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
        buffer_size=args.buffer_size,
    )
    return MiniVPNServer(
        host=args.host,
        port=args.port,
        handler=handler,
        max_frame_bytes=args.max_frame_bytes,
    )


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Mini VPN tunnel server")
    parser.add_argument("--host", default=config.BIND_HOST)
    parser.add_argument("--port", type=int, default=config.PORT)
    parser.add_argument("--token", default=config.TOKEN)
    parser.add_argument("--connect-timeout", type=float, default=config.CONNECT_TIMEOUT)
    parser.add_argument("--read-timeout", type=float, default=config.READ_TIMEOUT)
    parser.add_argument("--buffer-size", type=int, default=config.BUFFER_SIZE)
    parser.add_argument("--max-frame-bytes", type=int, default=config.MAX_FRAME_BYTES)
    parser.add_argument(
        "--no-private-targets",
        dest="allow_private_targets",
        action="store_false",
        default=config.ALLOW_PRIVATE_TARGETS,
    )
    return parser.parse_args(argv)


async def _main() -> None:
    args = parse_args()
    server = build_server(args)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(server.stop()))
        except (NotImplementedError, RuntimeError):
            pass
    await server.serve_forever()


def main() -> None:
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        log_event("INFO", "Shutdown requested by user")


if __name__ == "__main__":
    main()
