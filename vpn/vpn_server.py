"""Application-layer Mini VPN tunnel server.

The server accepts JSON-line tunnel frames from the custom browser, forwards the
embedded raw HTTP request to the requested upstream, then returns the raw HTTP
response in a JSON-line frame.
"""

import argparse
import ipaddress
import socket
import ssl
import sys
import threading
import time
from typing import Optional

try:
    from . import config
    from .protocol import (
        STATUS_ERROR,
        STATUS_FORBIDDEN,
        STATUS_UNAUTHORIZED,
        STATUS_UPSTREAM_ERROR,
        VPNProtocolError,
        build_error_response,
        build_success_response,
        decode_frame,
        encode_frame,
        parse_connect_request,
    )
except ImportError:
    import config
    from protocol import (
        STATUS_ERROR,
        STATUS_FORBIDDEN,
        STATUS_UNAUTHORIZED,
        STATUS_UPSTREAM_ERROR,
        VPNProtocolError,
        build_error_response,
        build_success_response,
        decode_frame,
        encode_frame,
        parse_connect_request,
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

    def handle_frame(self, frame_bytes: bytes) -> dict:
        request_id = None
        try:
            frame = decode_frame(frame_bytes)
            request = parse_connect_request(frame)
            request_id = request.request_id
            if self.token and request.token != self.token:
                return build_error_response(STATUS_UNAUTHORIZED, "Invalid VPN token", request_id)
            if not self.policy.is_allowed(request.target_host):
                return build_error_response(STATUS_FORBIDDEN, "Target blocked by VPN policy", request_id)
            upstream_response = self._forward(
                request.target_host,
                request.target_port,
                request.payload,
                request.use_tls,
                request.server_name or request.target_host,
            )
            return build_success_response(request_id, upstream_response)
        except VPNProtocolError as exc:
            return build_error_response(exc.status, str(exc), exc.request_id)
        except Exception as exc:
            return build_error_response(STATUS_ERROR, str(exc), request_id)

    def _forward(
        self,
        target_host: str,
        target_port: int,
        payload: bytes,
        use_tls: bool = False,
        server_name: str = "",
    ) -> bytes:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connect_timeout)
            sock.connect((target_host, target_port))
            if use_tls:
                context = ssl._create_unverified_context()
                sock = context.wrap_socket(sock, server_hostname=server_name or target_host)
            sock.settimeout(self.read_timeout)
            sock.sendall(payload)
            chunks = []
            while True:
                try:
                    chunk = sock.recv(self.buffer_size)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            if not chunks:
                raise RuntimeError("Upstream returned empty response")
            return b"".join(chunks)
        except (OSError, ssl.SSLError, RuntimeError) as exc:
            raise RuntimeError(f"{STATUS_UPSTREAM_ERROR}: {exc}") from exc
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


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
        self._stop_event = threading.Event()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        self.socket.settimeout(0.5)

    def serve_forever(self) -> None:
        log_event("INFO", f"VPN tunnel listening on {self.host}:{self.port}")
        while not self._stop_event.is_set():
            try:
                client_socket, client_addr = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                raise
            threading.Thread(
                target=self._handle_client,
                args=(client_socket, client_addr),
                daemon=True,
            ).start()

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self.socket.close()
        except OSError:
            pass

    def _handle_client(self, client_socket: socket.socket, client_addr) -> None:
        with client_socket:
            client_socket.settimeout(self.handler.read_timeout)
            try:
                frame = self._read_frame(client_socket)
                response = self.handler.handle_frame(frame)
                client_socket.sendall(encode_frame(response))
                status = response.get("status", "-")
                log_event("TUNNEL", f"{client_addr[0]} -> {status}", "32" if status == "OK" else "31")
            except Exception as exc:
                error = build_error_response(STATUS_ERROR, str(exc))
                try:
                    client_socket.sendall(encode_frame(error))
                except OSError:
                    pass

    def _read_frame(self, client_socket: socket.socket) -> bytes:
        data = bytearray()
        while not data.endswith(b"\n"):
            chunk = client_socket.recv(min(config.BUFFER_SIZE, self.max_frame_bytes - len(data) + 1))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > self.max_frame_bytes:
                raise ValueError(f"VPN frame too large (max {self.max_frame_bytes} bytes)")
        return bytes(data)


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


def main() -> None:
    args = parse_args()
    server = build_server(args)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log_event("INFO", "Shutdown requested by user")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
