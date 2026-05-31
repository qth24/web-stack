"""Browser-side client for the Mini VPN application-layer tunnel."""

import asyncio
import uuid

from .http_client import HTTPClient, HTTPError, HTTPResponse

try:
    from .config import (
        VPN_HOST,
        VPN_PORT,
        VPN_TIMEOUT,
        VPN_TOKEN,
        VPN_BUFFER,
        VPN_MAX_FRAME_BYTES,
    )
except ImportError:
    from config import (
        VPN_HOST,
        VPN_PORT,
        VPN_TIMEOUT,
        VPN_TOKEN,
        VPN_BUFFER,
        VPN_MAX_FRAME_BYTES,
    )

try:
    from vpn.protocol import (
        VPNProtocolError,
        build_connect_request,
        build_stream_connect_request,
        decode_frame,
        decode_response_payload,
        ensure_ok_response,
        encode_frame,
    )
except ImportError:
    from protocol import (
        VPNProtocolError,
        build_connect_request,
        build_stream_connect_request,
        decode_frame,
        decode_response_payload,
        ensure_ok_response,
        encode_frame,
    )


class VPNError(HTTPError):
    """Raised when the browser cannot complete a request through Mini VPN."""


class VPNClient:
    def __init__(
        self,
        host: str = VPN_HOST,
        port: int = VPN_PORT,
        token: str = VPN_TOKEN,
        timeout: float = VPN_TIMEOUT,
        buffer_size: int = VPN_BUFFER,
        max_frame_bytes: int = VPN_MAX_FRAME_BYTES,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.token = token
        self.timeout = float(timeout)
        self.buffer_size = max(256, int(buffer_size))
        self.max_frame_bytes = max(1024, int(max_frame_bytes))
        self._http = HTTPClient(timeout=timeout)

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    async def get(
        self,
        ip: str,
        port: int,
        path: str,
        host: str,
        extra_headers: dict | None = None,
        use_tls: bool = False,
    ) -> HTTPResponse:
        request_text = self._http._build_request("GET", path, host, extra_headers=extra_headers)
        raw_response = await self.forward_http_request(
            target_host=ip,
            target_port=port,
            server_name=host,
            payload=request_text.encode("utf-8"),
            use_tls=use_tls,
        )
        return self._http._parse_response(raw_response)

    async def forward_http_request(
        self,
        target_host: str,
        target_port: int,
        server_name: str,
        payload: bytes,
        use_tls: bool = False,
    ) -> bytes:
        request_id = uuid.uuid4().hex
        frame = build_connect_request(
            request_id=request_id,
            token=self.token,
            target_host=target_host,
            target_port=target_port,
            payload=payload,
            use_tls=use_tls,
            server_name=server_name,
        )
        writer = None
        try:
            reader, writer = await self._open_connection()
            writer.write(encode_frame(frame))
            await writer.drain()
            response_frame = await self._read_frame(reader)
            response = decode_frame(response_frame)
            return decode_response_payload(response, request_id)
        except VPNProtocolError as exc:
            raise VPNError(f"VPN server error ({exc.status}): {exc}") from exc
        except TimeoutError as exc:
            raise VPNError(f"VPN server did not respond after {self.timeout}s") from exc
        except ConnectionRefusedError as exc:
            raise VPNError(f"Could not connect to VPN server at {self.endpoint}") from exc
        except OSError as exc:
            raise VPNError(f"VPN connection error: {exc}") from exc
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

    async def open_stream(
        self,
        target_host: str,
        target_port: int,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        request_id = uuid.uuid4().hex
        frame = build_stream_connect_request(
            request_id=request_id,
            token=self.token,
            target_host=target_host,
            target_port=target_port,
        )
        writer = None
        try:
            reader, writer = await self._open_connection()
            writer.write(encode_frame(frame))
            await writer.drain()
            response_frame = await self._read_frame(reader)
            response = decode_frame(response_frame)
            ensure_ok_response(response, request_id)
            return reader, writer
        except VPNProtocolError as exc:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
            raise VPNError(f"VPN server error ({exc.status}): {exc}") from exc
        except TimeoutError as exc:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
            raise VPNError(f"VPN server did not respond after {self.timeout}s") from exc
        except ConnectionRefusedError as exc:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
            raise VPNError(f"Could not connect to VPN server at {self.endpoint}") from exc
        except OSError as exc:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
            raise VPNError(f"VPN connection error: {exc}") from exc

    async def _open_connection(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port),
            timeout=self.timeout,
        )

    async def _read_frame(self, reader: asyncio.StreamReader) -> bytes:
        data = bytearray()
        while not data.endswith(b"\n"):
            chunk = await asyncio.wait_for(
                reader.read(min(self.buffer_size, self.max_frame_bytes - len(data) + 1)),
                timeout=self.timeout,
            )
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > self.max_frame_bytes:
                raise VPNError(f"VPN response frame too large (max {self.max_frame_bytes} bytes)")
        if not data:
            raise VPNError("VPN server returned empty response")
        return bytes(data)
