"""JSON-line protocol for the application-layer Mini VPN tunnel."""

import base64
import json
from dataclasses import dataclass
from typing import Any, Optional


PROTOCOL_VERSION = "v1"
CONNECT_OPERATION = "connect"

STATUS_OK = "OK"
STATUS_BAD_REQUEST = "BAD_REQUEST"
STATUS_UNAUTHORIZED = "UNAUTHORIZED"
STATUS_FORBIDDEN = "FORBIDDEN"
STATUS_UPSTREAM_ERROR = "UPSTREAM_ERROR"
STATUS_ERROR = "ERROR"


class VPNProtocolError(Exception):
    def __init__(self, status: str, message: str, request_id: Optional[str] = None) -> None:
        super().__init__(message)
        self.status = status
        self.request_id = request_id


@dataclass(frozen=True)
class TunnelRequest:
    request_id: str
    target_host: str
    target_port: int
    payload: bytes
    token: str = ""
    use_tls: bool = False
    server_name: str = ""
    version: str = PROTOCOL_VERSION
    op: str = CONNECT_OPERATION


def encode_frame(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8") + b"\n"


def decode_frame(data: bytes) -> dict[str, Any]:
    try:
        text = data.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Frame must be UTF-8 JSON") from exc
    if not text:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Empty frame")
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Invalid JSON frame") from exc
    if not isinstance(payload, dict):
        raise VPNProtocolError(STATUS_BAD_REQUEST, "JSON frame root must be an object")
    return payload


def build_connect_request(
    request_id: str,
    token: str,
    target_host: str,
    target_port: int,
    payload: bytes,
    use_tls: bool = False,
    server_name: str = "",
) -> dict[str, Any]:
    return {
        "version": PROTOCOL_VERSION,
        "id": request_id,
        "op": CONNECT_OPERATION,
        "token": token,
        "target_host": target_host,
        "target_port": int(target_port),
        "use_tls": bool(use_tls),
        "server_name": server_name,
        "payload": base64.b64encode(payload).decode("ascii"),
    }


def parse_connect_request(frame: dict[str, Any]) -> TunnelRequest:
    request_id = _string_or_none(frame.get("id"))
    if frame.get("version") != PROTOCOL_VERSION:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Unsupported protocol version", request_id)
    if request_id is None:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Missing or invalid id")
    if frame.get("op") != CONNECT_OPERATION:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Unsupported or missing operation", request_id)
    target_host = _string_or_none(frame.get("target_host"))
    if target_host is None:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Missing or invalid target_host", request_id)
    try:
        target_port = int(frame.get("target_port"))
    except (TypeError, ValueError):
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Missing or invalid target_port", request_id)
    if not 1 <= target_port <= 65535:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "target_port out of range", request_id)
    raw_payload = _string_or_none(frame.get("payload"))
    if raw_payload is None:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Missing or invalid payload", request_id)
    try:
        payload = base64.b64decode(raw_payload.encode("ascii"), validate=True)
    except (ValueError, TypeError) as exc:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Payload must be base64", request_id) from exc
    if not payload:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Payload cannot be empty", request_id)
    return TunnelRequest(
        request_id=request_id,
        token=str(frame.get("token", "")),
        target_host=target_host,
        target_port=target_port,
        use_tls=bool(frame.get("use_tls", False)),
        server_name=str(frame.get("server_name", "")),
        payload=payload,
    )


def build_success_response(request_id: str, payload: bytes) -> dict[str, Any]:
    return {
        "version": PROTOCOL_VERSION,
        "id": request_id,
        "status": STATUS_OK,
        "via": "mini-vpn",
        "payload": base64.b64encode(payload).decode("ascii"),
    }


def build_error_response(status: str, message: str, request_id: Optional[str] = None) -> dict[str, Any]:
    return {
        "version": PROTOCOL_VERSION,
        "id": request_id,
        "status": status,
        "via": "mini-vpn",
        "payload": None,
        "message": message,
    }


def decode_response_payload(frame: dict[str, Any], expected_id: str) -> bytes:
    if frame.get("version") != PROTOCOL_VERSION:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Unsupported response version")
    if frame.get("id") != expected_id:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Response id mismatch")
    if frame.get("status") != STATUS_OK:
        raise VPNProtocolError(str(frame.get("status") or STATUS_ERROR), str(frame.get("message") or "VPN error"))
    payload = _string_or_none(frame.get("payload"))
    if payload is None:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Response missing payload")
    try:
        return base64.b64decode(payload.encode("ascii"), validate=True)
    except (ValueError, TypeError) as exc:
        raise VPNProtocolError(STATUS_BAD_REQUEST, "Response payload must be base64") from exc


def _string_or_none(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None
