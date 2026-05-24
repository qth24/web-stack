"""UDP JSON v1 protocol helpers for the mini DNS module."""

import json
from dataclasses import dataclass
from typing import Any, Optional

try:
    from .dns_resolver import is_valid_domain, normalize_domain
except ImportError:
    from dns_resolver import is_valid_domain, normalize_domain


PROTOCOL_VERSION = "v1"
RESOLVE_OPERATION = "resolve"
QTYPE_A = "A"

STATUS_OK = "OK"
STATUS_BAD_REQUEST = "BAD_REQUEST"
STATUS_UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
STATUS_UNSUPPORTED_QTYPE = "UNSUPPORTED_QTYPE"
STATUS_NXDOMAIN = "NXDOMAIN"
STATUS_RATE_LIMITED = "RATE_LIMITED"
STATUS_ERROR = "ERROR"


@dataclass(frozen=True)
class DNSQuery:
    request_id: str
    domain: str
    qtype: str = QTYPE_A
    version: str = PROTOCOL_VERSION
    op: str = RESOLVE_OPERATION


class ProtocolError(Exception):
    """Protocol validation error with enough context to build a response."""

    def __init__(
        self,
        status: str,
        message: str,
        request_id: Optional[str] = None,
        domain: Optional[str] = None,
        qtype: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.request_id = request_id
        self.domain = domain
        self.qtype = qtype


def decode_request(payload: bytes) -> DNSQuery:
    """Decode a UDP JSON v1 request into a normalized DNSQuery."""
    if not payload:
        raise ProtocolError(STATUS_BAD_REQUEST, "Empty UDP packet")

    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProtocolError(
            STATUS_BAD_REQUEST,
            "Request must be UTF-8 encoded JSON",
        ) from exc

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ProtocolError(STATUS_BAD_REQUEST, "Invalid JSON payload") from exc

    if not isinstance(data, dict):
        raise ProtocolError(STATUS_BAD_REQUEST, "JSON root must be an object")

    request_id = _normalized_optional_string(data.get("id"))
    version = _normalized_optional_string(data.get("version"))
    op = _normalized_optional_string(data.get("op"))
    raw_domain = data.get("domain")
    normalized_domain = None
    if isinstance(raw_domain, str) and raw_domain.strip():
        normalized_domain = normalize_domain(raw_domain)
    qtype = _normalized_optional_string(data.get("qtype"))
    if qtype is not None:
        qtype = qtype.upper()

    if version != PROTOCOL_VERSION:
        raise ProtocolError(
            STATUS_UNSUPPORTED_VERSION,
            f"Unsupported protocol version: {version!r}",
            request_id=request_id,
            domain=normalized_domain,
            qtype=qtype,
        )

    if request_id is None:
        raise ProtocolError(
            STATUS_BAD_REQUEST,
            "Missing or invalid 'id' field",
            domain=normalized_domain,
            qtype=qtype,
        )

    if op != RESOLVE_OPERATION:
        raise ProtocolError(
            STATUS_BAD_REQUEST,
            "Unsupported or missing 'op' field",
            request_id=request_id,
            domain=normalized_domain,
            qtype=qtype,
        )

    if not isinstance(raw_domain, str):
        raise ProtocolError(
            STATUS_BAD_REQUEST,
            "Missing or invalid 'domain' field",
            request_id=request_id,
            qtype=qtype,
        )

    if normalized_domain is None:
        raise ProtocolError(
            STATUS_BAD_REQUEST,
            "Domain cannot be empty",
            request_id=request_id,
            qtype=qtype,
        )

    if not is_valid_domain(normalized_domain):
        raise ProtocolError(
            STATUS_BAD_REQUEST,
            "Invalid domain format",
            request_id=request_id,
            domain=normalized_domain,
            qtype=qtype,
        )

    if qtype is None:
        raise ProtocolError(
            STATUS_BAD_REQUEST,
            "Missing or invalid 'qtype' field",
            request_id=request_id,
            domain=normalized_domain,
        )

    if qtype != QTYPE_A:
        raise ProtocolError(
            STATUS_UNSUPPORTED_QTYPE,
            f"Unsupported qtype: {qtype!r}",
            request_id=request_id,
            domain=normalized_domain,
            qtype=qtype,
        )

    return DNSQuery(
        request_id=request_id,
        domain=normalized_domain,
        qtype=qtype,
    )


def build_success_response(query: DNSQuery, ip: str, ttl: int) -> dict[str, Any]:
    return {
        "version": PROTOCOL_VERSION,
        "id": query.request_id,
        "status": STATUS_OK,
        "domain": query.domain,
        "qtype": query.qtype,
        "ip": ip,
        "ttl": max(0, int(ttl)),
    }


def build_error_response(
    status: str,
    message: str,
    request_id: Optional[str] = None,
    domain: Optional[str] = None,
    qtype: Optional[str] = None,
    retry_after: Optional[float] = None,
) -> dict[str, Any]:
    response = {
        "version": PROTOCOL_VERSION,
        "id": request_id,
        "status": status,
        "domain": domain,
        "qtype": qtype,
        "ip": None,
        "ttl": None,
        "message": message,
    }
    if retry_after is not None:
        response["retry_after"] = max(0.0, round(float(retry_after), 2))
    return response


def encode_response(response: dict[str, Any]) -> bytes:
    return json.dumps(response, ensure_ascii=True).encode("utf-8")


def _normalized_optional_string(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None
