"""Resolver layer for mini DNS module."""

import json
import socket
import struct
from random import randint
from typing import Any, Callable, Dict, Optional, Tuple


DEFAULT_RECORDS: Dict[str, Dict[str, Any]] = {
    "example.local": {"ip": "127.0.0.1", "ttl": 5},
    "web.local": {"ip": "127.0.0.1", "ttl": 5},
    "api.local": {"ip": "127.0.0.1", "ttl": 8},
}

DEFAULT_UPSTREAM_SERVERS: Tuple[str, ...] = ("8.8.8.8", "1.1.1.1")
DEFAULT_UPSTREAM_TIMEOUT = 2.0


def normalize_domain(raw_domain: str) -> str:
    domain = raw_domain.strip().lower()
    if domain.endswith("."):
        domain = domain[:-1]
    return domain


def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False

    labels = domain.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        for ch in label:
            if not (ch.isalnum() or ch == "-"):
                return False

    return True


def is_valid_ipv4(ip_address: str) -> bool:
    try:
        socket.inet_aton(ip_address)
    except OSError:
        return False
    return True


def _encode_domain(domain: str) -> bytes:
    labels = domain.split(".")
    encoded = bytearray()
    for label in labels:
        encoded.append(len(label))
        encoded.extend(label.encode("ascii"))
    encoded.append(0)
    return bytes(encoded)


def _build_dns_query(domain: str, tx_id: int) -> bytes:
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    question = _encode_domain(domain) + struct.pack("!HH", 1, 1)
    return header + question


def _read_name(packet: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
    if depth > 20:
        raise ValueError("DNS name compression pointer loop")

    labels = []
    next_offset = None

    while True:
        if offset >= len(packet):
            raise ValueError("DNS name offset out of range")

        length = packet[offset]
        if length == 0:
            offset += 1
            break

        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("DNS compression pointer truncated")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if next_offset is None:
                next_offset = offset + 2
            name, _ = _read_name(packet, pointer, depth + 1)
            labels.append(name)
            break

        offset += 1
        end = offset + length
        if end > len(packet):
            raise ValueError("DNS label extends beyond packet")
        labels.append(packet[offset:end].decode("ascii"))
        offset = end

    full_name = ".".join(label for label in labels if label)
    return full_name, (next_offset if next_offset is not None else offset)


def _query_upstream_a(domain: str, dns_server_ip: str, timeout: float) -> Optional[Tuple[str, int]]:
    tx_id = randint(0, 0xFFFF)
    query = _build_dns_query(domain, tx_id)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(max(0.1, float(timeout)))

    try:
        sock.sendto(query, (dns_server_ip, 53))
        response, _ = sock.recvfrom(2048)
    except OSError:
        return None
    finally:
        sock.close()

    if len(response) < 12:
        return None

    try:
        recv_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", response[:12])
    except struct.error:
        return None

    if recv_id != tx_id:
        return None

    rcode = flags & 0x000F
    if rcode != 0:
        return None

    offset = 12

    try:
        for _ in range(qdcount):
            _, offset = _read_name(response, offset)
            offset += 4

        for _ in range(ancount):
            _, offset = _read_name(response, offset)
            if offset + 10 > len(response):
                return None

            record_type, record_class, ttl, rdlength = struct.unpack(
                "!HHIH", response[offset:offset + 10]
            )
            offset += 10

            if offset + rdlength > len(response):
                return None

            rdata = response[offset:offset + rdlength]
            offset += rdlength

            if record_type == 1 and record_class == 1 and rdlength == 4:
                ip = socket.inet_ntoa(rdata)
                return ip, max(1, int(ttl))
    except (ValueError, UnicodeDecodeError, struct.error, OSError):
        return None

    return None


class StaticResolver:
    """Resolve domain names from static records."""

    def __init__(
        self,
        records: Dict[str, Any],
        default_ttl: int = 10,
        enable_upstream: bool = True,
        upstream_servers: Tuple[str, ...] = DEFAULT_UPSTREAM_SERVERS,
        upstream_timeout: float = DEFAULT_UPSTREAM_TIMEOUT,
    ) -> None:
        self.default_ttl = max(1, int(default_ttl))
        self.enable_upstream = bool(enable_upstream)
        self.upstream_timeout = max(0.1, float(upstream_timeout))
        self.upstream_servers = tuple(ip for ip in upstream_servers if is_valid_ipv4(ip))
        self.records: Dict[str, Tuple[str, int]] = {}

        for raw_domain, value in records.items():
            domain = normalize_domain(str(raw_domain))
            if not is_valid_domain(domain):
                continue

            ip: Optional[str] = None
            ttl = self.default_ttl

            if isinstance(value, str):
                ip = value
            elif isinstance(value, dict):
                ip = value.get("ip")
                ttl = value.get("ttl", self.default_ttl)
            else:
                continue

            if not isinstance(ip, str) or not is_valid_ipv4(ip):
                continue

            try:
                ttl = max(1, int(ttl))
            except (TypeError, ValueError):
                ttl = self.default_ttl

            self.records[domain] = (ip, ttl)

    def resolve(self, domain: str) -> Optional[Tuple[str, int]]:
        static_result = self.records.get(domain)
        if static_result is not None:
            return static_result

        if not self.enable_upstream:
            return None

        for dns_server_ip in self.upstream_servers:
            upstream_result = _query_upstream_a(domain, dns_server_ip, self.upstream_timeout)
            if upstream_result is not None:
                return upstream_result

        return None


def load_records_from_file(path: str, logger: Optional[Callable[[str, str, Optional[str]], None]] = None) -> Dict[str, Any]:
    def _log(tag: str, message: str, color: Optional[str] = None) -> None:
        if logger:
            logger(tag, message, color)

    try:
        with open(path, "r", encoding="utf-8") as file_obj:
            data = json.load(file_obj)
    except FileNotFoundError:
        _log("ERROR", f"Records file not found: {path}. Using defaults.", "31")
        return DEFAULT_RECORDS
    except (OSError, json.JSONDecodeError) as exc:
        _log("ERROR", f"Cannot read records file: {exc}. Using defaults.", "31")
        return DEFAULT_RECORDS

    if not isinstance(data, dict):
        _log("ERROR", "Records file root must be an object. Using defaults.", "31")
        return DEFAULT_RECORDS

    return data
