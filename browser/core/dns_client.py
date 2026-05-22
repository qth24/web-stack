"""
dns_client.py — Sends DNS queries to the DNS server via UDP.
Simple protocol:
  - Send: JSON {"domain": "example.local"}
  - Receive: JSON {"status": "OK", "domain": "...", "ip": "...", "expire_at": ...}
"""

import json
import socket
import time
from dataclasses import dataclass
from typing import Optional

try:
    from .config import DNS_BUFFER, DNS_HOST, DNS_PORT, DNS_TIMEOUT, ENABLE_DNS_CACHE
except ImportError:
    from config import DNS_BUFFER, DNS_HOST, DNS_PORT, DNS_TIMEOUT, ENABLE_DNS_CACHE


@dataclass
class DNSResult:
    domain: str
    ip: str
    from_cache: bool = False
    expire_at: Optional[float] = None

    def __str__(self):
        src = " [cache]" if self.from_cache else ""
        return f"{self.domain} → {self.ip}{src}"


class DNSError(Exception):
    pass


class DNSClient:
    """
    Sends DNS queries over UDP with a simple in-memory cache.
    Uses JSON-based protocol.
    """

    def __init__(
        self,
        server_host: str = DNS_HOST,
        server_port: int = DNS_PORT,
        timeout: float = DNS_TIMEOUT,
        enable_cache: bool = ENABLE_DNS_CACHE,
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.timeout = timeout
        self.enable_cache = enable_cache
        self._cache: dict[str, DNSResult] = {}

    def resolve(self, domain: str) -> DNSResult:
        """
        Resolves domain to IP. 
        Uses cache if available, otherwise sends UDP query.
        """
        domain = domain.strip().lower()
        if not domain:
            raise DNSError("Domain cannot be empty")

        # Check cache
        if self.enable_cache:
            cached = self._cache.get(domain)
            if cached and (cached.expire_at is None or cached.expire_at > time.time()):
                return DNSResult(
                    domain=cached.domain,
                    ip=cached.ip,
                    from_cache=True,
                    expire_at=cached.expire_at,
                )
            if cached:
                del self._cache[domain]

        # Send UDP query
        result = self._query(domain)

        # Save to cache
        if self.enable_cache:
            self._cache[domain] = result

        return result

    def _query(self, domain: str) -> DNSResult:
        """Sends JSON UDP packet and receives JSON response"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        try:
            # Build and send JSON query
            query_data = json.dumps({"domain": domain})
            sock.sendto(query_data.encode("utf-8"), (self.server_host, self.server_port))

            # Receive response
            data, _ = sock.recvfrom(DNS_BUFFER)
            response_text = data.decode("utf-8").strip()
            
            try:
                response_json = json.loads(response_text)
            except json.JSONDecodeError:
                raise DNSError(f"DNS server returned malformed JSON: '{response_text}'")

            # Check status
            status = response_json.get("status")
            if status == "NXDOMAIN":
                raise DNSError(f"Domain not found: '{domain}'")
            elif status != "OK":
                msg = response_json.get("message", "Unknown error")
                raise DNSError(f"DNS server error ({status}): {msg}")

            ip = response_json.get("ip")
            if not ip:
                raise DNSError(f"DNS server response missing 'ip' field: {response_text}")

            # Basic IP validation
            self._validate_ip(ip)
            resolved_domain = response_json.get("domain") or domain
            expire_at = response_json.get("expire_at")
            if not isinstance(expire_at, (int, float)):
                expire_at = None
            return DNSResult(domain=resolved_domain, ip=ip, expire_at=expire_at)

        except socket.timeout:
            raise DNSError(
                f"DNS server did not respond after {self.timeout}s "
                f"(check if server is running at {self.server_host}:{self.server_port})"
            )
        except ConnectionRefusedError:
            raise DNSError(
                f"Could not connect to DNS server at "
                f"{self.server_host}:{self.server_port}"
            )
        finally:
            sock.close()

    def _validate_ip(self, ip: str) -> None:
        """Basic IPv4 validation"""
        parts = ip.split(".")
        if len(parts) != 4:
            raise DNSError(f"DNS server returned invalid IP: '{ip}'")
        try:
            for p in parts:
                val = int(p)
                if not (0 <= val <= 255):
                    raise ValueError
        except ValueError:
            raise DNSError(f"DNS server returned invalid IP: '{ip}'")

    def clear_cache(self):
        self._cache.clear()

    def get_cache(self) -> dict:
        now = time.time()
        expired_domains = [
            domain
            for domain, result in self._cache.items()
            if result.expire_at is not None and result.expire_at <= now
        ]
        for domain in expired_domains:
            del self._cache[domain]

        return {
            domain: {
                "ip": result.ip,
                "expire_at": result.expire_at,
            }
            for domain, result in self._cache.items()
        }
