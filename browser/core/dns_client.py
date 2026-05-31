"""
dns_client.py — Sends DNS queries to the DNS server using RFC 1035 wire format.
Protocol:
  - Send: RFC 1035 binary query via dnslib.DNSRecord
  - Receive: RFC 1035 binary response via dnslib.DNSRecord.parse
"""

import asyncio
import socket
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from dnslib import DNSRecord, QTYPE, RCODE, DNSError as DNSLibError

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
    Uses RFC 1035 binary wire format via dnslib.
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

    async def resolve(self, domain: str) -> DNSResult:
        """
        Resolves domain to IP.
        Uses cache if available, otherwise sends UDP query.
        """
        domain = domain.strip().lower()
        if domain.endswith("."):
            domain = domain[:-1]
        if not domain:
            raise DNSError("Domain cannot be empty")
        if self._is_ipv4_literal(domain):
            return DNSResult(domain=domain, ip=domain, from_cache=False, expire_at=None)

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
        result = await self._query(domain)

        # Save to cache
        if self.enable_cache:
            self._cache[domain] = result

        return result

    @staticmethod
    def _is_ipv4_literal(value: str) -> bool:
        try:
            socket.inet_aton(value)
        except OSError:
            return False
        return value.count(".") == 3

    async def _query(self, domain: str) -> DNSResult:
        """Sends RFC 1035 binary DNS query via UDP and parses the response."""
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            query = DNSRecord.question(domain, qtype="A")
            query.header.id = uuid.uuid4().int % 65536
            query_bytes = bytes(query.pack())
            if hasattr(sock, "fileno") and hasattr(sock, "setblocking"):
                sock.setblocking(False)
                await loop.sock_sendto(sock, query_bytes, (self.server_host, self.server_port))
                data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, DNS_BUFFER), timeout=self.timeout)
            else:
                def _blocking_roundtrip():
                    sock.sendto(query_bytes, (self.server_host, self.server_port))
                    return sock.recvfrom(DNS_BUFFER)
                data, _ = await asyncio.to_thread(_blocking_roundtrip)
            response = DNSRecord.parse(data)

            if response.header.rcode != RCODE.NOERROR:
                raise DNSError(f"DNS server returned error for domain '{domain}' (rcode={response.header.rcode})")

            if not response.rr:
                raise DNSError(f"DNS server returned no answer records for '{domain}'")

            for rr in response.rr:
                if rr.rtype == QTYPE.A:
                    ip = str(rr.rdata)
                    self._validate_ip(ip)
                    ttl = max(0, int(rr.ttl))
                    expire_at = time.time() + ttl
                    return DNSResult(domain=domain, ip=ip, expire_at=expire_at)

            raise DNSError(f"DNS server returned no A record for '{domain}'")

        except TimeoutError:
            raise DNSError(
                f"DNS server did not respond after {self.timeout}s "
                f"(check if server is running at {self.server_host}:{self.server_port})"
            )
        except ConnectionRefusedError:
            raise DNSError(
                f"Could not connect to DNS server at "
                f"{self.server_host}:{self.server_port}"
            )
        except (DNSLibError, ValueError) as e:
            raise DNSError(f"DNS query failed for '{domain}': {e}") from e
        except OSError as e:
            raise DNSError(f"Socket error for DNS query: {e}") from e
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
