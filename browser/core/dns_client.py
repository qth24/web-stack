"""
dns_client.py — Sends DNS queries to the DNS server via UDP.
Simple protocol:
  - Send: domain name (UTF-8 encoded)
  - Receive: IP address (plain text) or "NXDOMAIN"
"""

import socket
import json
from dataclasses import dataclass


# DNS server configuration
DNS_HOST = "127.0.0.1"
DNS_PORT = 5200
DNS_TIMEOUT = 3.0       # seconds
DNS_BUFFER = 4096       # bytes


@dataclass
class DNSResult:
    domain: str
    ip: str
    from_cache: bool = False

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
        enable_cache: bool = True,
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.timeout = timeout
        self.enable_cache = enable_cache
        self._cache: dict[str, str] = {}

    def resolve(self, domain: str) -> DNSResult:
        """
        Resolves domain to IP. 
        Uses cache if available, otherwise sends UDP query.
        """
        domain = domain.strip().lower()

        # Check cache
        if self.enable_cache and domain in self._cache:
            return DNSResult(domain=domain, ip=self._cache[domain], from_cache=True)

        # Send UDP query
        ip = self._query(domain)

        # Save to cache
        if self.enable_cache:
            self._cache[domain] = ip

        return DNSResult(domain=domain, ip=ip)

    def _query(self, domain: str) -> str:
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
            return ip

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
        return dict(self._cache)


if __name__ == "__main__":
    client = DNSClient()

    for domain in ["example.local", "test.local", "notfound.local"]:
        try:
            result = client.resolve(domain)
            print(f"[OK]  {result}")
        except DNSError as e:
            print(f"[ERR] {e}")

    # Second call should use cache
    try:
        r = client.resolve("example.local")
        print(f"[OK]  {r}")
    except DNSError as e:
        print(f"[ERR] {e}")
