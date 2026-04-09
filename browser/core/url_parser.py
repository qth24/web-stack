from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass
from typing import Optional


@dataclass
class ParsedURL:
    """URL parsing result"""
    protocol: str       # "http"
    host: str           # "example.local"
    port: int           # 8080 (default 80 if not present)
    path: str           # "/about"
    query: dict         # {"q": ["1"]}
    raw: str            # Original URL

    def __str__(self):
        return (
            f"ParsedURL(\n"
            f"  protocol = {self.protocol}\n"
            f"  host     = {self.host}\n"
            f"  port     = {self.port}\n"
            f"  path     = {self.path}\n"
            f"  query    = {self.query}\n"
            f")"
        )


class URLParseError(Exception):
    pass


def parse_url(url: str) -> ParsedURL:
    """
    Parses URL and returns ParsedURL.
    Raises URLParseError if URL is invalid.
    """
    url = url.strip()

    # Check for unsupported schemes (e.g., ftp://, ws://)
    if "://" in url:
        scheme = url.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            raise URLParseError(f"Unsupported protocol: '{scheme}'. Only http/https are supported.")

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    # Re-check protocol
    if parsed.scheme not in ("http", "https"):
        raise URLParseError(f"Unsupported protocol: '{parsed.scheme}'. Only http/https are supported.")

    # Check for host
    if not parsed.netloc and not parsed.hostname:
        raise URLParseError(f"URL missing host: '{url}'")

    host = parsed.hostname or ""
    if not host:
        raise URLParseError(f"Could not extract host from: '{url}'")

    # Default ports
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port if parsed.port else default_port

    # Default path is "/"
    path = parsed.path if parsed.path else "/"

    # Query string
    query = parse_qs(parsed.query)

    return ParsedURL(
        protocol=parsed.scheme,
        host=host,
        port=port,
        path=path,
        query=query,
        raw=url,
    )


if __name__ == "__main__":
    test_urls = [
        "http://example.local/about",
        "http://test.local:8080/page?id=1",
        "example.local",           # missing scheme
        "ftp://bad.local",         # unsupported scheme
    ]

    for u in test_urls:
        try:
            result = parse_url(u)
            print(result)
        except URLParseError as e:
            print(f"[ERROR] {e}\n")
