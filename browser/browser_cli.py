import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from browser.core.url_parser import parse_url, URLParseError
from browser.core.dns_client import DNSClient, DNSError
from browser.core.http_client import HTTPClient, HTTPError

DNS_HOST = "127.0.0.1"
DNS_PORT = 5200
HTTP_PORT = 8000

RESET  = "\033[0m"
BLUE   = "\033[94m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[2m"
BOLD   = "\033[1m"


def cprint(msg, color=""):
    print(f"{color}{msg}{RESET}")


def navigate(url: str):
    dns_client = DNSClient(server_host=DNS_HOST, server_port=DNS_PORT)
    http_client = HTTPClient()

    cprint("-" * 55, DIM)

    # Parse URL
    cprint(f"[1/4] Parse URL: {url}", BLUE)
    try:
        parsed = parse_url(url)
    except URLParseError as e:
        cprint(f"      ✗ {e}", RED)
        return

    cprint(f"      ✓ host={parsed.host}  port={parsed.port}  path={parsed.path}", GREEN)

    # DNS
    cprint(f"[2/4] DNS query: {parsed.host}", BLUE)
    try:
        dns_result = dns_client.resolve(parsed.host)
    except DNSError as e:
        cprint(f"      ✗ {e}", RED)
        return

    src = " (cache)" if dns_result.from_cache else ""
    cprint(f"      ✓ {dns_result.domain} → {dns_result.ip}{src}", GREEN)

    # HTTP
    http_port = parsed.port if parsed.port not in (80, 443) else HTTP_PORT
    cprint(f"[3/4] GET {parsed.path} → {dns_result.ip}:{http_port}", BLUE)

    try:
        response = http_client.get(
            ip=dns_result.ip,
            port=http_port,
            path=parsed.path,
            host=parsed.host,
        )
    except HTTPError as e:
        cprint(f"      ✗ {e}", RED)
        return

    color = GREEN if response.is_ok else RED
    cprint(f"      ✓ {response.status_code} {response.status_text}", color)

    # Headers
    cprint("[4/4] Headers:", BLUE)
    for k, v in response.headers.items():
        cprint(f"      {k}: {v}", DIM)

    # Body
    cprint("\n" + "─" * 55 + " CONTENT " + "─" * 10, DIM)
    print(response.body)
    cprint("─" * 74, DIM)


def interactive_mode():
    cprint("Mini Web Browser - CLI Mode", BOLD)
    cprint("Type URL and press Enter. Ctrl+C to exit.\n", DIM)

    while True:
        try:
            url = input(f"{BLUE}URL> {RESET}").strip()
            if not url:
                continue
            if url.lower() in ("exit", "quit", "q"):
                break
            navigate(url)
        except KeyboardInterrupt:
            print()
            break

    cprint("\nExited.", DIM)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Single command mode: python browser_cli.py http://example.local/
        navigate(sys.argv[1])
    else:
        # Interactive mode
        interactive_mode()
