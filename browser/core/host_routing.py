"""Pure helpers for deciding when the browser should use custom DNS loading."""

import socket


def is_ipv4_address(value: str) -> bool:
    try:
        socket.inet_aton(value)
    except OSError:
        return False
    return value.count(".") == 3


def should_use_custom_dns(host: str, force_all_hosts: bool = False) -> bool:
    host = (host or "").strip().lower()
    return bool(host) and (
        force_all_hosts
        or host == "localhost"
        or host.endswith(".local")
        or is_ipv4_address(host)
    )


def uses_local_http_default(host: str) -> bool:
    host = (host or "").strip().lower()
    return host == "localhost" or host.endswith(".local")


def effective_port_for_host(
    scheme: str,
    host: str,
    explicit_port: int | None,
    local_http_default: int,
    https_default: int,
) -> int:
    if explicit_port is not None:
        return int(explicit_port)
    if scheme == "https":
        return int(https_default)
    if uses_local_http_default(host):
        return int(local_http_default)
    return 80
