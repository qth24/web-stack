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
