#!/usr/bin/env python3
"""Start all Mini Web Stack services from the project root.

Usage:
    python3 start.py             # start all 4 services
    python3 start.py --dry-run   # print commands without executing
"""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# --- ANSI colors ---
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _load_env_file(path: Path) -> None:
    """Load .env file into os.environ (same pattern as dns/config.py)."""
    if not path.exists():
        print(f"{YELLOW}Warning: {path} not found — skipping env load{RESET}")
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        print(f"{YELLOW}Warning: could not read {path}{RESET}")
        return

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _handle_sigint(
    processes: list,
) -> None:
    """Shutdown handler: terminate all child process groups."""
    print(f"\n{YELLOW}[stop]{RESET} Shutting down...")
    for name, proc in processes:
        if proc.poll() is None:
            print(f"  {RED}Stopping{RESET} {name} (pid={proc.pid})")
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
    for name, proc in processes:
        try:
            proc.wait(timeout=5)
            print(f"  {name}: exited")
        except subprocess.TimeoutExpired:
            print(f"  {YELLOW}{name}: force killing{RESET}")
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
    print(f"{GREEN}All services stopped.{RESET}")
    sys.exit(0)


def main() -> None:
    project_root = Path(__file__).resolve().parent

    # --- CLI flag ---
    dry_run = "--dry-run" in sys.argv

    # --- Load root .env ---
    env_path = project_root / ".env"
    print(f"{CYAN}[env]{RESET} Loading {env_path}")
    _load_env_file(env_path)

    # --- Service definitions (start order matters) ---
    services = [
        ("DNS Server", "dns/dns_server.py"),
        ("HTTP Server", "http-server/src/server.py"),
        ("VPN Server", "vpn/vpn_server.py"),
        ("Browser", "browser/gui/browser_gui.py"),
    ]

    processes: list = []

    # --- Register SIGINT handler ---
    signal.signal(signal.SIGINT, lambda sig, frame: _handle_sigint(processes))

    # --- Start services ---
    delay_seconds = 1

    for i, (name, script) in enumerate(services):
        if i > 0:
            time.sleep(delay_seconds)

        script_path = project_root / script
        cmd = ["python3", str(script_path)]

        print(f"\n{GREEN}[start]{RESET} {name} ({script})")
        print(f"  {BOLD}$ {' '.join(cmd)}{RESET}")

        if dry_run:
            continue

        proc = subprocess.Popen(
            cmd,
            cwd=str(project_root),
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        processes.append((name, proc))

    if dry_run:
        print(f"\n{YELLOW}[dry-run]{RESET} No processes started.")
        return

    if not processes:
        print(f"\n{YELLOW}[warn]{RESET} No services started.")
        return

    print(f"\n{GREEN}{BOLD}All services running. Press Ctrl+C to stop.{RESET}")

    # --- Wait for children ---
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _handle_sigint(processes)


if __name__ == "__main__":
    main()
