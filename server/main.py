"""Server entry point — dispatches to gateway or app role based on env."""
import asyncio
import os
import signal

from server.config import (
    HTTP_ROLE, HTTP_HOST, HTTP_PORT, HTTP_HTTPS_PORT,
    HTTP_BACKENDS, HTTP_NODE_ID, HTTP_MAX_WORKERS,
    TLS_CERT_PATH, TLS_KEY_PATH,
)
from server.gateway.server import GatewayServer


async def _serve(server) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(server.stop()))
        except (NotImplementedError, RuntimeError):
            pass
    await server.serve_forever()


async def _main():
    close_db = None
    if HTTP_ROLE == "gateway":
        server = GatewayServer(
            host=HTTP_HOST,
            port=HTTP_HTTPS_PORT,
            backends=HTTP_BACKENDS,
            tls_cert=TLS_CERT_PATH,
            tls_key=TLS_KEY_PATH,
            node_id=HTTP_NODE_ID,
            max_workers=HTTP_MAX_WORKERS,
        )
    else:
        try:
            from server.app.db import close_pool, init_schema
            from server.shared.static import set_public_dir
            from server.app.server import AppServer
            await init_schema()
            public = os.getenv("HTTP_PUBLIC_DIR", "http-server/public")
            set_public_dir(public)
            server = AppServer(
                host=HTTP_HOST,
                port=HTTP_PORT,
                max_workers=HTTP_MAX_WORKERS,
                node_id=HTTP_NODE_ID,
            )
            close_db = close_pool
        except ImportError:
            print("[main] app modules not available; starting gateway anyway")
            server = GatewayServer(
                host=HTTP_HOST,
                port=HTTP_HTTPS_PORT,
                backends=HTTP_BACKENDS,
                tls_cert=TLS_CERT_PATH,
                tls_key=TLS_KEY_PATH,
                node_id=HTTP_NODE_ID,
                max_workers=HTTP_MAX_WORKERS,
            )
    try:
        await _serve(server)
    finally:
        if close_db is not None:
            await close_db()


def main():
    asyncio.run(_main())


if __name__ == "__main__":
    main()
