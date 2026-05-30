"""Server entry point — dispatches to gateway or app role based on env."""
from server.config import (
    HTTP_ROLE, HTTP_HOST, HTTP_PORT, HTTP_HTTPS_PORT,
    HTTP_BACKENDS, HTTP_NODE_ID, HTTP_MAX_WORKERS,
    TLS_CERT_PATH, TLS_KEY_PATH,
)
from server.gateway.server import GatewayServer


def main():
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
            from server.app.db import init_schema
            from server.shared.static import set_public_dir, PUBLIC_DIR
            from server.app.server import AppServer
            import os
            init_schema()
            public = os.getenv("HTTP_PUBLIC_DIR", "http-server/public")
            set_public_dir(public)
            server = AppServer(
                host=HTTP_HOST,
                port=HTTP_PORT,
                max_workers=HTTP_MAX_WORKERS,
            )
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
    server.start()


if __name__ == "__main__":
    main()
