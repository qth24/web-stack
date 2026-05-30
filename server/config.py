import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

HTTP_ROLE = os.getenv("HTTP_ROLE", "app")
HTTP_HOST = os.getenv("HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("HTTP_PORT", "8081"))
HTTP_HTTPS_PORT = int(os.getenv("HTTP_HTTPS_PORT", "8443"))
HTTP_BACKENDS = [b.strip() for b in os.getenv("HTTP_BACKENDS", "localhost:8081,localhost:8082").split(",") if b.strip()]
HTTP_NODE_ID = os.getenv("HTTP_NODE_ID", "app-a")
HTTP_MAX_WORKERS = int(os.getenv("HTTP_MAX_WORKERS", "16"))
TLS_CERT_PATH = os.getenv("TLS_CERT_PATH") or None
TLS_KEY_PATH = os.getenv("TLS_KEY_PATH") or None
HTTP_DEV_INSECURE_TLS = os.getenv("HTTP_DEV_INSECURE_TLS", "false").lower() == "true"
