import html
import time
import sys
import os

# Add root directory to path to import core modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    from PySide6.QtCore import Qt, QUrl
    from PySide6.QtGui import QTextCursor
    from PySide6.QtWebEngineWidgets import QWebEngineView
    from PySide6.QtWidgets import (
        QApplication,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QSplitter,
        QStatusBar,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    print("Missing GUI dependencies.")
    print("Install with: python -m pip install PySide6")
    raise SystemExit(1)

from browser.core.url_parser import parse_url, URLParseError
from browser.core.dns_client import DNSClient, DNSError
from browser.core.http_client import HTTPClient, HTTPError



DNS_SERVER_HOST = "127.0.0.1"
DNS_SERVER_PORT = 5200
HTTP_SERVER_PORT = 8000

# Quick test URLs
BOOKMARKS = [
    "http://example.local/",
    "http://example.local/about",
    "http://test.local/",
]


class BrowserApp:
    """
    Main browser window.
    Layout:
      [toolbar]  - address bar + Go/Clear buttons
      [log]      - step-by-step log (DNS query, HTTP request...)
      [content]  - web content (HTML/CSS/JS)
      [statusbar]
    """

    LOG_COLORS = {
        "info": "#89b4fa",
        "ok": "#a6e3a1",
        "warn": "#f9e2af",
        "error": "#f38ba8",
        "header": "#cba6f7",
        "dim": "#6c7086",
    }

    def __init__(self):
        self.window = QMainWindow()
        self.window.setWindowTitle("Mini Web Browser")
        self.window.resize(960, 700)
        self.window.setMinimumSize(700, 500)

        self.dns_client = DNSClient(
            server_host=DNS_SERVER_HOST,
            server_port=DNS_SERVER_PORT,
        )
        self.http_client = HTTPClient()

        self._build_ui()
        self._bind_shortcuts()


    def _build_ui(self):
        root_widget = QWidget()
        self.window.setCentralWidget(root_widget)

        root_layout = QVBoxLayout(root_widget)
        root_layout.setContentsMargins(8, 8, 8, 8)
        root_layout.setSpacing(6)

        toolbar = QHBoxLayout()
        root_layout.addLayout(toolbar)

        toolbar.addWidget(QLabel("URL:"))

        self.url_input = QLineEdit()
        self.url_input.setText("http://example.local/")
        toolbar.addWidget(self.url_input, 1)

        self.go_btn = QPushButton("Go")
        self.go_btn.clicked.connect(self._on_go)
        toolbar.addWidget(self.go_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._on_clear)
        toolbar.addWidget(clear_btn)

        toolbar.addWidget(QLabel("Quick:"))
        for bm in BOOKMARKS:
            short = bm.replace("http://", "").rstrip("/") or "/"
            btn = QPushButton(short)
            btn.clicked.connect(lambda _=False, u=bm: self._navigate_to(u))
            toolbar.addWidget(btn)

        splitter = QSplitter(Qt.Orientation.Vertical)
        root_layout.addWidget(splitter, 1)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet(
            "background:#1e1e2e;"
            "color:#cdd6f4;"
            "font-family:monospace;"
            "font-size:12px;"
        )
        splitter.addWidget(self.log_text)

        self.web_view = QWebEngineView()
        splitter.addWidget(self.web_view)
        splitter.setSizes([170, 500])

        self.status_bar = QStatusBar()
        self.window.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready.")

    def _bind_shortcuts(self):
        self.url_input.returnPressed.connect(self._on_go)

    # Event handlers

    def _on_go(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self.window, "Missing URL", "Please enter a URL.")
            return
        self._navigate(url)

    def _on_clear(self):
        self._clear_log()
        self._clear_content()
        self.status_bar.showMessage("Ready.")

    def _navigate_to(self, url: str):
        self.url_input.setText(url)
        self._navigate(url)

    # Navigation

    def _navigate(self, url: str):
        self._clear_log()
        self._clear_content()
        self._set_loading(True)

        try:
            start = time.time()

            # Step 1: Parse URL
            self._log("─" * 50, "dim")
            self._log(f"[1/4] Parse URL: {url}", "info")

            try:
                parsed = parse_url(url)
            except URLParseError as e:
                self._log(f"      ✗ {e}", "error")
                self._show_error(f"Invalid URL:\n{e}")
                return

            self._log(f"      ✓ host={parsed.host}  port={parsed.port}  path={parsed.path}", "ok")

            # Step 2: DNS query
            self._log(f"[2/4] DNS query: {parsed.host} → {DNS_SERVER_HOST}:{DNS_SERVER_PORT}", "info")

            try:
                dns_result = self.dns_client.resolve(parsed.host)
            except DNSError as e:
                self._log(f"      ✗ {e}", "error")
                self._show_error(f"DNS Error:\n{e}")
                return

            src = " (cache)" if dns_result.from_cache else ""
            self._log(f"      ✓ {dns_result.domain} → {dns_result.ip}{src}", "ok")

            # Step 3: HTTP request
            http_port = parsed.port if parsed.port not in (80, 443) else HTTP_SERVER_PORT
            self._log(f"[3/4] HTTP GET {parsed.path} → {dns_result.ip}:{http_port}", "info")
            self._log(f"      Host: {parsed.host}", "dim")

            try:
                response = self.http_client.get(
                    ip=dns_result.ip,
                    port=http_port,
                    path=parsed.path,
                    host=parsed.host,
                )
            except HTTPError as e:
                self._log(f"      ✗ {e}", "error")
                self._show_error(f"HTTP Error:\n{e}")
                return

            # Status
            status_tag = "ok" if response.is_ok else "error"
            self._log(f"      ✓ {response.status_code} {response.status_text}", status_tag)

            # Headers
            self._log("[4/4] Response headers:", "info")
            for k, v in response.headers.items():
                self._log(f"      {k}: {v}", "dim")

            # Step 4: Render
            elapsed = time.time() - start
            self._set_status(
                f"{response.status_code} {response.status_text}  |  "
                f"{len(response.body)} chars  |  {elapsed * 1000:.0f}ms"
            )
            self._render_content(response, dns_result.ip, http_port, parsed.path)

        finally:
            self._set_loading(False)

    # UI helpers

    def _log(self, msg: str, tag: str = ""):
        color = self.LOG_COLORS.get(tag, self.LOG_COLORS["dim"])
        self.log_text.moveCursor(QTextCursor.MoveOperation.End)
        self.log_text.insertHtml(
            f'<span style="color:{color}; white-space:pre;">{html.escape(msg)}</span><br>'
        )
        self.log_text.moveCursor(QTextCursor.MoveOperation.End)

    def _clear_log(self):
        self.log_text.clear()

    def _clear_content(self):
        self.web_view.setHtml("")

    def _render_content(self, response, ip: str, port: int, path: str):
        content_type = response.headers.get("Content-Type", "").lower()
        base_url = QUrl(f"http://{ip}:{port}{path}")

        if response.is_ok and "text/html" in content_type:
            self.web_view.setHtml(response.body, base_url)
            return

        title = f"{response.status_code} {response.status_text}" if not response.is_ok else "Response Body"
        escaped_body = html.escape(response.body)
        self.web_view.setHtml(
            "<html><body style='font-family:monospace; padding:16px;'>"
            f"<h3>{html.escape(title)}</h3>"
            f"<pre>{escaped_body}</pre>"
            "</body></html>"
        )

    def _show_error(self, msg: str):
        QMessageBox.critical(self.window, "Navigation error", msg)
        self.web_view.setHtml(
            "<html><body style='font-family:sans-serif; padding:16px;'>"
            "<h3>Navigation error</h3>"
            f"<pre>{html.escape(msg)}</pre>"
            "</body></html>"
        )
        self.status_bar.showMessage("Error.")

    def _set_status(self, msg: str):
        self.status_bar.showMessage(msg)

    def _set_loading(self, loading: bool):
        if loading:
            self.go_btn.setEnabled(False)
            self.go_btn.setText("...")
            self.status_bar.showMessage("Loading...")
        else:
            self.go_btn.setEnabled(True)
            self.go_btn.setText("Go")


def main():
    app = QApplication(sys.argv)
    browser = BrowserApp()
    browser.window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
