import html
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Optional

# Add root directory to path to import core modules.
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

try:
    from PySide6.QtCore import Qt, QUrl
    from PySide6.QtGui import QAction, QTextCursor
    from PySide6.QtWebEngineWidgets import QWebEngineView
    from PySide6.QtWidgets import (
        QApplication,
        QCheckBox,
        QDialog,
        QDialogButtonBox,
        QFormLayout,
        QFrame,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QSpinBox,
        QSplitter,
        QStatusBar,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QTextEdit,
        QToolBar,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    print("Missing GUI dependencies.")
    print("Install with: python -m pip install PySide6")
    raise SystemExit(1)

from browser.core.config import (
    DEFAULT_BOOKMARKS,
    DNS_HOST,
    DNS_PORT,
    DNS_TIMEOUT,
    ENABLE_DNS_CACHE,
    HOME_URL,
    HTTP_DEFAULT_PORT,
    STATE_PATH,
)
from browser.core.dns_client import DNSClient, DNSError
from browser.core.http_client import HTTPClient, HTTPError
from browser.core.url_parser import URLParseError, parse_url


@dataclass
class BrowserSettings:
    dns_host: str = DNS_HOST
    dns_port: int = DNS_PORT
    dns_timeout: float = DNS_TIMEOUT
    http_default_port: int = HTTP_DEFAULT_PORT
    enable_dns_cache: bool = ENABLE_DNS_CACHE
    home_url: str = HOME_URL


@dataclass
class NetworkEvent:
    url: str
    host: str
    path: str
    dns_server: str
    dns_ip: Optional[str] = None
    dns_from_cache: bool = False
    dns_ttl_remaining: Optional[int] = None
    http_endpoint: str = ""
    status: str = ""
    duration_ms: int = 0
    error: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)


class SettingsDialog(QDialog):
    def __init__(self, parent: QWidget, settings: BrowserSettings):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(420)

        self.dns_host_input = QLineEdit(settings.dns_host)

        self.dns_port_input = QSpinBox()
        self.dns_port_input.setRange(1, 65535)
        self.dns_port_input.setValue(settings.dns_port)

        self.dns_timeout_input = QSpinBox()
        self.dns_timeout_input.setRange(1, 30)
        self.dns_timeout_input.setValue(int(settings.dns_timeout))

        self.http_port_input = QSpinBox()
        self.http_port_input.setRange(1, 65535)
        self.http_port_input.setValue(settings.http_default_port)

        self.cache_input = QCheckBox("Enable DNS TTL cache")
        self.cache_input.setChecked(settings.enable_dns_cache)

        self.home_url_input = QLineEdit(settings.home_url)

        form = QFormLayout()
        form.addRow("DNS host", self.dns_host_input)
        form.addRow("DNS UDP port", self.dns_port_input)
        form.addRow("DNS timeout", self.dns_timeout_input)
        form.addRow("Default HTTP port", self.http_port_input)
        form.addRow("Home URL", self.home_url_input)
        form.addRow("", self.cache_input)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def settings(self) -> BrowserSettings:
        return BrowserSettings(
            dns_host=self.dns_host_input.text().strip() or DNS_HOST,
            dns_port=self.dns_port_input.value(),
            dns_timeout=float(self.dns_timeout_input.value()),
            http_default_port=self.http_port_input.value(),
            enable_dns_cache=self.cache_input.isChecked(),
            home_url=self.home_url_input.text().strip() or HOME_URL,
        )


class BrowserApp:
    LOG_COLORS = {
        "info": "#1d4ed8",
        "ok": "#15803d",
        "warn": "#a16207",
        "error": "#b91c1c",
        "dim": "#64748b",
    }

    def __init__(self):
        self.settings = self._load_settings()
        self.bookmarks = self._load_list("bookmarks", DEFAULT_BOOKMARKS)
        self.history = self._load_list("history", [])
        self.back_stack: list[str] = []
        self.forward_stack: list[str] = []
        self.current_url = ""
        self.network_events: list[NetworkEvent] = []

        self.window = QMainWindow()
        self.window.setWindowTitle("Mini Web Browser")
        self.window.resize(1180, 760)
        self.window.setMinimumSize(900, 560)

        self.dns_client = self._make_dns_client()
        self.http_client = HTTPClient()

        self._build_ui()
        self._bind_actions()
        self._refresh_all_lists()
        self._navigate(self.settings.home_url, add_to_history=False)

    def _make_dns_client(self) -> DNSClient:
        return DNSClient(
            server_host=self.settings.dns_host,
            server_port=self.settings.dns_port,
            timeout=self.settings.dns_timeout,
            enable_cache=self.settings.enable_dns_cache,
        )

    def _build_ui(self):
        root_widget = QWidget()
        self.window.setCentralWidget(root_widget)

        root_layout = QVBoxLayout(root_widget)
        root_layout.setContentsMargins(8, 8, 8, 8)
        root_layout.setSpacing(6)

        self.toolbar = QToolBar("Navigation")
        self.toolbar.setMovable(False)
        self.window.addToolBar(self.toolbar)

        self.back_action = QAction("Back", self.window)
        self.forward_action = QAction("Forward", self.window)
        self.reload_action = QAction("Reload", self.window)
        self.home_action = QAction("Home", self.window)
        self.bookmark_action = QAction("Bookmark", self.window)
        self.settings_action = QAction("Settings", self.window)

        self.toolbar.addAction(self.back_action)
        self.toolbar.addAction(self.forward_action)
        self.toolbar.addAction(self.reload_action)
        self.toolbar.addAction(self.home_action)
        self.toolbar.addSeparator()

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText(HOME_URL)
        self.toolbar.addWidget(self.url_input)

        self.go_action = QAction("Go", self.window)
        self.toolbar.addAction(self.go_action)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.bookmark_action)
        self.toolbar.addAction(self.settings_action)

        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        root_layout.addWidget(main_splitter, 1)

        self.side_tabs = QTabWidget()
        self.side_tabs.setMinimumWidth(240)
        main_splitter.addWidget(self.side_tabs)

        history_panel = QWidget()
        history_layout = QVBoxLayout(history_panel)
        history_layout.setContentsMargins(0, 0, 0, 0)
        self.history_list = QListWidget()
        self.clear_history_btn = QPushButton("Clear History")
        history_layout.addWidget(self.history_list)
        history_layout.addWidget(self.clear_history_btn)

        bookmark_panel = QWidget()
        bookmark_layout = QVBoxLayout(bookmark_panel)
        bookmark_layout.setContentsMargins(0, 0, 0, 0)
        self.bookmark_list = QListWidget()
        bookmark_buttons = QHBoxLayout()
        self.add_bookmark_btn = QPushButton("Add")
        self.remove_bookmark_btn = QPushButton("Remove")
        bookmark_buttons.addWidget(self.add_bookmark_btn)
        bookmark_buttons.addWidget(self.remove_bookmark_btn)
        bookmark_layout.addWidget(self.bookmark_list)
        bookmark_layout.addLayout(bookmark_buttons)

        cache_panel = QWidget()
        cache_layout = QVBoxLayout(cache_panel)
        cache_layout.setContentsMargins(0, 0, 0, 0)
        self.cache_table = QTableWidget(0, 4)
        self.cache_table.setHorizontalHeaderLabels(["Domain", "IP", "TTL", "Expires"])
        self.cache_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.clear_cache_btn = QPushButton("Clear DNS Cache")
        cache_layout.addWidget(self.cache_table)
        cache_layout.addWidget(self.clear_cache_btn)

        self.side_tabs.addTab(history_panel, "History")
        self.side_tabs.addTab(bookmark_panel, "Bookmarks")
        self.side_tabs.addTab(cache_panel, "DNS Cache")

        center_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(center_splitter)

        self.web_view = QWebEngineView()
        center_splitter.addWidget(self.web_view)

        inspector_frame = QFrame()
        inspector_layout = QVBoxLayout(inspector_frame)
        inspector_layout.setContentsMargins(0, 0, 0, 0)

        self.inspector_tabs = QTabWidget()
        inspector_layout.addWidget(self.inspector_tabs)

        self.network_table = QTableWidget(0, 8)
        self.network_table.setHorizontalHeaderLabels(
            ["URL", "DNS IP", "Cache", "TTL", "Endpoint", "Status", "Time", "Error"]
        )
        self.network_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.inspector_tabs.addTab(self.network_table, "Network")

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.inspector_tabs.addTab(self.detail_text, "Details")

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.inspector_tabs.addTab(self.log_text, "Log")

        center_splitter.addWidget(inspector_frame)
        center_splitter.setSizes([520, 220])
        main_splitter.setSizes([260, 900])

        self.status_bar = QStatusBar()
        self.window.setStatusBar(self.status_bar)
        self._set_status("Ready.")

    def _bind_actions(self):
        self.url_input.returnPressed.connect(self._on_go)
        self.go_action.triggered.connect(self._on_go)
        self.back_action.triggered.connect(self._go_back)
        self.forward_action.triggered.connect(self._go_forward)
        self.reload_action.triggered.connect(self._reload)
        self.home_action.triggered.connect(lambda: self._navigate(self.settings.home_url))
        self.bookmark_action.triggered.connect(self._add_current_bookmark)
        self.settings_action.triggered.connect(self._open_settings)
        self.add_bookmark_btn.clicked.connect(self._add_current_bookmark)
        self.remove_bookmark_btn.clicked.connect(self._remove_selected_bookmark)
        self.clear_history_btn.clicked.connect(self._clear_history)
        self.clear_cache_btn.clicked.connect(self._clear_dns_cache)
        self.history_list.itemDoubleClicked.connect(self._open_list_item)
        self.bookmark_list.itemDoubleClicked.connect(self._open_list_item)
        self.network_table.itemSelectionChanged.connect(self._show_selected_network_event)

    def _on_go(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self.window, "Missing URL", "Please enter a URL.")
            return
        self._navigate(url)

    def _go_back(self):
        if not self.back_stack:
            return
        target = self.back_stack.pop()
        if self.current_url:
            self.forward_stack.append(self.current_url)
        self._navigate(target, add_to_history=False, record_navigation=False)

    def _go_forward(self):
        if not self.forward_stack:
            return
        target = self.forward_stack.pop()
        if self.current_url:
            self.back_stack.append(self.current_url)
        self._navigate(target, add_to_history=False, record_navigation=False)

    def _reload(self):
        if self.current_url:
            self._navigate(self.current_url, add_to_history=False, record_navigation=False)

    def _open_list_item(self, item: QListWidgetItem):
        url = item.data(Qt.ItemDataRole.UserRole) or item.text()
        self._navigate(url)

    def _add_current_bookmark(self):
        url = self.current_url or self.url_input.text().strip()
        if not url:
            return
        if url not in self.bookmarks:
            self.bookmarks.insert(0, url)
            self._save_state()
            self._refresh_bookmarks()
            self._set_status(f"Bookmarked {url}")
        else:
            self._set_status("Bookmark already exists.")

    def _remove_selected_bookmark(self):
        item = self.bookmark_list.currentItem()
        if item is None:
            return
        url = item.data(Qt.ItemDataRole.UserRole) or item.text()
        if url in self.bookmarks:
            self.bookmarks.remove(url)
            self._save_state()
            self._refresh_bookmarks()
            self._set_status(f"Removed bookmark {url}")

    def _clear_history(self):
        self.history.clear()
        self._save_state()
        self._refresh_history()
        self._set_status("History cleared.")

    def _clear_dns_cache(self):
        self.dns_client.clear_cache()
        self._refresh_cache()
        self._set_status("DNS cache cleared.")

    def _open_settings(self):
        dialog = SettingsDialog(self.window, self.settings)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        self.settings = dialog.settings()
        self.dns_client = self._make_dns_client()
        self._save_state()
        self._refresh_cache()
        self._set_status(
            f"DNS server set to {self.settings.dns_host}:{self.settings.dns_port}"
        )

    def _navigate(
        self,
        url: str,
        add_to_history: bool = True,
        record_navigation: bool = True,
    ):
        self._set_loading(True)
        self._clear_log()
        start = time.time()
        event = NetworkEvent(
            url=url,
            host="",
            path="",
            dns_server=f"{self.settings.dns_host}:{self.settings.dns_port}",
        )

        try:
            self._log(f"Navigate {url}", "info")
            try:
                parsed = parse_url(url)
            except URLParseError as exc:
                event.error = str(exc)
                self._add_network_event(event)
                self._show_error("Invalid URL", str(exc))
                return

            normalized_url = parsed.raw
            self.url_input.setText(normalized_url)
            event.url = normalized_url
            event.host = parsed.host
            event.path = parsed.path

            self._log(f"DNS {parsed.host} via {event.dns_server}", "info")
            try:
                dns_result = self.dns_client.resolve(parsed.host)
            except DNSError as exc:
                event.error = str(exc)
                self._add_network_event(event)
                self._show_error("DNS Error", str(exc))
                return

            event.dns_ip = dns_result.ip
            event.dns_from_cache = dns_result.from_cache
            event.dns_ttl_remaining = self._ttl_remaining(dns_result.expire_at)
            cache_note = "cache" if dns_result.from_cache else "network"
            self._log(f"Resolved {dns_result.domain} -> {dns_result.ip} ({cache_note})", "ok")

            http_port = parsed.port if parsed.port not in (80, 443) else self.settings.http_default_port
            event.http_endpoint = f"{dns_result.ip}:{http_port}"
            event.request_headers = {
                "Host": parsed.host,
                "User-Agent": "MiniWebBrowser/1.0",
                "Accept": "text/html,*/*",
                "Connection": "close",
            }

            self._log(f"HTTP GET {parsed.path} -> {event.http_endpoint}", "info")
            try:
                response = self.http_client.get(
                    ip=dns_result.ip,
                    port=http_port,
                    path=parsed.path,
                    host=parsed.host,
                )
            except HTTPError as exc:
                event.error = str(exc)
                self._add_network_event(event)
                self._show_error("HTTP Error", str(exc))
                return

            event.status = f"{response.status_code} {response.status_text}".strip()
            event.response_headers = dict(response.headers)
            self._log(event.status, "ok" if response.is_ok else "error")

            elapsed = time.time() - start
            event.duration_ms = int(elapsed * 1000)
            self._render_content(response, dns_result.ip, http_port, parsed.path)
            self._add_network_event(event)

            if record_navigation and self.current_url and self.current_url != normalized_url:
                self.back_stack.append(self.current_url)
                self.forward_stack.clear()

            self.current_url = normalized_url
            if add_to_history:
                self._add_history(normalized_url)

            self._set_status(
                f"{event.status} | {len(response.body)} chars | {event.duration_ms}ms"
            )
        finally:
            self._refresh_cache()
            self._update_navigation_state()
            self._set_loading(False)

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

    def _show_error(self, title: str, message: str):
        self.web_view.setHtml(
            "<html><body style='font-family:sans-serif; padding:16px;'>"
            f"<h3>{html.escape(title)}</h3>"
            f"<pre>{html.escape(message)}</pre>"
            "</body></html>"
        )
        self._log(message, "error")
        self._set_status(title)

    def _add_history(self, url: str):
        if url in self.history:
            self.history.remove(url)
        self.history.insert(0, url)
        self.history = self.history[:100]
        self._save_state()
        self._refresh_history()

    def _add_network_event(self, event: NetworkEvent):
        if event.duration_ms == 0:
            event.duration_ms = 0
        self.network_events.insert(0, event)
        self.network_events = self.network_events[:100]
        self._refresh_network_table()

    def _show_selected_network_event(self):
        selected = self.network_table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        if row >= len(self.network_events):
            return
        event = self.network_events[row]
        detail = {
            "url": event.url,
            "host": event.host,
            "path": event.path,
            "dns_server": event.dns_server,
            "dns_ip": event.dns_ip,
            "dns_from_cache": event.dns_from_cache,
            "dns_ttl_remaining": event.dns_ttl_remaining,
            "http_endpoint": event.http_endpoint,
            "status": event.status,
            "duration_ms": event.duration_ms,
            "error": event.error,
            "request_headers": event.request_headers,
            "response_headers": event.response_headers,
        }
        self.detail_text.setPlainText(json.dumps(detail, indent=2))

    def _refresh_all_lists(self):
        self._refresh_history()
        self._refresh_bookmarks()
        self._refresh_cache()
        self._refresh_network_table()
        self._update_navigation_state()

    def _refresh_history(self):
        self.history_list.clear()
        for url in self.history:
            item = QListWidgetItem(url)
            item.setData(Qt.ItemDataRole.UserRole, url)
            self.history_list.addItem(item)

    def _refresh_bookmarks(self):
        self.bookmark_list.clear()
        for url in self.bookmarks:
            item = QListWidgetItem(url)
            item.setData(Qt.ItemDataRole.UserRole, url)
            self.bookmark_list.addItem(item)

    def _refresh_cache(self):
        cache = self.dns_client.get_cache()
        self.cache_table.setRowCount(0)
        now = time.time()
        for row, (domain, entry) in enumerate(cache.items()):
            expire_at = entry.get("expire_at")
            ttl = ""
            expires = ""
            if isinstance(expire_at, (int, float)):
                ttl = f"{max(0, int(expire_at - now))}s"
                expires = time.strftime("%H:%M:%S", time.localtime(expire_at))

            self.cache_table.insertRow(row)
            values = [domain, entry.get("ip", ""), ttl, expires]
            for col, value in enumerate(values):
                self.cache_table.setItem(row, col, QTableWidgetItem(str(value)))

    def _refresh_network_table(self):
        self.network_table.setRowCount(0)
        for row, event in enumerate(self.network_events):
            self.network_table.insertRow(row)
            values = [
                event.url,
                event.dns_ip or "",
                "yes" if event.dns_from_cache else "no",
                f"{event.dns_ttl_remaining}s" if event.dns_ttl_remaining is not None else "",
                event.http_endpoint,
                event.status,
                f"{event.duration_ms}ms" if event.duration_ms else "",
                event.error,
            ]
            for col, value in enumerate(values):
                self.network_table.setItem(row, col, QTableWidgetItem(value))

    def _update_navigation_state(self):
        self.back_action.setEnabled(bool(self.back_stack))
        self.forward_action.setEnabled(bool(self.forward_stack))
        self.reload_action.setEnabled(bool(self.current_url))

    def _clear_log(self):
        self.log_text.clear()

    def _log(self, msg: str, tag: str = "dim"):
        color = self.LOG_COLORS.get(tag, self.LOG_COLORS["dim"])
        self.log_text.moveCursor(QTextCursor.MoveOperation.End)
        self.log_text.insertHtml(
            f'<span style="color:{color}; white-space:pre;">{html.escape(msg)}</span><br>'
        )
        self.log_text.moveCursor(QTextCursor.MoveOperation.End)

    def _set_status(self, msg: str):
        self.status_bar.showMessage(msg)

    def _set_loading(self, loading: bool):
        self.go_action.setEnabled(not loading)
        if loading:
            self._set_status("Loading...")

    @staticmethod
    def _ttl_remaining(expire_at: Optional[float]) -> Optional[int]:
        if not isinstance(expire_at, (int, float)):
            return None
        return max(0, int(expire_at - time.time()))

    def _load_settings(self) -> BrowserSettings:
        state = self._read_state()
        raw_settings = state.get("settings", {})
        if not isinstance(raw_settings, dict):
            raw_settings = {}
        return BrowserSettings(
            dns_host=str(raw_settings.get("dns_host", DNS_HOST)),
            dns_port=self._as_int(raw_settings.get("dns_port"), DNS_PORT),
            dns_timeout=self._as_float(raw_settings.get("dns_timeout"), DNS_TIMEOUT),
            http_default_port=self._as_int(
                raw_settings.get("http_default_port"), HTTP_DEFAULT_PORT
            ),
            enable_dns_cache=bool(raw_settings.get("enable_dns_cache", ENABLE_DNS_CACHE)),
            home_url=str(raw_settings.get("home_url", HOME_URL)),
        )

    def _load_list(self, key: str, default: list[str]) -> list[str]:
        state = self._read_state()
        values = state.get(key, default)
        if not isinstance(values, list):
            return list(default)
        return [str(value) for value in values if str(value).strip()]

    def _read_state(self) -> dict[str, Any]:
        try:
            with open(STATE_PATH, "r", encoding="utf-8") as file_obj:
                data = json.load(file_obj)
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save_state(self):
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "settings": {
                "dns_host": self.settings.dns_host,
                "dns_port": self.settings.dns_port,
                "dns_timeout": self.settings.dns_timeout,
                "http_default_port": self.settings.http_default_port,
                "enable_dns_cache": self.settings.enable_dns_cache,
                "home_url": self.settings.home_url,
            },
            "bookmarks": self.bookmarks,
            "history": self.history,
        }
        try:
            with open(STATE_PATH, "w", encoding="utf-8") as file_obj:
                json.dump(data, file_obj, indent=2)
        except OSError as exc:
            self._set_status(f"Could not save browser state: {exc}")

    @staticmethod
    def _as_int(value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _as_float(value: Any, default: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default


def main():
    app = QApplication(sys.argv)
    browser = BrowserApp()
    browser.window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
