import html
import json
import os
import re
import socket
import sys
import time
import base64
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, quote_plus, unquote_plus, urlencode, urlparse
from urllib.request import Request, urlopen

os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu")
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

try:
    from PySide6.QtCore import Qt, QTimer, QUrl
    from PySide6.QtGui import QAction, QIcon
    try:
        from PySide6.QtWebEngineCore import QWebEnginePage
    except ImportError:
        QWebEnginePage = None
    from PySide6.QtWebEngineWidgets import QWebEngineView
    from PySide6.QtWidgets import (
        QApplication,
        QCheckBox,
        QDialog,
        QDialogButtonBox,
        QFileDialog,
        QFormLayout,
        QFrame,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMenu,
        QMessageBox,
        QPushButton,
        QComboBox,
        QStyle,
        QSpinBox,
        QSplitter,
        QStatusBar,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
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
    CONFIGURED_KEYS,
    DEFAULT_BOOKMARKS,
    DNS_HOST,
    DNS_PORT,
    DNS_TIMEOUT,
    ENABLE_DNS_CACHE,
    HOME_URL,
    HTTP_DEFAULT_PORT,
    SEARCH_URL,
    STATE_PATH,
    BROWSER_THEME,
    SEARCH_ENGINE,
    BROWSER_FONT_SIZE,
)
from browser.core.dns_client import DNSClient, DNSError
from browser.core.http_client import HTTPClient, HTTPError, HTTPResponse
from browser.core.url_parser import URLParseError, parse_url


@dataclass
class BrowserSettings:
    dns_host: str = DNS_HOST
    dns_port: int = DNS_PORT
    dns_timeout: float = DNS_TIMEOUT
    http_default_port: int = HTTP_DEFAULT_PORT
    enable_dns_cache: bool = ENABLE_DNS_CACHE
    home_url: str = HOME_URL
    search_url: str = SEARCH_URL
    theme: str = BROWSER_THEME
    font_size: int = BROWSER_FONT_SIZE
    search_engine: str = SEARCH_ENGINE if SEARCH_ENGINE in {"google", "bing"} else "google"


@dataclass
class NetworkEvent:
    url: str
    host: str = ""
    path: str = ""
    dns_server: str = ""
    dns_ip: Optional[str] = None
    dns_from_cache: bool = False
    dns_ttl_remaining: Optional[int] = None
    endpoint: str = ""
    status: str = ""
    duration_ms: int = 0
    error: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    cache_state: str = ""


@dataclass
class BrowserTab:
    view: QWebEngineView
    page: Any = None
    current_url: str = ""
    title: str = "New Tab"
    back_stack: list[str] = field(default_factory=list)
    forward_stack: list[str] = field(default_factory=list)
    last_response: Optional[HTTPResponse] = None
    last_event: Optional[NetworkEvent] = None
    incognito: bool = False
    cookies: dict[str, dict[str, str]] = field(default_factory=dict)


class BrowserPage(QWebEnginePage if QWebEnginePage else object):
    def __init__(self, app: "BrowserApp", tab: BrowserTab):
        if QWebEnginePage:
            super().__init__(tab.view)
        self.browser_app = app
        self.browser_tab = tab

    def acceptNavigationRequest(self, url: QUrl, nav_type, is_main_frame: bool) -> bool:
        link_clicked = getattr(
            getattr(QWebEnginePage, "NavigationType", QWebEnginePage),
            "NavigationTypeLinkClicked",
            None,
        )
        target = url.toString()
        if is_main_frame and target.startswith("internal:"):
            QTimer.singleShot(0, lambda: self.browser_app._handle_internal_url(target, tab=self.browser_tab))
            return False
        if is_main_frame and nav_type == link_clicked:
            QTimer.singleShot(0, lambda: self.browser_app._navigate(target, tab=self.browser_tab))
            return False
        return True


class SettingsDialog(QDialog):
    def __init__(self, parent: QWidget, settings: BrowserSettings):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(500)

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
        self.search_url_input = QLineEdit(settings.search_url)
        self.theme_input = QComboBox()
        self.theme_input.addItems(["light", "dark"])
        self.theme_input.setCurrentText(settings.theme if settings.theme in {"light", "dark"} else "light")
        self.font_size_input = QSpinBox()
        self.font_size_input.setRange(12, 24)
        self.font_size_input.setValue(settings.font_size)
        self.search_engine_input = QComboBox()
        self.search_engine_input.addItems(["google", "bing"])
        self.search_engine_input.setCurrentText(settings.search_engine)

        form = QFormLayout()
        form.addRow("DNS host", self.dns_host_input)
        form.addRow("DNS UDP port", self.dns_port_input)
        form.addRow("DNS timeout", self.dns_timeout_input)
        form.addRow("Default HTTP port", self.http_port_input)
        form.addRow("Home URL", self.home_url_input)
        form.addRow("Search URL", self.search_url_input)
        form.addRow("Search engine", self.search_engine_input)
        form.addRow("Theme", self.theme_input)
        form.addRow("Font size", self.font_size_input)
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
            search_url=self.search_url_input.text().strip() or SEARCH_URL,
            theme=self.theme_input.currentText(),
            font_size=self.font_size_input.value(),
            search_engine=self.search_engine_input.currentText(),
        )


class BrowserApp:
    def __init__(self):
        self.settings = self._load_settings()
        self.bookmarks = self._load_list("bookmarks", DEFAULT_BOOKMARKS)
        self.shortcuts = self._load_shortcuts(DEFAULT_BOOKMARKS)
        self.history = self._load_history()
        self.cookies = self._load_cookies()
        self.network_events: list[NetworkEvent] = []

        self.dns_client = self._make_dns_client()
        self.http_client = HTTPClient()

        self.window = QMainWindow()
        self.window.setWindowTitle("WaterCat Browser")
        self.window.resize(1240, 780)
        self.window.setMinimumSize(980, 620)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)

        self._build_ui()
        self._bind_actions()
        self._apply_style()
        self._new_tab(self.settings.home_url)

    def _build_ui(self):
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.window.setCentralWidget(central)

        self.toolbar = QToolBar("Navigation")
        self.toolbar.setMovable(False)
        self.window.addToolBar(self.toolbar)

        style = QApplication.style()
        self.back_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_ArrowBack), "", self.window)
        self.forward_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_ArrowForward), "", self.window)
        self.reload_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload), "", self.window)
        self.home_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_DirHomeIcon), "", self.window)
        self.back_action.setToolTip("Back")
        self.forward_action.setToolTip("Forward")
        self.reload_action.setToolTip("Reload")
        self.home_action.setToolTip("Home")
        self.new_tab_action = QAction("+", self.window)
        self.incognito_action = QAction("Incognito", self.window)
        self.bookmark_action = QAction("Bookmark", self.window)
        self.history_action = QAction("History", self.window)
        self.bookmarks_action = QAction("Bookmarks", self.window)
        self.add_shortcut_action = QAction("Add Shortcut", self.window)
        self.print_action = QAction("Print", self.window)
        self.download_action = QAction("Download", self.window)
        self.devtools_action = QAction("DevTools", self.window)
        self.settings_action = QAction("Settings", self.window)

        for action in [
            self.back_action,
            self.forward_action,
            self.reload_action,
            self.home_action,
            self.new_tab_action,
        ]:
            self.toolbar.addAction(action)

        self.url_input = QLineEdit()
        self.url_input.setClearButtonEnabled(True)
        self.url_input.setPlaceholderText("Search or enter address")
        self.toolbar.addWidget(self.url_input)

        self.go_action = QAction("Go", self.window)
        self.toolbar.addAction(self.go_action)

        self.menu_button = QPushButton("Menu")
        self.menu = QMenu(self.menu_button)
        self.menu.addAction(self.new_tab_action)
        self.menu.addAction(self.incognito_action)
        self.menu.addSeparator()
        self.menu.addAction(self.history_action)
        self.menu.addAction(self.bookmarks_action)
        self.menu.addAction(self.bookmark_action)
        self.menu.addAction(self.add_shortcut_action)
        self.menu.addSeparator()
        self.menu.addAction(self.print_action)
        self.menu.addAction(self.download_action)
        self.menu.addAction(self.devtools_action)
        self.menu.addSeparator()
        self.menu.addAction(self.settings_action)
        self.menu_button.setMenu(self.menu)
        self.toolbar.addWidget(self.menu_button)

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        root.addWidget(main_splitter, 1)
        main_splitter.addWidget(self.tabs)

        self.devtools_frame = QFrame()
        devtools_layout = QVBoxLayout(self.devtools_frame)
        devtools_layout.setContentsMargins(6, 6, 6, 6)
        devtools_header = QHBoxLayout()
        dt_label = QLabel("DevTools")
        dt_label.setStyleSheet("font-weight:600;font-size:13px;letter-spacing:.04em;text-transform:uppercase;")
        devtools_header.addWidget(dt_label)
        devtools_header.addStretch(1)
        self.close_devtools_btn = QPushButton("✕")
        self.close_devtools_btn.setFixedWidth(34)
        self.close_devtools_btn.setStyleSheet("border-radius:4px;")
        devtools_header.addWidget(self.close_devtools_btn)
        devtools_layout.addLayout(devtools_header)
        self.devtools_tabs = QTabWidget()
        devtools_layout.addWidget(self.devtools_tabs)

        self.network_table = QTableWidget(0, 9)
        self.network_table.setHorizontalHeaderLabels(
            ["URL", "DNS IP", "DNS Cache", "TTL", "Endpoint", "Status", "HTTP Cache", "Time", "Error"]
        )
        self.network_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.devtools_tabs.addTab(self.network_table, "Network")

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.devtools_tabs.addTab(self.details_text, "Headers")

        self.cookies_table = QTableWidget(0, 3)
        self.cookies_table.setHorizontalHeaderLabels(["Domain", "Name", "Value"])
        self.cookies_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.devtools_tabs.addTab(self.cookies_table, "Cookies")

        self.inspector_text = QTextEdit()
        self.inspector_text.setReadOnly(True)
        self.devtools_tabs.addTab(self.inspector_text, "Inspector")

        self.console_text = QTextEdit()
        self.console_text.setReadOnly(True)
        self.devtools_tabs.addTab(self.console_text, "Console")

        self.history_list = QListWidget()
        self.devtools_tabs.addTab(self.history_list, "History")

        self.bookmark_list = QListWidget()
        self.devtools_tabs.addTab(self.bookmark_list, "Bookmarks")

        main_splitter.addWidget(self.devtools_frame)
        main_splitter.setSizes([590, 190])
        self.devtools_frame.hide()

        self.status_bar = QStatusBar()
        self.window.setStatusBar(self.status_bar)
        self._refresh_side_lists()
        self._set_status("Ready.")

    def _bind_actions(self):
        self.url_input.returnPressed.connect(self._on_go)
        self.go_action.triggered.connect(self._on_go)
        self.back_action.triggered.connect(self._go_back)
        self.forward_action.triggered.connect(self._go_forward)
        self.reload_action.triggered.connect(self._reload)
        self.home_action.triggered.connect(lambda: self._navigate(self.settings.home_url))
        self.new_tab_action.triggered.connect(lambda: self._new_tab(self.settings.home_url))
        self.incognito_action.triggered.connect(lambda: self._new_tab(self.settings.home_url, True))
        self.bookmark_action.triggered.connect(self._bookmark_current)
        self.history_action.triggered.connect(self._show_history_page)
        self.bookmarks_action.triggered.connect(self._show_bookmarks_page)
        self.add_shortcut_action.triggered.connect(self._add_shortcut_current)
        self.print_action.triggered.connect(self._print_current)
        self.download_action.triggered.connect(self._download_current)
        self.devtools_action.triggered.connect(self._toggle_devtools)
        self.close_devtools_btn.clicked.connect(lambda: self.devtools_frame.hide())
        self.settings_action.triggered.connect(self._open_settings_page)
        self.tabs.currentChanged.connect(lambda _: self._sync_toolbar())
        self.tabs.tabCloseRequested.connect(self._close_tab)
        self.network_table.itemSelectionChanged.connect(self._show_selected_event)
        self.history_list.itemDoubleClicked.connect(self._open_list_item)
        self.bookmark_list.itemDoubleClicked.connect(self._open_list_item)

    def _theme_colors(self) -> dict[str, str]:
        dark = self.settings.theme == "dark"
        if dark:
            return {
                "window": "#0f172a", "bar": "#1e293b", "panel": "#1e293b", "panel2": "#334155",
                "text": "#f1f5f9", "muted": "#94a3b8", "border": "#475569", "border2": "#334155",
                "tab": "#334155", "tab_selected": "#0f172a", "input": "#0f172a",
                "accent": "#3b82f6", "accent_hover": "#2563eb",
                "error": "#ef4444", "warning": "#f59e0b", "success": "#22c55e",
                "incognito": "#8b5cf6",
            }
        return {
            "window": "#f8fafc", "bar": "#e8edf3", "panel": "#ffffff", "panel2": "#f9fafb",
            "text": "#0f172a", "muted": "#64748b", "border": "#cbd5e1", "border2": "#e2e8f0",
            "tab": "#e2e8f0", "tab_selected": "#ffffff", "input": "#ffffff",
            "accent": "#2563eb", "accent_hover": "#1d4ed8",
            "error": "#ef4444", "warning": "#f97316", "success": "#22c55e",
            "incognito": "#8b5cf6",
        }

    def _apply_style(self):
        c = self._theme_colors()
        self.window.setStyleSheet(
            f"""
            QMainWindow {{ background: {c['window']}; color: {c['text']}; }}
            QToolBar {{
                background: {c['bar']};
                border-bottom: 1px solid {c['border']};
                spacing: 4px;
                padding: 4px 8px;
            }}
            QToolButton {{
                color: {c['text']};
                background: transparent;
                border: 1px solid transparent;
                border-radius: 6px;
                padding: 5px 7px;
            }}
            QToolButton:hover {{ border-color: {c['border']}; background: {c['panel2']}; }}
            QToolButton:pressed {{ background: {c['tab']}; }}
            QPushButton {{
                color: {c['text']};
                background: {c['panel2']};
                border: 1px solid {c['border']};
                border-radius: 6px;
                padding: 5px 10px;
            }}
            QPushButton:hover {{ border-color: {c['accent']}; }}
            QPushButton::menu-indicator {{ image: none; width: 0; }}
            QLineEdit {{
                color: {c['text']};
                background: {c['input']};
                border: 1px solid {c['border']};
                border-radius: 16px;
                padding: 7px 14px;
                font-size: 15px;
                selection-background-color: {c['accent']};
            }}
            QLineEdit:focus {{ border: 2px solid {c['accent']}; padding: 6px 13px; }}
            QTabWidget::pane {{
                border-top: 1px solid {c['border']};
                background: {c['panel']};
            }}
            QTabBar::tab {{
                color: {c['muted']};
                background: {c['tab']};
                border: 1px solid {c['border']};
                border-bottom: 0;
                padding: 7px 12px;
                margin-right: 2px;
                min-width: 80px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }}
            QTabBar::tab:hover {{ color: {c['text']}; }}
            QTabBar::tab:selected {{
                color: {c['text']};
                background: {c['tab_selected']};
                border-color: {c['border']};
            }}
            QFrame {{
                background: {c['panel']};
                border: 1px solid {c['border']};
            }}
            QTableWidget, QListWidget, QTextEdit {{
                color: {c['text']};
                background: {c['panel']};
                border: 1px solid {c['border']};
                gridline-color: {c['border2']};
                selection-background-color: {c['accent']};
            }}
            QHeaderView::section {{
                color: {c['text']};
                background: {c['bar']};
                border: 0;
                border-right: 1px solid {c['border']};
                border-bottom: 1px solid {c['border']};
                padding: 5px;
            }}
            QComboBox, QSpinBox {{
                color: {c['text']};
                background: {c['input']};
                border: 1px solid {c['border']};
                border-radius: 6px;
                padding: 5px 8px;
            }}
            QMenu {{
                color: {c['text']};
                background: {c['panel']};
                border: 1px solid {c['border']};
                border-radius: 8px;
                padding: 4px 0;
            }}
            QMenu::item {{ padding: 7px 22px; border-radius: 4px; margin: 2px 4px; }}
            QMenu::item:selected {{ background: {c['accent']}; color: white; }}
            QMenu::separator {{ height: 1px; background: {c['border']}; margin: 4px 0; }}
            QStatusBar {{
                color: {c['muted']};
                background: {c['bar']};
                border-top: 1px solid {c['border']};
            }}
            """
        )

    def _new_tab(self, url: str = "", incognito: bool = False):
        view = QWebEngineView()
        tab = BrowserTab(view=view, incognito=incognito)
        view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        view.customContextMenuRequested.connect(lambda pos, v=view: self._show_context_menu(v, pos))
        if QWebEnginePage:
            tab.page = BrowserPage(self, tab)
            view.setPage(tab.page)
        index = self.tabs.addTab(view, "\U0001F576 Incognito" if incognito else "New Tab")
        self.tabs.setCurrentIndex(index)
        view.setProperty("browser_tab", tab)
        if url:
            self._navigate(url, tab=tab, add_history=not incognito)
        else:
            self._render_new_tab(tab)
        self._sync_toolbar()

    def _close_tab(self, index: int):
        if self.tabs.count() == 1:
            self._new_tab(self.settings.home_url)
        widget = self.tabs.widget(index)
        self.tabs.removeTab(index)
        if widget:
            widget.deleteLater()
        self._sync_toolbar()

    def _current_tab(self) -> Optional[BrowserTab]:
        widget = self.tabs.currentWidget()
        if widget is None:
            return None
        return widget.property("browser_tab")

    def _on_go(self):
        self._navigate(self._resolve_address(self.url_input.text().strip()))

    def _resolve_address(self, value: str) -> str:
        if not value:
            return self.settings.home_url
        if value.startswith("internal:"):
            return value
        parsed = urlparse(value if "://" in value else f"http://{value}")
        host = parsed.hostname or ""
        if parsed.scheme in {"http", "https"} and host and (
            "." in host or host == "localhost" or self._is_ipv4(host)
        ):
            return parsed.geturl()
        if " " in value:
            return self.settings.search_url.replace("{query}", quote_plus(value))
        return self.settings.search_url.replace("{query}", quote_plus(value))

    def _navigate(
        self,
        url: str,
        tab: Optional[BrowserTab] = None,
        add_history: bool = True,
        record_navigation: bool = True,
    ):
        tab = tab or self._current_tab()
        if tab is None:
            return

        start = time.time()
        event = NetworkEvent(url=url, dns_server=f"{self.settings.dns_host}:{self.settings.dns_port}")
        self._set_status("Resolving DNS...")

        try:
            if url.startswith("internal:home"):
                self._render_new_tab(tab)
                if record_navigation and tab.current_url and tab.current_url != url:
                    tab.back_stack.append(tab.current_url)
                    tab.forward_stack.clear()
                tab.current_url = "internal:home"
                tab.title = "New Tab"
                self._update_tab_label(tab)
                self._set_status("Ready.")
                return

            if url.startswith("internal:"):
                self._handle_internal_url(url, tab, record_navigation=record_navigation)
                return

            try:
                parsed = parse_url(url)
            except URLParseError as exc:
                event.error = str(exc)
                self._record_event(event)
                self._render_error(tab, "Invalid URL", str(exc))
                return

            event.url = parsed.raw
            event.host = parsed.host
            event.path = parsed.path

            if self._is_ipv4(parsed.host):
                dns_ip = parsed.host
                dns_from_cache = False
                dns_ttl_remaining = None
            else:
                try:
                    dns_result = self.dns_client.resolve(parsed.host)
                except DNSError as exc:
                    event.status = "404 Not Found"
                    event.error = str(exc)
                    self._record_event(event)
                    self._render_error(tab, "404 Not Found", str(exc), code=404)
                    return
                dns_ip = dns_result.ip
                dns_from_cache = dns_result.from_cache
                dns_ttl_remaining = self._ttl_remaining(dns_result.expire_at)

            event.dns_ip = dns_ip
            event.dns_from_cache = dns_from_cache
            event.dns_ttl_remaining = dns_ttl_remaining
            http_port = parsed.port if parsed.port not in (80, 443) else self.settings.http_default_port
            event.endpoint = f"{dns_ip}:{http_port}"
            self._set_status("Connecting...")

            request_headers = self._request_headers(parsed.host, tab)
            event.request_headers = dict(request_headers)
            request_path = self._request_path(parsed.raw, parsed.path)
            self._set_status("Loading...")
            try:
                response = self.http_client.get(
                    ip=dns_ip,
                    port=http_port,
                    path=request_path,
                    host=parsed.host,
                    extra_headers=request_headers,
                )
            except HTTPError as exc:
                event.status = self._http_error_status(str(exc))
                event.error = str(exc)
                self._record_event(event)
                self._render_error(tab, event.status, str(exc), code=self._status_code(event.status))
                return

            self._store_cookies(parsed.host, response, tab)
            event.status = f"{response.status_code} {response.status_text}".strip()
            event.response_headers = dict(response.headers)
            event.duration_ms = int((time.time() - start) * 1000)
            tab.last_response = response
            tab.last_event = event
            self._render_response(tab, response, dns_ip, http_port, request_path)
            self._record_event(event)

            if record_navigation and tab.current_url and tab.current_url != parsed.raw:
                tab.back_stack.append(tab.current_url)
                tab.forward_stack.clear()
            tab.current_url = parsed.raw
            tab.title = self._title_for(parsed.host, tab.incognito)
            self._update_tab_label(tab)
            if add_history and not tab.incognito:
                self._add_history(parsed.raw)
            self._save_state()
            self._set_status(f"{event.status} | {event.duration_ms}ms")
        finally:
            self._refresh_all()
            self._sync_toolbar()

    def _render_response(self, tab: BrowserTab, response: HTTPResponse, ip: str, port: int, path: str):
        content_type = response.headers.get("Content-Type", "").lower()
        base_url = QUrl(f"http://{ip}:{port}{path}")

        # Determine HTTP cache state
        if response.status_code == 304:
            cache_state = "304"
        elif response.headers.get("ETag"):
            cache_state = "hit"
        else:
            cache_state = "miss"

        if tab.last_event:
            tab.last_event.cache_state = cache_state

        if response.is_ok and "text/html" in content_type:
            html_body = self._load_same_origin_assets(response.body, ip, port, tab)
            tab.view.setHtml(html_body, base_url)
        elif response.is_ok:
            self._render_download_page(tab, response)
        else:
            title = f"{response.status_code} {response.status_text}".strip()
            self._render_error(tab, title or "HTTP Error", response.body[:3000], code=response.status_code)

    def _load_same_origin_assets(self, html_body: str, ip: str, port: int, tab: BrowserTab) -> str:
        """Inline same-origin CSS as <style> tags and convert same-origin images to data URIs."""
        host = tab.last_event.host if tab.last_event else ""

        css_link_patterns = [
            r'<link\s+[^>]*rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\'][^>]*>',
            r'<link\s+[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\']stylesheet["\'][^>]*>',
        ]
        img_pattern = r'<img\s+[^>]*src=["\']([^"\']+)["\'][^>]*>'

        def _is_same_origin(url: str) -> bool:
            lower = url.lower()
            if lower.startswith(("http://", "https://")):
                return False
            return url.startswith("/") or (
                not url.startswith("//")
                and not url.startswith("data:")
                and not url.startswith("javascript:")
                and "#" not in url.split("/")[0]
            )

        def _skip_external(url: str, tag: str) -> str:
            if tab.last_event:
                tab.last_event.error += f"; skipped external: {url}" if tab.last_event.error else f"skipped external: {url}"
            return tag

        for pattern in css_link_patterns:
            matches = list(re.finditer(pattern, html_body, re.I))
            for match in reversed(matches):
                full_tag = match.group(0)
                href = match.group(1)
                if not _is_same_origin(href):
                    html_body = html_body[:match.start()] + _skip_external(href, full_tag) + html_body[match.end():]
                    continue
                try:
                    resp = self.http_client.get(ip=ip, port=port, path=href, host=host)
                    if resp.is_ok:
                        replacement = f"<style>{resp.body}</style>"
                        html_body = html_body[:match.start()] + replacement + html_body[match.end():]
                except Exception:
                    pass

        img_matches = list(re.finditer(img_pattern, html_body, re.I))
        for match in reversed(img_matches):
            full_tag = match.group(0)
            src = match.group(1)
            if src.startswith("data:") or not _is_same_origin(src):
                if not src.startswith("data:") and _is_same_origin(src) is False:
                    html_body = html_body[:match.start()] + _skip_external(src, full_tag) + html_body[match.end():]
                continue
            try:
                resp = self.http_client.get(ip=ip, port=port, path=src, host=host)
                if resp.is_ok:
                    mime = resp.headers.get("Content-Type", "application/octet-stream")
                    encoded = base64.b64encode(resp.body_bytes).decode("ascii")
                    data_uri = f"data:{mime};base64,{encoded}"
                    new_tag = full_tag.replace(f'src="{src}"', f'src="{data_uri}"', 1).replace(f"src='{src}'", f'src="{data_uri}"', 1)
                    html_body = html_body[:match.start()] + new_tag + html_body[match.end():]
            except Exception:
                pass

        return html_body

    def _render_new_tab(self, tab: BrowserTab):
        logo_path = Path(__file__).resolve().parents[1] / "assets" / "watercat.png"
        logo_src = self._image_data_uri(logo_path)
        shortcuts = "".join(
            "<div class='shortcut-wrap'><a class='shortcut' href='{url}'><span>{letter}</span><b>{label}</b></a>"
            "<a class='shortcut-delete' href='internal:delete-shortcut?url={encoded}'>Delete</a></div>".format(
                url=html.escape(self._shortcut_url(item)),
                encoded=quote_plus(self._shortcut_url(item)),
                letter=html.escape(self._shortcut_label(item)[:1].upper() or "W"),
                label=html.escape(self._shortcut_label(item)),
            )
            for item in self.shortcuts[:10]
        )
        brand_inner = (
            f"<img src='{html.escape(logo_src)}'>" if logo_src
            else "<h1 style='color:var(--accent,#2563eb)'>WaterCat</h1>"
        )
        body = f"""
        <main class="home">
          <div class="brand">
            {brand_inner}
            <span class="brand-tagline">Browse the web, your way.</span>
          </div>
          <form class="home-search" action="internal:go" method="get">
            <input name="q" autofocus placeholder="Search with {html.escape(self.settings.search_engine.title())} or enter address">
          </form>
          <section class="shortcuts">
            {shortcuts}
            <form class="shortcut-add" action="internal:add-shortcut" method="get">
              <input name="name" placeholder="Name">
              <input name="url" placeholder="URL">
              <button type="submit">Add</button>
            </form>
          </section>
        </main>
        """
        tab.view.setHtml(
            self._page_html(
                "WaterCat Browser",
                body,
            )
        )

    def _render_search_page(self, tab: BrowserTab, url: str):
        query = ""
        if "q=" in url:
            query = unquote_plus(url.split("q=", 1)[1])
        matches = [
            item
            for item in self.bookmarks + [entry["url"] for entry in self.history]
            if query.lower() in item.lower()
        ][:12]
        local_links = "".join(
            f"<div class='card'><h3><a href='{html.escape(item)}'>{html.escape(item)}</a></h3></div>"
            for item in matches
        )
        if not local_links:
            local_links = "<p class='muted' style='margin:16px 48px'>No local bookmark/history matches.</p>"
        engine_url = self._engine_search_url(query)
        engine_results = "".join(
            f"<div class='result'><b>{html.escape(title)}</b><p>{html.escape(url)}</p></div>"
            for title, url in self._external_search_results(query)
        )
        engine_name = html.escape(self.settings.search_engine.title())
        body = (
            f"<div class='search-header'>"
            f"<h1>Search results for &ldquo;{html.escape(query)}&rdquo;</h1>"
            f"<span class='search-engine'>{engine_name}</span>"
            f"</div>"
            f"<div class='result'><b>{engine_name} results page</b>"
            f"<p>{html.escape(engine_url)}</p></div>"
            f"{engine_results}"
            f"<h2 style='margin:24px 48px 12px'>Local matches</h2>"
            f"{local_links}"
        )
        tab.view.setHtml(self._page_html("Search", body))

    def _render_error(self, tab: BrowserTab, title: str, message: str, code: int = 500):
        c = self._theme_colors()
        if code == 404 or "not found" in title.lower():
            icon = "&#128269;"
            hint = "The page you're looking for doesn't exist. Check the URL or try navigating from the home page."
        elif "timeout" in title.lower() or code == 504:
            icon = "&#9203;"
            hint = "The server took too long to respond. Check your network connection and try again."
        elif "rate" in title.lower() or code == 429:
            icon = "&#9888;&#65039;"
            hint = "Too many requests. Wait a moment before trying again."
        elif "invalid" in title.lower() or "url" in title.lower():
            icon = "&#9888;&#65039;"
            hint = "The URL format is invalid. Make sure it starts with http:// and includes a valid host."
        elif "bad gateway" in title.lower() or code == 502:
            icon = "&#128268;"
            hint = "The server returned an invalid response. The upstream service may be down."
        else:
            icon = "&#128683;"
            hint = "Check the DNS record, server IP, port, or whether the HTTP server is running."

        body = (
            "<section class='error-page'>"
            f"<div class='error-icon'>{icon}</div>"
            f"<div class='error-code'>{code}</div>"
            f"<h1>{html.escape(title)}</h1>"
            f"<pre>{html.escape(message)}</pre>"
            f"<p class='error-hint'>{hint}</p>"
            "</section>"
        )
        tab.view.setHtml(self._page_html(title, body, error=True))
        tab.title = title
        self._update_tab_label(tab)
        self._set_status(title)

    def _render_download_page(self, tab: BrowserTab, response: HTTPResponse):
        size = len(response.body_bytes)
        content_type = html.escape(response.headers.get("Content-Type", "application/octet-stream"))
        size_str = f"{size:,}" if size >= 1000 else str(size)
        body = (
            "<div class='download-page'>"
            "<div class='download-card'>"
            "<div class='download-icon'>&#128229;</div>"
            "<h1>Download ready</h1>"
            f"<p class='download-meta'>{size_str} bytes &middot; {content_type}</p>"
            "<p class='muted'>Use Menu &gt; Download to save this response.</p>"
            "</div></div>"
        )
        tab.view.setHtml(self._page_html("Download ready", body))

    def _open_settings_page(self):
        self._show_settings_tab()

    def _show_settings_tab(self):
        self._new_tab("", False)
        tab = self._current_tab()
        if not tab:
            return
        body = f"""
        <h1>Settings</h1>
        <div class="settings-section">
          <h2>Appearance</h2>
          <div class="settings-card">
            <form class="settings-form" action="internal:save-settings" method="get" style="margin:0;border:0;padding:0">
              <label>Theme
                <select name="theme">
                  <option value="light" {'selected' if self.settings.theme == 'light' else ''}>Light</option>
                  <option value="dark" {'selected' if self.settings.theme == 'dark' else ''}>Dark</option>
                </select>
              </label>
              <label>Font size <input type="number" min="12" max="24" name="font_size" value="{self.settings.font_size}"></label>
              <label>Search engine
                <select name="search_engine">
                  <option value="google" {'selected' if self.settings.search_engine == 'google' else ''}>Google</option>
                  <option value="bing" {'selected' if self.settings.search_engine == 'bing' else ''}>Bing</option>
                </select>
              </label>
              <button type="submit">Save Settings</button>
            </form>
          </div>
        </div>
        <div class="settings-section">
          <h2>Connection</h2>
          <div class="settings-readonly">
            <p><b>DNS:</b> {html.escape(self.settings.dns_host)}:{self.settings.dns_port}</p>
            <p><b>HTTP default port:</b> {self.settings.http_default_port}</p>
            <p><b>Home:</b> {html.escape(self.settings.home_url)}</p>
            <p><b>Search URL:</b> {html.escape(self.settings.search_url)}</p>
            <p><b>DNS cache:</b> {'enabled' if self.settings.enable_dns_cache else 'disabled'}</p>
          </div>
        </div>
        """
        tab.view.setHtml(self._page_html("Settings", body))
        tab.title = "Settings"
        self._update_tab_label(tab)

    def _page_html(self, title: str, body: str, error: bool = False) -> str:
        c = self._theme_colors()
        error_color = c["error"] if error else c["text"]
        return (
            "<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>{html.escape(title)}</title>"
            f"<style>body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;color:{c['text']};background:{c['window']};font-size:{self.settings.font_size}px}}"
            "body>h1,body>p,body>h2,body>ul,body>pre,body>.result{margin-left:48px;margin-right:48px}"
            "body>h1{margin-top:48px}"
            f"h1{{color:{error_color}}}pre{{white-space:pre-wrap;background:{c['panel2']};border:1px solid {c['border']};padding:16px;border-radius:8px}}"
            f"a{{color:{c['accent']};text-decoration:none}}a:hover{{color:{c['accent_hover']};text-decoration:underline}}"
            f".home{{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:28px;padding-bottom:80px;background:linear-gradient(180deg,{c['window']} 0%,{c['panel2']} 100%)}}"
            ".brand{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px}.brand img{width:min(420px,60vw);height:auto;object-fit:contain}.brand h1{font-size:44px;margin:0}"
            f".brand-tagline{{color:{c['muted']};font-size:15px;margin-top:2px;letter-spacing:.02em}}"
            f".home-search{{width:min(680px,65vw);background:{c['panel']};border:2px solid {c['border']};box-shadow:0 8px 28px rgba(15,23,42,.12);border-radius:16px;padding:6px 8px;transition:border-color .15s,box-shadow .15s}}"
            f".home-search:focus-within{{border-color:{c['accent']};box-shadow:0 8px 28px rgba(37,99,235,.18)}}"
            f".home-search input{{width:100%;box-sizing:border-box;border:0;outline:0;background:transparent;color:{c['text']};font-size:17px;padding:12px 10px}}"
            ".shortcuts{display:flex;gap:20px;flex-wrap:wrap;justify-content:center;max-width:860px}"
            f".shortcut-wrap{{width:96px;text-align:center}}.shortcut{{display:block;text-decoration:none;color:{c['text']}}}.shortcut span{{display:grid;place-items:center;width:64px;height:64px;margin:0 auto 8px;background:{c['panel2']};border:1px solid {c['border']};border-radius:16px;font-size:26px;transition:transform .12s,border-color .12s}}.shortcut:hover span{{transform:translateY(-2px);border-color:{c['accent']}}}"
            f".shortcut b{{font-size:13px;font-weight:600}}.shortcut-delete{{display:block;margin-top:4px;font-size:11px;color:{c['muted']};text-decoration:none}}.shortcut-delete:hover{{color:{c['error']}}}"
            f".shortcut-add{{width:170px;background:{c['panel']};border:1px solid {c['border']};border-radius:14px;padding:10px;display:flex;flex-direction:column;gap:6px}}.shortcut-add input,.settings-form input,.settings-form select{{background:{c['input']};color:{c['text']};border:1px solid {c['border']};border-radius:8px;padding:8px;font-size:14px}}.shortcut-add input:focus,.settings-form input:focus,.settings-form select:focus{{border-color:{c['accent']};outline:none}}.shortcut-add button,.settings-form button{{background:{c['accent']};color:white;border:0;border-radius:8px;padding:9px;font-size:14px;cursor:pointer;transition:background .12s}}.shortcut-add button:hover,.settings-form button:hover{{background:{c['accent_hover']}}}"
            f".settings-section{{margin:24px 48px;max-width:760px}}.settings-section h2{{color:{c['muted']};font-size:13px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px}}"
            f".settings-card{{background:{c['panel']};border:1px solid {c['border']};border-radius:12px;padding:18px;margin-bottom:16px}}"
            f".settings-form{{margin:24px 48px;background:{c['panel']};border:1px solid {c['border']};border-radius:12px;padding:18px;max-width:760px;display:flex;flex-direction:column;gap:14px}}.settings-form label{{display:flex;justify-content:space-between;gap:18px;align-items:center}}"
            f".settings-readonly{{margin:24px 48px;background:{c['panel2']};border:1px solid {c['border']};border-radius:12px;padding:18px;max-width:760px;display:flex;flex-direction:column;gap:10px}}"
            f".data-table{{margin:24px 48px;border-collapse:collapse;width:calc(100% - 96px);background:{c['panel']};border:1px solid {c['border']};border-radius:12px;overflow:hidden}}.data-table th,.data-table td{{border-bottom:1px solid {c['border2']};padding:12px;text-align:left}}.data-table th{{color:{c['muted']};font-size:13px;text-transform:uppercase;letter-spacing:.04em;background:{c['panel2']}}}.data-table tbody tr:nth-child(even){{background:{c['panel2']}}}.data-table tbody tr:hover{{background:{c['border2']}}}"
            f".muted{{color:{c['muted']}}}.result{{background:{c['panel']};border:1px solid {c['border']};border-radius:10px;padding:16px;margin:16px 48px}}"
            f".error-page{{margin:64px 48px;max-width:700px;text-align:center}}.error-icon{{font-size:64px;margin-bottom:16px}}.error-code{{font-size:72px;font-weight:800;color:{error_color};line-height:1}}.error-hint{{color:{c['muted']};margin-top:16px;font-size:15px}}"
            f".card{{background:{c['panel']};border:1px solid {c['border']};border-radius:12px;padding:16px;margin:12px 48px;transition:border-color .12s}}.card:hover{{border-color:{c['accent']}}}"
            f".card h3{{margin:0 0 6px;font-size:15px}}.card p{{margin:0;color:{c['muted']};font-size:13px}}"
            f".download-page{{margin:48px;max-width:600px}}.download-card{{background:{c['panel']};border:1px solid {c['border']};border-radius:12px;padding:24px;text-align:center}}.download-icon{{font-size:48px;margin-bottom:12px}}.download-meta{{color:{c['muted']};font-size:14px;margin:8px 0}}"
            f".search-header{{margin:32px 48px 16px}}.search-header h1{{margin:0}}.search-engine{{display:inline-block;background:{c['panel2']};border:1px solid {c['border']};border-radius:20px;padding:4px 14px;font-size:13px;color:{c['muted']};margin-top:8px}}"
            "</style>"
            "<script>"
            "document.addEventListener('submit',function(e){"
            "var f=e.target;if(!f.action||!f.action.startsWith('internal:'))return;"
            "e.preventDefault();var p=new URLSearchParams(new FormData(f));"
            "window.location.href=f.action+'?'+p.toString();"
            "});"
            "</script>"
            "</head><body>"
            f"{body}</body></html>"
        )

    def _request_headers(self, host: str, tab: BrowserTab) -> dict[str, str]:
        cookies = tab.cookies if tab.incognito else self.cookies
        domain_cookies = cookies.get(host, {})
        if not domain_cookies:
            return {}
        cookie_value = "; ".join(f"{name}={value}" for name, value in domain_cookies.items())
        return {"Cookie": cookie_value}

    def _store_cookies(self, host: str, response: HTTPResponse, tab: BrowserTab):
        if not response.set_cookie_headers:
            return
        jar = tab.cookies if tab.incognito else self.cookies
        jar.setdefault(host, {})
        for header in response.set_cookie_headers:
            pair = header.split(";", 1)[0]
            if "=" in pair:
                name, value = pair.split("=", 1)
                jar[host][name.strip()] = value.strip()
        if not tab.incognito:
            self._save_state()

    def _download_current(self):
        tab = self._current_tab()
        if not tab or not tab.last_response:
            QMessageBox.information(self.window, "Download", "No loaded response to save.")
            return
        filename = self._download_filename(tab)
        path, _ = QFileDialog.getSaveFileName(self.window, "Save response", filename)
        if not path:
            return
        data = tab.last_response.body_bytes or tab.last_response.body.encode("utf-8")
        try:
            Path(path).write_bytes(data)
        except OSError as exc:
            QMessageBox.critical(self.window, "Download failed", str(exc))
            return
        self._set_status(f"Saved {path}")

    def _download_filename(self, tab: BrowserTab) -> str:
        if tab.last_response:
            disposition = tab.last_response.headers.get("Content-Disposition", "")
            match = re.search(r'filename="?([^";]+)"?', disposition)
            if match:
                return match.group(1)
        if tab.current_url:
            tail = tab.current_url.rstrip("/").rsplit("/", 1)[-1]
            if tail and "." in tail:
                return tail
        return "download.html"

    def _bookmark_current(self):
        tab = self._current_tab()
        if not tab or not tab.current_url:
            return
        if tab.current_url not in self.bookmarks:
            self.bookmarks.insert(0, tab.current_url)
            self._save_state()
        self._refresh_all()

    def _add_shortcut_current(self):
        tab = self._current_tab()
        if not tab or not tab.current_url or tab.current_url.startswith("internal:"):
            QMessageBox.information(self.window, "Shortcut", "Open a web page before adding a shortcut.")
            return
        if tab.current_url not in self.shortcuts:
            self.shortcuts.insert(0, tab.current_url)
            self.shortcuts = self.shortcuts[:12]
            self._save_state()
        self._render_new_tab(tab) if tab.current_url == "internal:home" else None
        self._set_status("Shortcut added.")

    def _show_history_page(self):
        self._new_tab("", False)
        tab = self._current_tab()
        if not tab:
            return
        rows = "".join(
            "<tr><td>{time}</td><td><a href='{url}'>{url}</a></td></tr>".format(
                time=html.escape(entry.get("visited_at", "")),
                url=html.escape(entry.get("url", "")),
            )
            for entry in self.history
        ) or "<tr><td colspan='2'>No history yet.</td></tr>"
        body = (
            "<h1>History</h1>"
            "<table class='data-table'><thead><tr><th>Visited at</th><th>URL</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )
        tab.view.setHtml(self._page_html("History", body))
        tab.current_url = "internal:history"
        tab.title = "History"
        self._update_tab_label(tab)

    def _show_bookmarks_page(self):
        self._new_tab("", False)
        tab = self._current_tab()
        if not tab:
            return
        cards = "".join(
            f"<div class='card'><h3><a href='{html.escape(url)}'>{html.escape(url)}</a></h3></div>"
            for url in self.bookmarks
        ) or "<p class='muted' style='margin:24px 48px'>No bookmarks yet.</p>"
        tab.view.setHtml(self._page_html("Bookmarks", f"<h1>Bookmarks</h1>{cards}"))
        tab.current_url = "internal:bookmarks"
        tab.title = "Bookmarks"
        self._update_tab_label(tab)

    def _print_current(self):
        tab = self._current_tab()
        if not tab:
            return
        path, _ = QFileDialog.getSaveFileName(self.window, "Print to PDF", "page.pdf")
        if path:
            tab.view.page().printToPdf(path)
            self._set_status(f"Printed to {path}")

    def _show_context_menu(self, view: QWebEngineView, pos):
        tab = view.property("browser_tab")
        menu = QMenu(view)
        inspect_action = menu.addAction("Inspect HTML")
        reload_action = menu.addAction("Reload")
        chosen = menu.exec(view.mapToGlobal(pos))
        if chosen == inspect_action and tab:
            self.devtools_frame.show()
            inspector_index = self.devtools_tabs.indexOf(self.inspector_text)
            if inspector_index >= 0:
                self.devtools_tabs.setCurrentIndex(inspector_index)
            view.page().toHtml(
                lambda source: self.inspector_text.setHtml(self._highlight_html(source))
            )
        elif chosen == reload_action and tab:
            self._navigate(tab.current_url, tab=tab, add_history=False, record_navigation=False)

    def _go_back(self):
        tab = self._current_tab()
        if tab and tab.back_stack:
            target = tab.back_stack.pop()
            if tab.current_url:
                tab.forward_stack.append(tab.current_url)
            self._navigate(target, tab=tab, add_history=False, record_navigation=False)

    def _go_forward(self):
        tab = self._current_tab()
        if tab and tab.forward_stack:
            target = tab.forward_stack.pop()
            if tab.current_url:
                tab.back_stack.append(tab.current_url)
            self._navigate(target, tab=tab, add_history=False, record_navigation=False)

    def _reload(self):
        tab = self._current_tab()
        if tab and tab.current_url:
            self._navigate(tab.current_url, tab=tab, add_history=False, record_navigation=False)

    def _toggle_devtools(self):
        self.devtools_frame.setVisible(not self.devtools_frame.isVisible())
        self._refresh_all()

    def _handle_internal_url(
        self,
        url: str,
        tab: Optional[BrowserTab] = None,
        record_navigation: bool = True,
    ):
        tab = tab or self._current_tab()
        if tab is None:
            return
        parsed = urlparse(url)
        action = parsed.path or parsed.netloc
        values = parse_qs(parsed.query)

        if action == "go":
            target = values.get("q", [""])[0]
            self._navigate(self._resolve_address(target), tab=tab, record_navigation=record_navigation)
            return
        if action == "search":
            self._render_search_page(tab, url)
            self._mark_internal_tab(tab, url, "Search", record_navigation)
            return
        if action == "home":
            self._render_new_tab(tab)
            self._mark_internal_tab(tab, "internal:home", "New Tab", record_navigation)
            return
        if action == "add-shortcut":
            target = values.get("url", [""])[0].strip()
            name = values.get("name", [""])[0].strip()
            if target:
                target_url = self._resolve_address(target)
                if target_url not in [self._shortcut_url(item) for item in self.shortcuts]:
                    self.shortcuts.insert(
                        0,
                        {
                            "name": name or self._short_label(target_url),
                            "url": target_url,
                        },
                    )
                    self.shortcuts = self.shortcuts[:12]
                    self._save_state()
            self._render_new_tab(tab)
            self._mark_internal_tab(tab, "internal:home", "New Tab", record_navigation)
            return
        if action == "delete-shortcut":
            target = values.get("url", [""])[0]
            before = len(self.shortcuts)
            self.shortcuts = [
                item for item in self.shortcuts if self._shortcut_url(item) != target
            ]
            if len(self.shortcuts) != before:
                self._save_state()
            self._render_new_tab(tab)
            self._mark_internal_tab(tab, "internal:home", "New Tab", record_navigation)
            return
        if action == "save-settings":
            self._apply_settings_from_query(values)
            self._show_settings_tab()
            return

    def _mark_internal_tab(
        self,
        tab: BrowserTab,
        url: str,
        title: str,
        record_navigation: bool = True,
    ):
        if record_navigation and tab.current_url and tab.current_url != url:
            tab.back_stack.append(tab.current_url)
            tab.forward_stack.clear()
        tab.current_url = url
        tab.title = title
        self._update_tab_label(tab)
        self._sync_toolbar()

    def _apply_settings_from_query(self, values: dict[str, list[str]]):
        theme = values.get("theme", [self.settings.theme])[0]
        font_size = values.get("font_size", [str(self.settings.font_size)])[0]
        search_engine = values.get("search_engine", [self.settings.search_engine])[0]
        self.settings.theme = self._normalize_theme(theme)
        self.settings.font_size = max(12, min(24, self._as_int(font_size, self.settings.font_size)))
        self.settings.search_engine = self._normalize_search_engine(search_engine)
        self._apply_style()
        self._save_state()

    def _toggle_theme(self):
        self.settings.theme = "light" if self.settings.theme == "dark" else "dark"
        self._apply_style()
        self._save_state()

    def _open_list_item(self, item: QListWidgetItem):
        url = item.data(Qt.ItemDataRole.UserRole) or item.text()
        self._navigate(url)

    def _record_event(self, event: NetworkEvent):
        self.network_events.insert(0, event)
        self.network_events = self.network_events[:200]

    def _refresh_all(self):
        self._refresh_network_table()
        self._refresh_cookies_table()
        self._refresh_inspector()
        self._refresh_console()
        self._refresh_side_lists()

    def _refresh_network_table(self):
        self.network_table.setRowCount(0)
        c = self._theme_colors()
        for row, event in enumerate(self.network_events):
            self.network_table.insertRow(row)
            values = [
                event.url,
                event.dns_ip or "",
                "yes" if event.dns_from_cache else "no",
                f"{event.dns_ttl_remaining}s" if event.dns_ttl_remaining is not None else "",
                event.endpoint,
                event.status,
                event.cache_state,
                f"{event.duration_ms}ms" if event.duration_ms else "",
                event.error,
            ]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 5 and event.status:
                    try:
                        code = int(event.status.split(" ", 1)[0])
                        if 200 <= code < 300:
                            item.setForeground(Qt.GlobalColor.darkGreen)
                        elif 300 <= code < 400:
                            item.setForeground(Qt.GlobalColor.darkYellow)
                        elif code >= 400:
                            item.setForeground(Qt.GlobalColor.darkRed)
                    except (ValueError, IndexError):
                        pass
                if col == 8 and event.error:
                    item.setForeground(Qt.GlobalColor.darkRed)
                self.network_table.setItem(row, col, item)

    def _refresh_cookies_table(self):
        self.cookies_table.setRowCount(0)
        row = 0
        for domain, values in self.cookies.items():
            for name, value in values.items():
                self.cookies_table.insertRow(row)
                for col, text in enumerate([domain, name, value]):
                    self.cookies_table.setItem(row, col, QTableWidgetItem(text))
                row += 1

    def _refresh_side_lists(self):
        self.history_list.clear()
        for entry in self.history:
            url = entry.get("url", "")
            item = QListWidgetItem(f"{entry.get('visited_at', '')}  {url}")
            item.setData(Qt.ItemDataRole.UserRole, url)
            self.history_list.addItem(item)

        self.bookmark_list.clear()
        for url in self.bookmarks:
            item = QListWidgetItem(url)
            item.setData(Qt.ItemDataRole.UserRole, url)
            self.bookmark_list.addItem(item)

    def _show_selected_event(self):
        selected = self.network_table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        if row >= len(self.network_events):
            return
        event = self.network_events[row]
        self.details_text.setHtml(self._highlight_json(event.__dict__))

    def _refresh_inspector(self):
        tab = self._current_tab()
        if not tab:
            return
        tab.view.page().toHtml(
            lambda source: self.inspector_text.setHtml(self._highlight_html(source))
        )

    def _refresh_console(self):
        c = self._theme_colors()
        lines = []
        for event in self.network_events[:80]:
            level = "ERR" if event.error else "LOG"
            status = event.status or "-"
            klass = "err" if event.error else "info"
            lines.append(
                f"<div class='{klass}'><b>[{level}]</b> {html.escape(status)} "
                f"<span>{html.escape(event.url)}</span> {html.escape(event.error)}</div>"
            )
        self.console_text.setHtml(
            f"<style>body{{font-family:'SF Mono',Monaco,Consolas,monospace;font-size:12px;line-height:1.5;"
            f"background:{c['panel2']};color:{c['text']};padding:8px}}"
            f".err{{color:{c['error']};border-left:3px solid {c['error']};padding-left:8px;margin:4px 0}}"
            f".info{{color:{c['success']};border-left:3px solid {c['success']};padding-left:8px;margin:4px 0}}"
            f"span{{color:{c['accent']};font-size:11px}}"
            f"b{{font-weight:600;min-width:36px;display:inline-block}}</style>"
            + "\n".join(lines)
        )

    def _add_history(self, url: str):
        self.history = [entry for entry in self.history if entry.get("url") != url]
        self.history.insert(0, {"url": url, "visited_at": time.strftime("%Y-%m-%d %H:%M:%S")})
        self.history = self.history[:300]

    def _sync_toolbar(self):
        tab = self._current_tab()
        if not tab:
            return
        if tab.current_url == "internal:home":
            self.url_input.clear()
        elif tab.current_url.startswith("internal:search?"):
            query = unquote_plus(tab.current_url.split("q=", 1)[1]) if "q=" in tab.current_url else ""
            self.url_input.setText(query)
        else:
            self.url_input.setText(tab.current_url)
        self.back_action.setEnabled(bool(tab.back_stack))
        self.forward_action.setEnabled(bool(tab.forward_stack))
        self.reload_action.setEnabled(bool(tab.current_url))
        self.download_action.setEnabled(bool(tab.last_response))
        label = tab.title or "New Tab"
        if tab.incognito:
            label = f"Incognito - {label}"
        self.window.setWindowTitle(f"{label} - WaterCat Browser")

    def _update_tab_label(self, tab: BrowserTab):
        for index in range(self.tabs.count()):
            widget = self.tabs.widget(index)
            if widget and widget.property("browser_tab") is tab:
                label = tab.title[:24]
                if tab.incognito:
                    label = f"\U0001F576 {label}"
                self.tabs.setTabText(index, label)
                return

    def _make_dns_client(self) -> DNSClient:
        return DNSClient(
            server_host=self.settings.dns_host,
            server_port=self.settings.dns_port,
            timeout=self.settings.dns_timeout,
            enable_cache=self.settings.enable_dns_cache,
        )

    @staticmethod
    def _title_for(host: str, incognito: bool) -> str:
        return host if not incognito else f"Private {host}"

    @staticmethod
    def _short_label(url: str) -> str:
        return url.replace("http://", "").replace("https://", "").rstrip("/")[:18] or url

    @staticmethod
    def _shortcut_url(item: Any) -> str:
        if isinstance(item, dict):
            return str(item.get("url", ""))
        return str(item)

    def _shortcut_label(self, item: Any) -> str:
        if isinstance(item, dict) and item.get("name"):
            return str(item["name"])[:18]
        return self._short_label(self._shortcut_url(item))

    @staticmethod
    def _ttl_remaining(expire_at: Optional[float]) -> Optional[int]:
        if not isinstance(expire_at, (int, float)):
            return None
        return max(0, int(expire_at - time.time()))

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        try:
            socket.inet_aton(value)
        except OSError:
            return False
        return value.count(".") == 3

    @staticmethod
    def _request_path(raw_url: str, fallback_path: str) -> str:
        parsed = urlparse(raw_url)
        path = parsed.path or fallback_path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path

    def _engine_search_url(self, query: str) -> str:
        encoded = quote_plus(query)
        if self.settings.search_engine == "bing":
            return f"https://www.bing.com/search?q={encoded}"
        return f"https://www.google.com/search?q={encoded}"

    def _synthetic_search_results(self, query: str) -> list[tuple[str, str]]:
        if not query.strip():
            return []
        engine = self.settings.search_engine.title()
        return [
            (f"{engine} search for {query}", self._engine_search_url(query)),
            (f"Images for {query}", self._engine_search_url(f"{query} images")),
            (f"News about {query}", self._engine_search_url(f"{query} news")),
        ]

    def _external_search_results(self, query: str) -> list[tuple[str, str]]:
        if not query.strip():
            return []
        search_url = self._engine_search_url(query)
        request = Request(
            search_url,
            headers={
                "User-Agent": "Mozilla/5.0 MiniWebBrowser/1.0",
                "Accept": "text/html,*/*",
            },
        )
        try:
            with urlopen(request, timeout=4) as response:
                page = response.read(350000).decode("utf-8", errors="replace")
        except Exception:
            return self._synthetic_search_results(query)

        results: list[tuple[str, str]] = []
        for match in re.finditer(r'<a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a>', page, re.I | re.S):
            url = html.unescape(match.group(1))
            title = re.sub(r"<[^>]+>", " ", match.group(2))
            title = html.unescape(re.sub(r"\s+", " ", title)).strip()
            if not title or "google" in url.lower() and self.settings.search_engine == "google":
                continue
            if self.settings.search_engine == "bing" and "bing.com" in url.lower():
                continue
            if (title, url) not in results:
                results.append((title[:120], url))
            if len(results) >= 6:
                break

        return results or self._synthetic_search_results(query)

    def _highlight_html(self, source: str) -> str:
        c = self._theme_colors()
        tag_color = c["accent"]
        attr_color = "#c084fc"
        val_color = c["warning"]
        comment_color = c["success"]
        bracket_color = c["muted"]
        escaped = html.escape(source)
        escaped = re.sub(
            r"(&lt;/?)([a-zA-Z0-9:-]+)",
            rf"<span style='color:{bracket_color}'>\1</span><span style='color:{tag_color}'>\2</span>",
            escaped,
        )
        escaped = re.sub(
            r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)(=)&quot;([^&]*)&quot;",
            rf"<span style='color:{attr_color}'>\1</span><span style='color:{bracket_color}'>\2</span><span style='color:{val_color}'>&quot;\3&quot;</span>",
            escaped,
        )
        escaped = escaped.replace("&lt;!--", f"<span style='color:{comment_color}'>&lt;!--")
        escaped = escaped.replace("--&gt;", "--&gt;</span>")
        return (
            f"<pre style='font-family:monospace;font-size:13px;line-height:1.45;"
            f"background:{c['panel2']};color:{c['text']};padding:12px;margin:0;white-space:pre-wrap'>"
            f"{escaped}</pre>"
        )

    def _highlight_json(self, value: Any) -> str:
        c = self._theme_colors()
        text = html.escape(json.dumps(value, indent=2))
        text = re.sub(
            r'(&quot;[^&]+&quot;)(:)',
            rf"<span style='color:{c['accent']}'>\1</span><span style='color:{c['muted']}'>\2</span>",
            text,
        )
        text = re.sub(
            r": (&quot;.*?&quot;)",
            rf": <span style='color:{c['warning']}'>\1</span>",
            text,
        )
        return (
            f"<pre style='font-family:monospace;font-size:13px;line-height:1.45;"
            f"background:{c['panel2']};color:{c['text']};padding:12px;margin:0;white-space:pre-wrap'>"
            f"{text}</pre>"
        )

    @staticmethod
    def _image_data_uri(path: Path) -> str:
        try:
            data = path.read_bytes()
        except OSError:
            return ""
        encoded = base64.b64encode(data).decode("ascii")
        return f"data:image/png;base64,{encoded}"

    @staticmethod
    def _http_error_status(message: str) -> str:
        text = message.lower()
        if "could not connect" in text or "connection refused" in text:
            return "404 Not Found"
        if "timed out" in text or "did not respond" in text:
            return "504 Gateway Timeout"
        if "invalid http response" in text or "empty response" in text:
            return "502 Bad Gateway"
        return "500 Internal Browser Error"

    @staticmethod
    def _status_code(status: str) -> int:
        try:
            return int(status.split(" ", 1)[0])
        except (ValueError, IndexError):
            return 500

    def _set_status(self, msg: str):
        self.status_bar.showMessage(msg)

    def _load_settings(self) -> BrowserSettings:
        state = self._read_state()
        raw = state.get("settings", {})
        if not isinstance(raw, dict):
            raw = {}
        return BrowserSettings(
            dns_host=self._setting_str(raw, "dns_host", "BROWSER_DNS_HOST", DNS_HOST),
            dns_port=self._setting_int(raw, "dns_port", "BROWSER_DNS_PORT", DNS_PORT),
            dns_timeout=self._setting_float(raw, "dns_timeout", "BROWSER_DNS_TIMEOUT", DNS_TIMEOUT),
            http_default_port=self._setting_int(
                raw, "http_default_port", "BROWSER_HTTP_DEFAULT_PORT", HTTP_DEFAULT_PORT
            ),
            enable_dns_cache=bool(
                self._setting_raw(raw, "enable_dns_cache", "BROWSER_ENABLE_DNS_CACHE", ENABLE_DNS_CACHE)
            ),
            home_url=self._setting_str(raw, "home_url", "BROWSER_HOME_URL", HOME_URL),
            search_url=self._setting_str(raw, "search_url", "BROWSER_SEARCH_URL", SEARCH_URL),
            theme=self._normalize_theme(
                self._setting_str(raw, "theme", "BROWSER_THEME", BROWSER_THEME)
            ),
            font_size=self._setting_int(raw, "font_size", "BROWSER_FONT_SIZE", BROWSER_FONT_SIZE),
            search_engine=self._normalize_search_engine(
                self._setting_str(raw, "search_engine", "BROWSER_SEARCH_ENGINE", SEARCH_ENGINE)
            ),
        )

    def _load_list(self, key: str, default: list[str]) -> list[str]:
        state = self._read_state()
        values = state.get(key, default)
        if not isinstance(values, list):
            return list(default)
        return [str(value) for value in values if str(value).strip()]

    def _load_shortcuts(self, default: list[str]) -> list[Any]:
        state = self._read_state()
        values = state.get("shortcuts", default)
        if not isinstance(values, list):
            values = default
        result = []
        for item in values:
            if isinstance(item, dict):
                url = str(item.get("url", "")).strip()
                name = str(item.get("name", "")).strip()
                if url:
                    result.append({"name": name or self._short_label(url), "url": url})
            else:
                url = str(item).strip()
                if url:
                    result.append({"name": self._short_label(url), "url": url})
        return result

    def _load_history(self) -> list[dict[str, str]]:
        state = self._read_state()
        values = state.get("history", [])
        if not isinstance(values, list):
            return []
        result = []
        for item in values:
            if isinstance(item, dict):
                url = str(item.get("url", "")).strip()
                visited_at = str(item.get("visited_at", "")).strip()
            else:
                url = str(item).strip()
                visited_at = ""
            if url:
                result.append({"url": url, "visited_at": visited_at})
        return result

    def _load_cookies(self) -> dict[str, dict[str, str]]:
        values = self._read_state().get("cookies", {})
        if not isinstance(values, dict):
            return {}
        result: dict[str, dict[str, str]] = {}
        for domain, cookies in values.items():
            if isinstance(cookies, dict):
                result[str(domain)] = {str(k): str(v) for k, v in cookies.items()}
        return result

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
                "search_url": self.settings.search_url,
                "theme": self.settings.theme,
                "font_size": self.settings.font_size,
                "search_engine": self.settings.search_engine,
            },
            "bookmarks": self.bookmarks,
            "shortcuts": self.shortcuts,
            "history": self.history,
            "cookies": self.cookies,
        }
        try:
            with open(STATE_PATH, "w", encoding="utf-8") as file_obj:
                json.dump(data, file_obj, indent=2)
        except OSError as exc:
            self._set_status(f"Could not save state: {exc}")

    @staticmethod
    def _setting_raw(raw: dict[str, Any], state_key: str, env_key: str, config_value: Any) -> Any:
        if env_key in CONFIGURED_KEYS:
            return config_value
        return raw.get(state_key, config_value)

    def _setting_str(self, raw: dict[str, Any], state_key: str, env_key: str, config_value: str) -> str:
        return str(self._setting_raw(raw, state_key, env_key, config_value))

    def _setting_int(self, raw: dict[str, Any], state_key: str, env_key: str, config_value: int) -> int:
        try:
            return int(self._setting_raw(raw, state_key, env_key, config_value))
        except (TypeError, ValueError):
            return config_value

    @staticmethod
    def _as_int(value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _setting_float(self, raw: dict[str, Any], state_key: str, env_key: str, config_value: float) -> float:
        try:
            return float(self._setting_raw(raw, state_key, env_key, config_value))
        except (TypeError, ValueError):
            return config_value

    @staticmethod
    def _normalize_theme(value: str) -> str:
        return value if value in {"light", "dark"} else "light"

    @staticmethod
    def _normalize_search_engine(value: str) -> str:
        return value if value in {"google", "bing"} else "google"


def main():
    app = QApplication(sys.argv)
    browser = BrowserApp()
    browser.window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
