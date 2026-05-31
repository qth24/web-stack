import asyncio
import html
import json
import os
import re
import socket
import sys
import time
import traceback
import base64
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, quote_plus, unquote_plus, urlencode, urljoin, urlparse
from urllib.request import Request, urlopen

os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu")
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

try:
    from PySide6.QtCore import QObject, QSize, Qt, QTimer, QUrl, Signal, Slot
    from PySide6.QtGui import QAction, QColor, QIcon
    try:
        from PySide6.QtNetwork import QNetworkProxy
    except ImportError:
        QNetworkProxy = None
    try:
        from PySide6.QtWebEngineCore import QWebEnginePage
    except ImportError:
        QWebEnginePage = None
    try:
        from PySide6.QtWebEngineCore import QWebEngineProfile, QWebEngineCookieStore
    except ImportError:
        QWebEngineProfile = None
        QWebEngineCookieStore = None
    try:
        from PySide6.QtWebChannel import QWebChannel
    except ImportError:
        QWebChannel = None
    from PySide6.QtWebEngineWidgets import QWebEngineView
    from PySide6.QtWidgets import (
        QAbstractItemView,
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
        QSizePolicy,
        QStyle,
        QSpinBox,
        QSplitter,
        QStackedWidget,
        QStatusBar,
        QTabBar,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QTextBrowser,
        QTextEdit,
        QToolBar,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    print("Missing GUI dependencies.")
    print("Install with: python -m pip install PySide6")
    raise SystemExit(1)

try:
    from qasync import QEventLoop
except ImportError:
    QEventLoop = None

from browser.core.config import (
    CONFIGURED_KEYS,
    ACCOUNT_BASE_URL,
    COOKIE_STATE_PATH,
    DEFAULT_BOOKMARKS,
    DNS_HOST,
    DNS_PORT,
    DNS_TIMEOUT,
    ENABLE_DNS_CACHE,
    ENABLE_HTTP_CACHE,
    ENABLE_PHISHING_DETECTION,
    FORCE_CUSTOM_DNS_ALL_HOSTS,
    HOME_URL,
    HTTP_CACHE_MAX_ENTRY_MB,
    HTTP_CACHE_MAX_MB,
    HTTP_DEFAULT_PORT,
    HTTPS_DEFAULT_PORT,
    ENABLE_VPN,
    VPN_HOST,
    VPN_PORT,
    VPN_TOKEN,
    VPN_TIMEOUT,
    VPN_MODE,
    VPN_DOMAINS,
    GOOGLE_SAFE_BROWSING_API_KEY,
    PHISHING_BLOCK_THRESHOLD,
    PHISHING_RULES_PATH,
    PHISHING_SUSPICIOUS_THRESHOLD,
    AI_MAX_OUTPUT_TOKENS,
    AI_MODEL,
    AI_PAGE_TEXT_MAX_CHARS,
    AI_SELECTION_MAX_CHARS,
    AI_STREAM,
    AI_TEMPERATURE,
    ENABLE_AI_ASSISTANT,
    SEARCH_URL,
    STATE_DIR,
    STATE_PATH,
    BROWSER_THEME,
    SEARCH_ENGINE,
    BROWSER_FONT_SIZE,
    WEBENGINE_PROXY_HOST,
    WEBENGINE_PROXY_PORT,
)
from browser.core.dns_client import DNSClient, DNSError
from browser.core.host_routing import effective_port_for_host, is_ipv4_address, should_use_custom_dns
from browser.core.http_client import HTTPClient, HTTPError, HTTPResponse
from browser.core.vpn_client import VPNClient, VPNError
from browser.core.webengine_proxy import LocalWebEngineProxy
from browser.core.url_parser import URLParseError, parse_url
from browser.core.cookies import CookieJar
from browser.core.http_cache import HTTPCache
from browser.core.phishing import (
    ThreatAssessment,
    ReputationData,
    SignalHit,
    ReputationHit,
    assess_url,
    assess_content,
    load_reputation,
    load_user_rules_raw,
    save_user_rules,
    merge_assessments,
    get_top_reasons,
    set_external_reputation_lookup,
    should_run_local_content_analysis,
)
from browser.core.assistant import (
    AssistantConfig,
    AssistantMessage,
    AssistantRequest,
    AssistantSessionState,
    GeminiAssistantClient,
    build_custom_request,
    build_preset_request,
    render_assistant_message_html,
)
from browser.core.form_handler import inject_form_intercept
from browser.core.profile_store import EphemeralGuestProfileStore, ProfileStoreError, RemoteEncryptedProfileStore
from browser.core.session import SessionError, SessionManager


@dataclass
class BrowserSettings:
    dns_host: str = DNS_HOST
    dns_port: int = DNS_PORT
    dns_timeout: float = DNS_TIMEOUT
    http_default_port: int = HTTP_DEFAULT_PORT
    https_default_port: int = HTTPS_DEFAULT_PORT
    enable_dns_cache: bool = ENABLE_DNS_CACHE
    enable_http_cache: bool = ENABLE_HTTP_CACHE
    enable_vpn: bool = ENABLE_VPN
    vpn_host: str = VPN_HOST
    vpn_port: int = VPN_PORT
    vpn_token: str = VPN_TOKEN
    vpn_timeout: float = VPN_TIMEOUT
    vpn_mode: str = VPN_MODE if VPN_MODE in {"all", "domains"} else "all"
    vpn_domains: list[str] = field(default_factory=lambda: list(VPN_DOMAINS))
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
    route: str = "direct"
    vpn_server: str = ""
    status: str = ""
    duration_ms: int = 0
    error: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    cache_state: str = ""
    risk_score: int = 0
    risk_verdict: str = ""
    risk_reasons: list[str] = field(default_factory=list)


@dataclass
class BrowserTab:
    view: QWebEngineView
    page: Any = None
    auth_bridge: Any = None
    web_channel: Any = None
    current_url: str = ""
    title: str = "New Tab"
    icon: Optional[QIcon] = None
    back_stack: list[str] = field(default_factory=list)
    forward_stack: list[str] = field(default_factory=list)
    last_response: Optional[HTTPResponse] = None
    last_event: Optional[NetworkEvent] = None
    incognito: bool = False
    incognito_jar_id: int = 0
    phishing_assessment: Any = None


class WaterCatAuthBridge(QObject if "QObject" in globals() else object):
    authResult = Signal(str) if "Signal" in globals() else None

    def __init__(self, app: "BrowserApp", tab: BrowserTab):
        if "QObject" in globals():
            super().__init__()
        self.browser_app = app
        self.browser_tab = tab

    @Slot(str)
    def submitAuth(self, payload: str) -> None:
        self.browser_app._spawn_task(self.browser_app._complete_account_auth(self.browser_tab, payload))


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


class BrowserTabs(QWidget):
    def __init__(self):
        super().__init__()
        self.tab_bar = QTabBar()
        self.tab_bar.setObjectName("mainTabBar")
        self.tab_bar.setExpanding(False)
        self.stack = QStackedWidget()
        self.stack.setObjectName("tabStack")
        self._nav_widget: Optional[QWidget] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.tab_bar)
        layout.addWidget(self.stack, 1)

        self.currentChanged = self.tab_bar.currentChanged
        self.tabCloseRequested = self.tab_bar.tabCloseRequested
        self.tab_bar.currentChanged.connect(self.stack.setCurrentIndex)
        self.tab_bar.tabMoved.connect(self._on_tab_moved)

    def setNavigationWidget(self, widget: QWidget) -> None:
        if self._nav_widget is not None:
            self.layout().removeWidget(self._nav_widget)
        self._nav_widget = widget
        self.layout().insertWidget(1, widget)

    def setDocumentMode(self, enabled: bool) -> None:
        self.tab_bar.setDocumentMode(enabled)

    def setTabsClosable(self, enabled: bool) -> None:
        self.tab_bar.setTabsClosable(enabled)

    def setMovable(self, enabled: bool) -> None:
        self.tab_bar.setMovable(enabled)

    def addTab(self, widget: QWidget, label: str) -> int:
        index = self.tab_bar.addTab(label)
        self.stack.addWidget(widget)
        self.setCurrentIndex(index)
        return index

    def removeTab(self, index: int) -> None:
        widget = self.stack.widget(index)
        self.tab_bar.removeTab(index)
        if widget is not None:
            self.stack.removeWidget(widget)

    def _on_tab_moved(self, from_index: int, to_index: int) -> None:
        widget = self.stack.widget(from_index)
        if widget is None:
            return
        self.stack.removeWidget(widget)
        self.stack.insertWidget(to_index, widget)
        self.stack.setCurrentIndex(self.tab_bar.currentIndex())

    def setCurrentIndex(self, index: int) -> None:
        self.tab_bar.setCurrentIndex(index)
        self.stack.setCurrentIndex(index)

    def currentWidget(self) -> Optional[QWidget]:
        return self.stack.currentWidget()

    def widget(self, index: int) -> Optional[QWidget]:
        return self.stack.widget(index)

    def count(self) -> int:
        return self.tab_bar.count()

    def setTabText(self, index: int, label: str) -> None:
        self.tab_bar.setTabText(index, label)

    def setTabIcon(self, index: int, icon: QIcon) -> None:
        self.tab_bar.setTabIcon(index, icon)


class SettingsDialog(QDialog):
    def __init__(self, parent: QWidget, settings: BrowserSettings):
        super().__init__(parent)
        self._initial_settings = settings
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
        self.http_cache_input = QCheckBox("Enable browser HTTP cache")
        self.http_cache_input.setChecked(settings.enable_http_cache)
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
        form.addRow("", self.http_cache_input)

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
            enable_http_cache=self.http_cache_input.isChecked(),
            enable_vpn=self._initial_settings.enable_vpn,
            vpn_host=self._initial_settings.vpn_host,
            vpn_port=self._initial_settings.vpn_port,
            vpn_token=self._initial_settings.vpn_token,
            vpn_timeout=self._initial_settings.vpn_timeout,
            vpn_mode=self._initial_settings.vpn_mode,
            vpn_domains=list(self._initial_settings.vpn_domains),
            home_url=self.home_url_input.text().strip() or HOME_URL,
            search_url=self.search_url_input.text().strip() or SEARCH_URL,
            theme=self.theme_input.currentText(),
            font_size=self.font_size_input.value(),
            search_engine=self.search_engine_input.currentText(),
        )


class BrowserApp:
    def __init__(self):
        self.profile_store: EphemeralGuestProfileStore | RemoteEncryptedProfileStore = EphemeralGuestProfileStore(DEFAULT_BOOKMARKS)
        self.current_user = dict(self.profile_store.current_user)
        self._profile_cache = self.profile_store.load_profile_data()
        self._legacy_state = self._read_state()
        self.settings = self._load_settings()
        self.bookmarks = self._load_list("bookmarks", DEFAULT_BOOKMARKS)
        self.shortcuts = self._load_shortcuts(DEFAULT_BOOKMARKS)
        self.history = self._load_history()
        self.network_events: list[NetworkEvent] = []

        self.cookie_jar = CookieJar(COOKIE_STATE_PATH)
        self.cookie_jar.load()
        self._incognito_jar_counter: int = 0
        self._incognito_jars: dict[int, CookieJar] = {}
        self._normal_profile: Any = None
        self._qt_cookie_store: Any = None
        self._webengine_proxy: LocalWebEngineProxy | None = None

        self.http_cache = HTTPCache(STATE_DIR / "http_cache", HTTP_CACHE_MAX_MB, HTTP_CACHE_MAX_ENTRY_MB)
        self._phishing_enabled = ENABLE_PHISHING_DETECTION
        self._phishing_reputation = load_reputation(PHISHING_RULES_PATH) if self._phishing_enabled else None
        self._phishing_session_host_allow: set[str] = set()

        if GOOGLE_SAFE_BROWSING_API_KEY and self._phishing_enabled:
            from browser.core.safe_browsing import google_safe_browsing_lookup
            set_external_reputation_lookup(google_safe_browsing_lookup)
        else:
            set_external_reputation_lookup(None)

        self._ai_config = AssistantConfig(
            enabled=ENABLE_AI_ASSISTANT,
            model=AI_MODEL,
            stream=AI_STREAM,
            temperature=AI_TEMPERATURE,
            max_output_tokens=AI_MAX_OUTPUT_TOKENS,
            selection_max_chars=AI_SELECTION_MAX_CHARS,
            page_text_max_chars=AI_PAGE_TEXT_MAX_CHARS,
        )
        self._ai_client = GeminiAssistantClient(self._ai_config) if ENABLE_AI_ASSISTANT else None
        self._assistant_sessions: dict[int, AssistantSessionState] = {}
        self._favicon_cache: dict[str, QIcon] = {}

        self.dns_client = self._make_dns_client()
        self.http_client = HTTPClient()
        self.vpn_client = self._make_vpn_client()
        if FORCE_CUSTOM_DNS_ALL_HOSTS:
            self._webengine_proxy = LocalWebEngineProxy(
                bind_host=WEBENGINE_PROXY_HOST,
                bind_port=WEBENGINE_PROXY_PORT,
                dns_client_factory=lambda: self.dns_client,
                vpn_client_factory=lambda: self.vpn_client,
                should_use_vpn=self._should_use_vpn,
            )
        self._session = SessionManager(
            base_url=ACCOUNT_BASE_URL,
            dns_client=self.dns_client,
            http_client=self.http_client,
            cookie_jar=self.cookie_jar,
            http_default_port=self.settings.http_default_port,
            https_default_port=self.settings.https_default_port,
            on_cookies_changed=self._on_session_cookies_changed,
        )

        self._setup_qt_profiles()

        self.window = QMainWindow()
        self.window.setWindowTitle("WaterCat Browser")
        self.window.resize(1240, 780)
        self.window.setMinimumSize(980, 620)
        self._state_save_pending = False
        self._state_save_timer = QTimer(self.window)
        self._state_save_timer.setSingleShot(True)
        self._state_save_timer.timeout.connect(self._save_state_now)

        self.tabs = BrowserTabs()
        self.tabs.setDocumentMode(True)
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)

        self._build_ui()
        self._bind_actions()
        self._apply_style()
        self._new_tab(self.settings.home_url)
        self._save_state(immediate=True)
        self._spawn_task(self._restore_authenticated_profile())

    def _show_account_dialog(self) -> None:
        self._save_state(immediate=True)
        self._open_account_page("login")

    def _use_local_profile(self) -> None:
        if self.current_user.get("is_local"):
            return
        self._save_state(immediate=True)
        if isinstance(self.profile_store, RemoteEncryptedProfileStore):
            self.profile_store.clear_local_key()
        self._spawn_task(self._logout_to_guest())

    def _switch_profile(self, store: EphemeralGuestProfileStore | RemoteEncryptedProfileStore, profile_data: dict[str, Any] | None = None) -> None:
        self.profile_store = store
        self.current_user = dict(store.current_user if hasattr(store, "current_user") else store.user)
        self._profile_cache = profile_data or store.load_profile_data()
        self.settings = self._load_settings()
        self.bookmarks = self._load_list("bookmarks", DEFAULT_BOOKMARKS)
        self.shortcuts = self._load_shortcuts(DEFAULT_BOOKMARKS)
        self.history = self._load_history()
        self.dns_client = self._make_dns_client()
        self.vpn_client = self._make_vpn_client()
        self._session = SessionManager(
            base_url=ACCOUNT_BASE_URL,
            dns_client=self.dns_client,
            http_client=self.http_client,
            cookie_jar=self.cookie_jar,
            http_default_port=self.settings.http_default_port,
            https_default_port=self.settings.https_default_port,
            on_cookies_changed=self._on_session_cookies_changed,
        )
        self._apply_style()
        self._refresh_side_lists()
        self._update_account_actions()
        self._sync_toolbar()
        mode = "encrypted account" if self.current_user.get("encrypted") else "guest profile"
        self._set_status(f"Using {mode}: {self.current_user.get('display_name')}.")

    def _open_account_page(self, mode: str) -> None:
        current = self._current_tab()
        next_url = "/"
        if current and current.current_url.startswith(("http://", "https://")):
            next_url = current.current_url
        base = ACCOUNT_BASE_URL.rstrip("/")
        target = f"{base}/{mode}?next={quote_plus(next_url)}"
        self._navigate(target)

    async def _logout_to_guest(self) -> None:
        try:
            await self._session.logout()
        except Exception:
            pass
        self._switch_profile(EphemeralGuestProfileStore(DEFAULT_BOOKMARKS))
        self._save_state(immediate=True)

    async def _restore_authenticated_profile(self) -> None:
        try:
            user = await self._session.me()
        except Exception:
            return
        if not user:
            return
        store = RemoteEncryptedProfileStore(self._session, STATE_DIR, user)
        try:
            restored = await store.restore_from_saved_key()
        except Exception:
            restored = False
        if not restored:
            store.clear_local_key()
            try:
                await self._session.logout()
            except Exception:
                pass
            self._set_status("Saved session expired or profile is locked. Sign in again to unlock your browser profile.")
            return
        self._switch_profile(store, store.load_profile_data())
        self._save_state(immediate=True)

    def _setup_qt_profiles(self) -> None:
        if QWebEngineProfile is None:
            return
        try:
            profile_dir = str(STATE_DIR / "webengine-profile")
            cache_dir = str(STATE_DIR / "webengine-cache")
            default_profile = QWebEngineProfile.defaultProfile()
            default_profile.setPersistentStoragePath(profile_dir)
            default_profile.setCachePath(cache_dir)
            default_profile.setHttpCacheType(
                QWebEngineProfile.HttpCacheType.DiskHttpCache
            )
            default_profile.setPersistentCookiesPolicy(
                QWebEngineProfile.PersistentCookiesPolicy.AllowPersistentCookies
            )
            self._normal_profile = default_profile
            self._qt_cookie_store = self._normal_profile.cookieStore()
            if self._qt_cookie_store is not None:
                self._qt_cookie_store.cookieAdded.connect(self._on_qt_cookie_added)
                self._qt_cookie_store.cookieRemoved.connect(self._on_qt_cookie_removed)
            self._seed_qt_cookies()
            self._configure_qt_network_proxy(False)
        except Exception:
            self._normal_profile = None
            self._qt_cookie_store = None
            self._configure_qt_network_proxy(False)

    async def start_background_services(self) -> None:
        if self._webengine_proxy is not None:
            await self._webengine_proxy.start()
            self._configure_qt_network_proxy(True)
        else:
            self._configure_qt_network_proxy(False)

    async def shutdown_async(self) -> None:
        try:
            await self.profile_store.sync_state(
                self._settings_data(),
                self.bookmarks,
                self.shortcuts,
                self.history,
            )
        except Exception:
            pass
        self._configure_qt_network_proxy(False)
        if self._webengine_proxy is not None:
            await self._webengine_proxy.stop()

    def _configure_qt_network_proxy(self, enabled: bool) -> None:
        if QNetworkProxy is None:
            return
        proxy_type_container = getattr(QNetworkProxy, "ProxyType", QNetworkProxy)
        no_proxy = getattr(proxy_type_container, "NoProxy", getattr(QNetworkProxy, "NoProxy", None))
        http_proxy = getattr(proxy_type_container, "HttpProxy", getattr(QNetworkProxy, "HttpProxy", None))
        if enabled and self._webengine_proxy is not None and http_proxy is not None:
            proxy = QNetworkProxy(http_proxy, self._webengine_proxy.bind_host, self._webengine_proxy.bind_port)
        elif no_proxy is not None:
            proxy = QNetworkProxy(no_proxy)
        else:
            return
        QNetworkProxy.setApplicationProxy(proxy)

    def _seed_qt_cookies(self) -> None:
        if self._qt_cookie_store is None:
            return
        try:
            from PySide6.QtNetwork import QNetworkCookie
        except ImportError:
            return
        for cookie in self.cookie_jar.cookie_list:
            if cookie.is_expired():
                continue
            self._set_qt_cookie(cookie)

    def _set_qt_cookie(self, cookie: Any) -> None:
        if self._qt_cookie_store is None:
            return
        try:
            from PySide6.QtNetwork import QNetworkCookie
            from PySide6.QtCore import QDateTime
        except ImportError:
            return
        domain = cookie.domain if cookie.host_only else f".{cookie.domain}"
        qt_cookie = QNetworkCookie()
        qt_cookie.setName(cookie.name.encode("utf-8"))
        qt_cookie.setValue(cookie.value.encode("utf-8"))
        qt_cookie.setDomain(domain)
        qt_cookie.setPath(cookie.path)
        qt_cookie.setSecure(cookie.secure)
        qt_cookie.setHttpOnly(cookie.http_only)
        if cookie.expires_at is not None:
            expires_dt = QDateTime.fromSecsSinceEpoch(int(cookie.expires_at))
            qt_cookie.setExpirationDate(expires_dt)
        self._qt_cookie_store.setCookie(qt_cookie)

    def _delete_qt_cookie(self, name: str, domain: str, path: str = "/") -> None:
        if self._qt_cookie_store is None:
            return
        try:
            from PySide6.QtNetwork import QNetworkCookie
        except ImportError:
            return
        self._qt_cookie_store.loadAllCookies()
        qt_domain = f".{domain}"
        for qt_cookie in self._qt_cookie_store.allCookies():
            cname = qt_cookie.name().data().decode("utf-8", errors="replace")
            cdomain = qt_cookie.domain()
            cpath = qt_cookie.path()
            if cname == name and (cdomain == domain or cdomain == qt_domain) and cpath == path:
                self._qt_cookie_store.deleteCookie(qt_cookie)

    def _on_qt_cookie_added(self, qt_cookie: Any) -> None:
        try:
            name = qt_cookie.name().data().decode("utf-8", errors="replace")
            value = qt_cookie.value().data().decode("utf-8", errors="replace")
            domain = qt_cookie.domain().lstrip(".")
            path = qt_cookie.path()
            secure = qt_cookie.isSecure()
            http_only = qt_cookie.isHttpOnly()
            expires = None
            if qt_cookie.expirationDate().isValid():
                expires = qt_cookie.expirationDate().toSecsSinceEpoch()
            from browser.core.cookies import Cookie
            nc = Cookie(
                name=name, value=value, domain=domain,
                host_only=not qt_cookie.domain().startswith("."),
                path=path, secure=secure, http_only=http_only,
                expires_at=expires, same_site="Lax",
            )
            existing = [c for c in self.cookie_jar.cookie_list
                        if c.name == name and c.domain == domain and c.path == path]
            if not existing:
                self.cookie_jar.store_cookie(nc)
                self.cookie_jar.save()
        except Exception:
            pass

    def _on_qt_cookie_removed(self, qt_cookie: Any) -> None:
        try:
            name = qt_cookie.name().data().decode("utf-8", errors="replace")
            domain = qt_cookie.domain().lstrip(".")
            path = qt_cookie.path()
            self.cookie_jar.delete_cookie(name, domain, path)
            self.cookie_jar.save()
        except Exception:
            pass

    def _on_session_cookies_changed(self, cookies: list[Any]) -> None:
        if not cookies:
            return
        for cookie in cookies:
            self._set_qt_cookie(cookie)
        self.cookie_jar.save()

    def _get_cookie_jar(self, tab: BrowserTab) -> CookieJar:
        if tab.incognito:
            if tab.incognito_jar_id not in self._incognito_jars:
                self._incognito_jars[tab.incognito_jar_id] = CookieJar()
            return self._incognito_jars[tab.incognito_jar_id]
        return self.cookie_jar

    def _build_ui(self):
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.window.setCentralWidget(central)

        self.toolbar = QToolBar("Navigation")
        self.toolbar.setMovable(False)
        self.toolbar.setFloatable(False)
        self.toolbar.setObjectName("browserToolbar")
        self.toolbar.setIconSize(QSize(18, 18))
        self.toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)

        style = QApplication.style()
        self.back_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_ArrowBack), "Back", self.window)
        self.forward_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_ArrowForward), "Forward", self.window)
        self.reload_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload), "Reload", self.window)
        self.home_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_DirHomeIcon), "Home", self.window)
        self.new_tab_action = QAction(
            self._theme_icon("tab-new", QStyle.StandardPixmap.SP_FileDialogNewFolder),
            "New Tab",
            self.window,
        )
        self.incognito_action = QAction(self._theme_icon("view-private"), "New Private Tab", self.window)
        self.bookmark_action = QAction(self._theme_icon("bookmark-new"), "Add Bookmark", self.window)
        self.history_action = QAction(self._theme_icon("document-open-recent"), "History", self.window)
        self.bookmarks_action = QAction(self._theme_icon("bookmarks"), "Bookmarks", self.window)
        self.add_shortcut_action = QAction("Add Shortcut", self.window)
        self.print_action = QAction(self._theme_icon("document-print"), "Print", self.window)
        self.download_action = QAction(self._theme_icon("download"), "Download", self.window)
        self.devtools_action = QAction(self._theme_icon("applications-development"), "DevTools", self.window)
        self.settings_action = QAction("Settings", self.window)
        self.account_action = QAction("", self.window)
        self.account_action.setEnabled(False)
        self.sign_in_action = QAction("Sign In", self.window)
        self.sign_up_action = QAction("Create Account", self.window)
        self.sign_out_action = QAction("Sign Out", self.window)
        self.vpn_check_action = QAction("Check VPN IP", self.window)
        self.ai_assistant_action = QAction(self._theme_icon("dialog-question"), "AI Assistant", self.window)
        self.ai_assistant_action.setCheckable(True)
        self.go_action = QAction(style.standardIcon(QStyle.StandardPixmap.SP_ArrowForward), "Go", self.window)

        for action, tip in [
            (self.back_action, "Back"),
            (self.forward_action, "Forward"),
            (self.reload_action, "Reload"),
            (self.home_action, "Home"),
            (self.new_tab_action, "Open a new tab"),
            (self.go_action, "Open address"),
        ]:
            action.setToolTip(tip)

        for action in [
            self.back_action,
            self.forward_action,
            self.reload_action,
            self.home_action,
            self.new_tab_action,
        ]:
            self.toolbar.addAction(action)

        self.url_input = QLineEdit()
        self.url_input.setObjectName("urlInput")
        self.url_input.setClearButtonEnabled(True)
        self.url_input.setPlaceholderText("Search or enter address")
        self.url_input.setMinimumWidth(420)
        self.url_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.toolbar.addWidget(self.url_input)

        self.toolbar.addAction(self.go_action)

        self.vpn_button = QPushButton("VPN")
        self.vpn_button.setObjectName("vpnButton")
        self.vpn_button.setCheckable(True)
        self.vpn_button.setChecked(self.settings.enable_vpn)
        self.vpn_button.setToolTip("Route custom HTTP requests through Mini VPN")
        self.vpn_button.setFixedSize(54, 36)
        self.toolbar.addWidget(self.vpn_button)

        self.menu_button = QPushButton("≡")
        self.menu_button.setObjectName("menuButton")
        self.menu_button.setToolTip("Open menu")
        self.menu_button.setFixedSize(40, 36)
        self.menu = QMenu(self.menu_button)
        self.menu.addAction(self.account_action)
        self.menu.addAction(self.sign_in_action)
        self.menu.addAction(self.sign_up_action)
        self.menu.addAction(self.sign_out_action)
        self.menu.addSeparator()
        self.menu.addAction(self.new_tab_action)
        self.menu.addAction(self.incognito_action)
        self.menu.addSeparator()
        self.menu.addAction(self.bookmark_action)
        self.menu.addAction(self.add_shortcut_action)
        self.menu.addSeparator()
        self.menu.addAction(self.bookmarks_action)
        self.menu.addAction(self.history_action)
        self.menu.addSeparator()
        self.menu.addAction(self.download_action)
        self.menu.addAction(self.print_action)
        self.menu.addSeparator()
        self.menu.addAction(self.devtools_action)
        self.menu.addAction(self.settings_action)
        self.menu.addSeparator()
        self.vpn_toggle_action = QAction("Use Mini VPN", self.window)
        self.vpn_toggle_action.setCheckable(True)
        self.vpn_toggle_action.setChecked(self.settings.enable_vpn)
        self.menu.addAction(self.vpn_toggle_action)
        self.menu.addAction(self.vpn_check_action)
        self.menu.addAction(self.ai_assistant_action)
        self.menu_button.setMenu(self.menu)
        self.toolbar.addWidget(self.menu_button)
        self.tabs.setNavigationWidget(self.toolbar)
        self._update_account_actions()

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.setHandleWidth(10)
        root.addWidget(main_splitter, 1)
        self.tabs.setObjectName("mainTabs")
        main_splitter.addWidget(self.tabs)

        self.devtools_frame = QFrame()
        self.devtools_frame.setObjectName("devtoolsFrame")
        devtools_layout = QVBoxLayout(self.devtools_frame)
        devtools_layout.setContentsMargins(10, 10, 10, 10)
        devtools_layout.setSpacing(10)
        devtools_header = QHBoxLayout()
        dt_label = QLabel("Developer Tools")
        dt_label.setObjectName("devtoolsLabel")
        devtools_header.addWidget(dt_label)
        devtools_header.addStretch(1)
        self.close_devtools_btn = QPushButton("×")
        self.close_devtools_btn.setObjectName("devtoolsCloseButton")
        self.close_devtools_btn.setFixedWidth(34)
        devtools_header.addWidget(self.close_devtools_btn)
        devtools_layout.addLayout(devtools_header)
        self.devtools_tabs = QTabWidget()
        self.devtools_tabs.setObjectName("devtoolsTabs")
        devtools_layout.addWidget(self.devtools_tabs)

        self.network_table = QTableWidget(0, 11)
        self.network_table.setHorizontalHeaderLabels(
            ["URL", "Route", "VPN", "DNS IP", "DNS Cache", "TTL", "Endpoint", "Status", "HTTP Cache", "Time", "Error"]
        )
        self.network_table.setAlternatingRowColors(True)
        self.network_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.network_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.network_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.devtools_tabs.addTab(self.network_table, "Network")

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.devtools_tabs.addTab(self.details_text, "Headers")

        self.cookies_table = QTableWidget(0, 3)
        self.cookies_table.setHorizontalHeaderLabels(["Domain", "Name", "Value"])
        self.cookies_table.setAlternatingRowColors(True)
        self.cookies_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.cookies_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.cookies_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.devtools_tabs.addTab(self.cookies_table, "Cookies")

        self.inspector_text = QTextEdit()
        self.inspector_text.setReadOnly(True)
        self.devtools_tabs.addTab(self.inspector_text, "Inspector")

        self.console_text = QTextEdit()
        self.console_text.setReadOnly(True)
        self.devtools_tabs.addTab(self.console_text, "Console")

        self.history_list = QListWidget()
        self.history_list.setUniformItemSizes(True)
        self.devtools_tabs.addTab(self.history_list, "History")

        self.bookmark_list = QListWidget()
        self.bookmark_list.setUniformItemSizes(True)
        self.devtools_tabs.addTab(self.bookmark_list, "Bookmarks")

        main_splitter.addWidget(self.devtools_frame)
        main_splitter.setSizes([590, 190])
        self.devtools_frame.hide()

        self._assistant_sidebar = QFrame()
        self._assistant_sidebar.setObjectName("assistantSidebar")
        self._assistant_sidebar.setMinimumWidth(260)
        self._assistant_sidebar.setMaximumWidth(500)
        assistant_layout = QVBoxLayout(self._assistant_sidebar)
        assistant_layout.setContentsMargins(0, 0, 0, 0)
        assistant_layout.setSpacing(0)

        asst_header = QHBoxLayout()
        asst_header.setContentsMargins(12, 10, 12, 6)
        asst_label = QLabel("AI Assistant")
        asst_label.setObjectName("assistantLabel")
        asst_header.addWidget(asst_label)
        asst_header.addStretch(1)
        self.open_asst_tab_btn = QPushButton("Open Tab")
        self.open_asst_tab_btn.setFixedHeight(28)
        self.open_asst_tab_btn.clicked.connect(self._open_assistant_tab)
        asst_header.addWidget(self.open_asst_tab_btn)
        self.close_asst_btn = QPushButton("×")
        self.close_asst_btn.setObjectName("devtoolsCloseButton")
        self.close_asst_btn.setFixedWidth(34)
        self.close_asst_btn.clicked.connect(lambda: self._toggle_assistant(False))
        asst_header.addWidget(self.close_asst_btn)
        assistant_layout.addLayout(asst_header)

        self.asst_context_chips = QLabel("")
        self.asst_context_chips.setWordWrap(True)
        self.asst_context_chips.setObjectName("assistantChips")
        self.asst_context_chips.setTextFormat(Qt.TextFormat.RichText)
        self.asst_context_chips.setMinimumHeight(0)
        self.asst_context_chips.hide()
        assistant_layout.addWidget(self.asst_context_chips)

        self.asst_transcript = QTextBrowser()
        self.asst_transcript.setOpenLinks(False)
        self.asst_transcript.anchorClicked.connect(lambda url: self._navigate(url.toString()))
        self.asst_transcript.setObjectName("assistantTranscript")
        assistant_layout.addWidget(self.asst_transcript, 1)

        self.asst_streaming_label = QLabel("")
        self.asst_streaming_label.setWordWrap(True)
        self.asst_streaming_label.setTextFormat(Qt.TextFormat.PlainText)
        self.asst_streaming_label.setObjectName("assistantStreaming")
        self.asst_streaming_label.hide()
        assistant_layout.addWidget(self.asst_streaming_label)

        qa_row = QHBoxLayout()
        qa_row.setContentsMargins(10, 6, 10, 10)
        qa_row.setSpacing(6)
        self.asst_quick_btn = QPushButton("Summarize")
        self.asst_quick_btn.clicked.connect(lambda: self._asst_preset("summarize"))
        qa_row.addWidget(self.asst_quick_btn)
        self.asst_clear_btn = QPushButton("Clear")
        self.asst_clear_btn.clicked.connect(self._asst_clear)
        qa_row.addWidget(self.asst_clear_btn)
        assistant_layout.addLayout(qa_row)

        composer_row = QHBoxLayout()
        composer_row.setContentsMargins(10, 0, 10, 12)
        composer_row.setSpacing(6)
        self.asst_composer = QLineEdit()
        self.asst_composer.setPlaceholderText("Ask about this page or anything else...")
        self.asst_composer.setObjectName("assistantComposer")
        self.asst_composer.returnPressed.connect(self._asst_send)
        composer_row.addWidget(self.asst_composer, 1)
        self.asst_send_btn = QPushButton("Send")
        self.asst_send_btn.clicked.connect(self._asst_send)
        composer_row.addWidget(self.asst_send_btn)
        self.asst_stop_btn = QPushButton("Stop")
        self.asst_stop_btn.hide()
        self.asst_stop_btn.clicked.connect(self._asst_stop)
        composer_row.addWidget(self.asst_stop_btn)
        assistant_layout.addLayout(composer_row)

        self._assistant_sidebar.hide()

        hsplitter = QSplitter(Qt.Orientation.Horizontal)
        hsplitter.setHandleWidth(10)
        hsplitter.addWidget(main_splitter)
        hsplitter.addWidget(self._assistant_sidebar)
        hsplitter.setSizes([940, 280])
        root.addWidget(hsplitter, 1)

        self.status_bar = QStatusBar()
        self.window.setStatusBar(self.status_bar)
        self._refresh_side_lists()
        self._set_status("Ready.")

    def _theme_icon(
        self,
        theme_name: str,
        fallback: Optional[QStyle.StandardPixmap] = None,
    ) -> QIcon:
        icon = QIcon.fromTheme(theme_name)
        if not icon.isNull():
            return icon
        if fallback is not None:
            return QApplication.style().standardIcon(fallback)
        return QIcon()

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
        self.sign_in_action.triggered.connect(self._show_account_dialog)
        self.sign_up_action.triggered.connect(lambda: self._open_account_page("register"))
        self.sign_out_action.triggered.connect(self._use_local_profile)
        self.vpn_check_action.triggered.connect(lambda: self._navigate("internal:vpn-check"))
        self.ai_assistant_action.triggered.connect(lambda checked: self._toggle_assistant(checked))
        self.vpn_button.toggled.connect(self._set_vpn_enabled)
        self.vpn_toggle_action.toggled.connect(self._set_vpn_enabled)
        self.tabs.currentChanged.connect(lambda _: self._sync_toolbar())
        self.tabs.tabCloseRequested.connect(self._close_tab)
        self.network_table.itemSelectionChanged.connect(self._show_selected_event)
        self.history_list.itemDoubleClicked.connect(self._open_list_item)
        self.bookmark_list.itemDoubleClicked.connect(self._open_list_item)

    def _theme_colors(self) -> dict[str, str]:
        dark = self.settings.theme == "dark"
        if dark:
            return {
                "window": "#0b1120",
                "window_alt": "#111a2f",
                "bar": "#182134",
                "bar_top": "#202c45",
                "bar_bottom": "#141d2f",
                "panel": "#152238",
                "panel2": "#1d2c45",
                "panel3": "#273650",
                "text": "#edf4ff",
                "muted": "#9eb1ca",
                "muted_soft": "#6e829f",
                "border": "#31425f",
                "border2": "#24344e",
                "tab": "#1d2940",
                "tab_hover": "#24344f",
                "tab_selected": "#111a2d",
                "tab_line": "#7aa2ff",
                "input": "#0f1a2d",
                "input_focus": "#13203a",
                "accent": "#6ea8ff",
                "accent_hover": "#8ab8ff",
                "accent_soft": "rgba(110, 168, 255, 0.18)",
                "accent_ring": "rgba(110, 168, 255, 0.34)",
                "shadow": "rgba(2, 6, 23, 0.38)",
                "shadow_soft": "rgba(2, 6, 23, 0.18)",
                "hero_1": "rgba(66, 153, 225, 0.28)",
                "hero_2": "rgba(20, 184, 166, 0.18)",
                "hero_3": "rgba(124, 58, 237, 0.18)",
                "error": "#ef4444", "warning": "#f59e0b", "success": "#22c55e",
                "incognito": "#8b5cf6",
            }
        return {
            "window": "#f3f6fb",
            "window_alt": "#eef2f8",
            "bar": "#edf2f8",
            "bar_top": "#f7f9fc",
            "bar_bottom": "#e6ecf4",
            "panel": "#ffffff",
            "panel2": "#f2f5fa",
            "panel3": "#e7edf5",
            "text": "#11203a",
            "muted": "#63748a",
            "muted_soft": "#8a98ad",
            "border": "#d5dde8",
            "border2": "#e7edf5",
            "tab": "#e7edf4",
            "tab_hover": "#f1f5fa",
            "tab_selected": "#ffffff",
            "tab_line": "#4f7fff",
            "input": "#ffffff",
            "input_focus": "#fefeff",
            "accent": "#2563eb",
            "accent_hover": "#1d4ed8",
            "accent_soft": "rgba(37, 99, 235, 0.1)",
            "accent_ring": "rgba(37, 99, 235, 0.18)",
            "shadow": "rgba(15, 23, 42, 0.12)",
            "shadow_soft": "rgba(15, 23, 42, 0.06)",
            "hero_1": "rgba(103, 161, 255, 0.18)",
            "hero_2": "rgba(255, 179, 71, 0.16)",
            "hero_3": "rgba(45, 212, 191, 0.16)",
            "error": "#ef4444", "warning": "#f97316", "success": "#22c55e",
            "incognito": "#8b5cf6",
        }

    def _apply_style(self):
        c = self._theme_colors()
        self.window.setStyleSheet(
            f"""
            QMainWindow {{
                background: {c['window']};
                color: {c['text']};
            }}
            QToolBar#browserToolbar {{
                background: qlineargradient(
                    x1:0, y1:0, x2:0, y2:1,
                    stop:0 {c['bar_top']},
                    stop:1 {c['bar_bottom']}
                );
                border: 0;
                border-bottom: 1px solid {c['border']};
                spacing: 6px;
                padding: 10px 12px 12px 12px;
            }}
            QToolButton {{
                color: {c['text']};
                background: transparent;
                border: 1px solid transparent;
                border-radius: 17px;
                padding: 8px;
                min-width: 18px;
                min-height: 18px;
                margin: 0 1px;
            }}
            QToolButton:hover {{
                background: {c['panel']};
                border-color: {c['border']};
            }}
            QToolButton:pressed {{
                background: {c['tab']};
                border-color: {c['border']};
            }}
            QToolButton:disabled {{
                color: {c['muted_soft']};
                background: transparent;
            }}
            QPushButton {{
                color: {c['text']};
                background: {c['panel2']};
                border: 1px solid {c['border']};
                border-radius: 12px;
                padding: 7px 12px;
            }}
            QPushButton:hover {{
                background: {c['panel']};
                border-color: {c['accent']};
            }}
            QPushButton::menu-indicator {{ image: none; width: 0; }}
            QPushButton#menuButton {{
                background: {c['panel']};
                border-radius: 18px;
                font-size: 18px;
                font-weight: 600;
                padding: 0;
            }}
            QPushButton#menuButton:hover {{
                background: {c['accent_soft']};
                border-color: {c['accent']};
            }}
            QPushButton#vpnButton {{
                background: {c['panel']};
                border-radius: 18px;
                font-size: 12px;
                font-weight: 700;
                padding: 0;
            }}
            QPushButton#vpnButton:checked {{
                background: {c['success']};
                border-color: {c['success']};
                color: white;
            }}
            QPushButton#vpnButton:hover {{
                border-color: {c['accent']};
            }}
            QPushButton#devtoolsCloseButton {{
                border-radius: 12px;
                min-height: 28px;
                font-size: 16px;
                padding: 0;
            }}
            QLabel#devtoolsLabel {{
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 0.14em;
                text-transform: uppercase;
                color: {c['muted']};
            }}
            QLabel#authTitle {{
                color: {c['text']};
                font-size: 22px;
                font-weight: 700;
            }}
            QLabel#authSubtitle {{
                color: {c['muted']};
                font-size: 13px;
            }}
            QLabel#authMessage {{
                color: {c['error']};
                font-size: 13px;
            }}
            QLineEdit#urlInput {{
                color: {c['text']};
                background: {c['input']};
                border: 1px solid {c['border']};
                border-radius: 20px;
                padding: 9px 18px;
                font-size: 15px;
                selection-background-color: {c['accent']};
            }}
            QLineEdit#urlInput:focus {{
                background: {c['input_focus']};
                border: 2px solid {c['tab_line']};
                padding: 8px 17px;
            }}
            QTabWidget::pane {{
                border-top: 1px solid {c['border2']};
                background: {c['panel']};
            }}
            QTabWidget#mainTabs::pane {{
                background: {c['panel']};
                border-top: 0;
            }}
            QTabBar#mainTabBar {{
                background: {c['bar_top']};
                border-bottom: 1px solid {c['border']};
                padding-left: 10px;
            }}
            QTabBar::tab {{
                color: {c['muted']};
                background: {c['tab']};
                border: 1px solid transparent;
                border-bottom: 0;
                padding: 10px 16px 11px 16px;
                margin: 8px 4px 0 0;
                min-width: 120px;
                border-top-left-radius: 14px;
                border-top-right-radius: 14px;
            }}
            QTabBar::tab:hover {{
                color: {c['text']};
                background: {c['tab_hover']};
                border-color: {c['border2']};
            }}
            QTabBar::tab:selected {{
                color: {c['text']};
                background: {c['tab_selected']};
                border-color: {c['border']};
                border-bottom-color: {c['tab_selected']};
            }}
            QTabBar::close-button {{
                subcontrol-position: right;
                margin-left: 10px;
                width: 16px;
            }}
            QFrame {{
                background: {c['panel']};
                border: 1px solid {c['border']};
                border-radius: 18px;
            }}
            QFrame#devtoolsFrame {{
                background: {c['panel']};
                border-top: 1px solid {c['border']};
                border-radius: 0;
            }}
            QFrame#assistantSidebar {{
                background: {c['panel']};
                border: 1px solid {c['border']};
                border-radius: 18px;
            }}
            QLabel#assistantLabel {{
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 0.14em;
                text-transform: uppercase;
                color: {c['muted']};
            }}
            QLabel#assistantChips {{
                color: {c['muted_soft']};
                font-size: 12px;
                padding: 4px 12px;
                background: {c['panel2']};
                border-bottom: 1px solid {c['border2']};
            }}
            QLabel#assistantStreaming {{
                color: {c['text']};
                font-size: 13px;
                padding: 8px 12px;
                background: {c['panel2']};
                border-top: 1px solid {c['border2']};
            }}
            QTextEdit#assistantTranscript {{
                border: 0;
                border-radius: 0;
                font-size: 13px;
                padding: 8px 12px;
            }}
            QLineEdit#assistantComposer {{
                font-size: 13px;
                padding: 8px 12px;
            }}
            QTableWidget, QListWidget, QTextEdit {{
                color: {c['text']};
                background: {c['panel']};
                border: 1px solid {c['border']};
                alternate-background-color: {c['panel2']};
                gridline-color: {c['border2']};
                selection-background-color: {c['accent']};
                border-radius: 14px;
            }}
            QAbstractItemView::item {{
                padding: 6px 8px;
                border: 0;
            }}
            QHeaderView::section {{
                color: {c['text']};
                background: {c['panel2']};
                border: 0;
                border-right: 1px solid {c['border']};
                border-bottom: 1px solid {c['border']};
                padding: 8px;
                font-weight: 600;
            }}
            QComboBox, QSpinBox {{
                color: {c['text']};
                background: {c['input']};
                border: 1px solid {c['border']};
                border-radius: 10px;
                padding: 7px 10px;
            }}
            QMenu {{
                color: {c['text']};
                background: {c['panel']};
                border: 1px solid {c['border']};
                border-radius: 14px;
                padding: 8px 0;
            }}
            QMenu::item {{
                padding: 8px 22px;
                border-radius: 8px;
                margin: 2px 8px;
            }}
            QMenu::item:selected {{
                background: {c['accent_soft']};
                color: {c['text']};
            }}
            QMenu::separator {{ height: 1px; background: {c['border']}; margin: 4px 0; }}
            QSplitter::handle {{
                background: {c['window_alt']};
            }}
            QStatusBar {{
                color: {c['muted']};
                background: {c['bar']};
                border-top: 1px solid {c['border']};
                padding: 2px 12px;
            }}
            """
        )

    def _new_tab(self, url: str = "", incognito: bool = False):
        view = QWebEngineView()
        tab = BrowserTab(view=view, incognito=incognito)
        if incognito:
            self._incognito_jar_counter += 1
            tab.incognito_jar_id = self._incognito_jar_counter
            self._incognito_jars[tab.incognito_jar_id] = CookieJar()
        view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        view.customContextMenuRequested.connect(lambda pos, v=view: self._show_context_menu(v, pos))
        if QWebEnginePage:
            tab.page = BrowserPage(self, tab)
            view.setPage(tab.page)
            if QWebChannel is not None:
                tab.auth_bridge = WaterCatAuthBridge(self, tab)
                tab.web_channel = QWebChannel(view.page())
                tab.web_channel.registerObject("watercatAuth", tab.auth_bridge)
                try:
                    view.page().setWebChannel(tab.web_channel)
                except Exception:
                    tab.web_channel = None
        view.loadStarted.connect(lambda t=tab: self._on_view_load_started(t))
        view.loadProgress.connect(lambda progress, t=tab: self._on_view_load_progress(t, progress))
        view.loadFinished.connect(lambda ok, t=tab: self._on_view_load_finished(t, ok))
        view.urlChanged.connect(lambda qurl, t=tab: self._on_view_url_changed(t, qurl))
        view.titleChanged.connect(lambda title, t=tab: self._on_view_title_changed(t, title))
        try:
            view.iconChanged.connect(lambda icon, t=tab: self._on_view_icon_changed(t, icon))
        except Exception:
            pass
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
        if widget:
            tab = widget.property("browser_tab")
            if tab and tab.incognito and tab.incognito_jar_id in self._incognito_jars:
                del self._incognito_jars[tab.incognito_jar_id]
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

    def _spawn_task(self, coro):
        loop = asyncio.get_event_loop()
        task = loop.create_task(coro)
        task.add_done_callback(self._on_async_task_done)
        return task

    def _on_async_task_done(self, task: asyncio.Task) -> None:
        try:
            task.result()
        except asyncio.CancelledError:
            return
        except Exception as exc:
            traceback.print_exc()
            self._set_status(f"Async error: {exc}")

    async def _complete_account_auth(self, tab: BrowserTab, raw_payload: str) -> None:
        try:
            payload = json.loads(raw_payload)
        except json.JSONDecodeError:
            self._emit_account_auth_result(tab, {"success": False, "error": "Invalid authentication payload."})
            return

        mode = str(payload.get("mode", "login")).strip().lower()
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", "")).strip()
        display_name = str(payload.get("display_name", "")).strip()
        next_url = str(payload.get("next", "/")).strip() or "/"
        if mode not in {"login", "register"}:
            self._emit_account_auth_result(tab, {"mode": mode, "success": False, "error": "Unknown authentication mode."})
            return
        if not username or not password:
            self._emit_account_auth_result(tab, {"mode": mode, "success": False, "error": "Username and password are required."})
            return
        if mode == "register" and password != str(payload.get("confirm_password", "")).strip():
            self._emit_account_auth_result(tab, {"mode": mode, "success": False, "error": "Password confirmation does not match."})
            return

        try:
            if mode == "register":
                user = await self._session.register(username, password, display_name)
            else:
                user = await self._session.login(username, password)
            store = RemoteEncryptedProfileStore(self._session, STATE_DIR, user)
            profile_data = await store.bootstrap_with_password(password)
            self._switch_profile(store, profile_data)
            self._save_state(immediate=True)
        except (ProfileStoreError, SessionError) as exc:
            self._emit_account_auth_result(tab, {"mode": mode, "success": False, "error": str(exc)})
            return
        except Exception as exc:
            self._emit_account_auth_result(tab, {"mode": mode, "success": False, "error": f"Authentication failed: {exc}"})
            return

        target = next_url if next_url.startswith(("http://", "https://")) else self.settings.home_url
        QTimer.singleShot(0, lambda target=target, current_tab=tab: self._navigate(target, tab=current_tab, add_history=False, record_navigation=False))
        self._emit_account_auth_result(tab, {"mode": mode, "success": True})

    def _emit_account_auth_result(self, tab: BrowserTab, payload: dict[str, Any]) -> None:
        if getattr(tab, "auth_bridge", None) is None or getattr(tab.auth_bridge, "authResult", None) is None:
            return
        try:
            tab.auth_bridge.authResult.emit(json.dumps(payload))
        except Exception:
            pass

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
        self._spawn_task(self._navigate_async(url, tab=tab, add_history=add_history, record_navigation=record_navigation))

    async def _navigate_async(
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

            if url.startswith("watercat-form:"):
                await self._handle_form_submission(url, tab)
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

            normalized_url = parsed.raw.lower()
            host = (parsed.host or "").lower()
            if self._is_account_url(parsed.raw):
                self._navigate_with_webengine(
                    parsed.raw,
                    parsed.host,
                    tab,
                    add_history=add_history,
                    record_navigation=record_navigation,
                )
                return
            if self._phishing_enabled and self._phishing_reputation is not None:
                if host not in self._phishing_session_host_allow:
                    url_assessment = assess_url(parsed.raw, self._phishing_reputation)
                    if url_assessment.verdict == "phishing":
                        self._show_phishing_warning(tab, parsed.raw, url_assessment)
                        return
                    tab.phishing_assessment = url_assessment
                    event.risk_score = url_assessment.score
                    event.risk_verdict = url_assessment.verdict
                    event.risk_reasons = list(url_assessment.reasons)
                    if url_assessment.verdict == "suspicious":
                        self._set_status(f"Suspicious: {url_assessment.score}")

            if not self._should_use_custom_loader(parsed.host, parsed.protocol):
                self._navigate_with_webengine(
                    parsed.raw,
                    parsed.host,
                    tab,
                    add_history=add_history,
                    record_navigation=record_navigation,
                )
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
                    dns_result = await self.dns_client.resolve(parsed.host)
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
            
            http_port = self._effective_port(parsed.raw, parsed.protocol, parsed.host, parsed.port)
                
            event.endpoint = f"{dns_ip}:{http_port}"
            self._set_status("Connecting...")

            request_path = self._request_path(parsed.raw, parsed.path)
            scheme = parsed.protocol

            self._set_status("Loading...")
            try:
                response, cache_state, req_headers, route_meta = await self._custom_fetch(
                    scheme=scheme,
                    host=parsed.host,
                    port=http_port,
                    path=request_path,
                    ip=dns_ip,
                    tab=tab,
                )
            except HTTPError as exc:
                event.status = self._http_error_status(str(exc))
                event.error = str(exc)
                self._record_event(event)
                self._render_error(tab, event.status, str(exc), code=self._status_code(event.status))
                return

            event.request_headers = req_headers
            event.route = route_meta.get("route", "direct")
            event.vpn_server = route_meta.get("vpn_server", "")

            event.status = f"{response.status_code} {response.status_text}".strip()
            event.response_headers = dict(response.headers)
            event.duration_ms = int((time.time() - start) * 1000)
            event.cache_state = cache_state
            tab.last_response = response
            tab.last_event = event

            redirect_url = self._redirect_target(parsed.raw, response)
            if redirect_url:
                self._record_event(event)
                self._set_status(f"Redirecting to {redirect_url}")
                await self._navigate_async(
                    redirect_url,
                    tab=tab,
                    add_history=add_history,
                    record_navigation=record_navigation,
                )
                return

            await self._render_response(tab, response, dns_ip, http_port, request_path, cache_state)
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

    async def _handle_form_submission(self, url: str, tab):
        try:
            payload = base64.b64decode(url[16:]).decode("utf-8")
            data = json.loads(payload)
            method = data.get("method", "GET")
            form_url = data.get("url", "")
            body = data.get("body", "")
            content_type = data.get("contentType", "application/x-www-form-urlencoded")

            if method == "GET":
                self._navigate(form_url, tab)
            elif method == "POST":
                parsed = parse_url(form_url)
                ip = (await self.dns_client.resolve(parsed.host)).ip
                port = self._effective_port(form_url, parsed.protocol, parsed.host, parsed.port)
                path = parsed.path
                response = await self.http_client.post(
                    ip=ip, port=port, path=path, host=parsed.host,
                    body=body, content_type=content_type,
                    use_tls=(parsed.protocol == "https")
                )
                tab.current_url = form_url
                tab.view.setHtml(response.body, QUrl(form_url))
        except Exception as e:
            traceback.print_exc()
            self._set_status(f"Form error: {e}")

    async def _render_response(self, tab: BrowserTab, response: HTTPResponse, ip: str, port: int, path: str, cache_state: str = "miss"):
        content_type = response.header("Content-Type").lower()
        protocol = "https" if tab.last_event and tab.last_event.url.startswith("https://") else "http"
        base_url = QUrl(f"{protocol}://{ip}:{port}{path}")

        if tab.last_event and not tab.last_event.cache_state:
            tab.last_event.cache_state = cache_state

        if response.is_ok and "text/html" in content_type:
            html_body = await self._load_same_origin_assets(response.body, ip, port, tab)
            tab.view.setHtml(html_body, base_url)
            self._run_post_load_phishing(tab)
        elif response.is_ok and self._is_displayable_response(content_type):
            self._render_text_response(tab, response)
        elif response.is_ok:
            self._render_download_page(tab, response)
        else:
            title = f"{response.status_code} {response.status_text}".strip()
            self._render_error(tab, title or "HTTP Error", response.body[:3000], code=response.status_code)

    def _run_post_load_phishing(self, tab: BrowserTab):
        if not self._phishing_enabled or self._phishing_reputation is None:
            return
        if not tab.current_url or tab.current_url.startswith("internal:"):
            return
        host = (urlparse(tab.current_url).hostname or "").lower()
        if host in self._phishing_session_host_allow:
            return

        pre_assessment = getattr(tab, "phishing_assessment", None)
        if not should_run_local_content_analysis(pre_assessment):
            return

        try:
            tab.view.page().toHtml(
                lambda html: self._on_content_analysis_done(tab, html)
            )
        except Exception:
            pass

    def _on_content_analysis_done(self, tab: BrowserTab, html: str):
        url = tab.current_url
        host = (urlparse(url).hostname or "").lower()
        if host in self._phishing_session_host_allow:
            return

        pre_assessment = getattr(tab, "phishing_assessment", None)
        url_assessment = pre_assessment if pre_assessment is not None else assess_url(url, self._phishing_reputation)
        content_assessment = assess_content(url, html, self._phishing_reputation)
        merged = merge_assessments(url_assessment, content_assessment)

        if tab.last_event:
            tab.last_event.risk_score = merged.score
            tab.last_event.risk_verdict = merged.verdict
            tab.last_event.risk_reasons = list(merged.reasons)

        if merged.verdict in ("phishing", "suspicious"):
            self._show_phishing_warning(tab, url, merged)

    def _show_phishing_warning(self, tab: BrowserTab, url: str, assessment: Any):
        import urllib.parse
        encoded_url = urllib.parse.quote_plus(url)
        parsed = urlparse(url)
        encoded_host = urllib.parse.quote_plus(parsed.hostname or url)

        top_reasons = get_top_reasons(assessment, 3)
        reasons_html = "".join(
            f"<li>{html.escape(r)}</li>" for r in top_reasons
        )

        if assessment.verdict == "suspicious":
            icon = "&#9888;"
            heading = "Suspicious Site Detected"
            lead = "WaterCat flagged this page as potentially risky. Proceed with caution."
            primary = f"<a class='button-link' href='internal:phishing-continue?url={encoded_url}'>Continue</a>"
            secondary = f"<a class='ghost-link' href='javascript:history.back()'>Go back</a>"
        else:
            icon = "&#128683;"
            heading = "Phishing Site Detected"
            lead = "WaterCat blocked this page because it may be a phishing attempt."
            primary = f"<a class='button-link' href='javascript:history.back()'>Go back</a>"
            secondary = f"<a class='ghost-link' href='internal:phishing-continue?url={encoded_url}'>Continue anyway</a>"

        body = (
            "<main class='page-shell error-shell'>"
            "<section class='surface error-card'>"
            f"<div class='error-icon'>{icon}</div>"
            "<p class='eyebrow'>Security Warning</p>"
            f"<h1>{html.escape(heading)}</h1>"
            f"<p class='lead'>{html.escape(lead)}</p>"
            f"<div class='kv-list' style='text-align:left;max-width:600px;margin:16px auto'>"
            f"<div class='kv-row'><span>Target URL</span><b style='overflow-wrap:anywhere'>{html.escape(url)}</b></div>"
            f"<div class='kv-row'><span>Risk Score</span><b>{assessment.score}</b></div>"
            f"<div class='kv-row'><span>Verdict</span><b>{html.escape(assessment.verdict)}</b></div>"
            f"</div>"
            f"<ul style='text-align:left;max-width:600px;margin:12px auto;color:var(--muted)'>{reasons_html}</ul>"
            "<div class='action-row center'>"
            f"{primary}"
            f"{secondary}"
            "</div></section></main>"
        )
        tab.view.setHtml(self._page_html("Security Warning", body, error=True))
        tab.title = "Security Warning"
        self._update_tab_label(tab)
        self._set_status(f"Phishing blocked: {assessment.score}")

    def _navigate_with_webengine(
        self,
        url: str,
        host: str,
        tab: BrowserTab,
        add_history: bool = True,
        record_navigation: bool = True,
    ):
        if record_navigation and tab.current_url and tab.current_url != url:
            tab.back_stack.append(tab.current_url)
            tab.forward_stack.clear()

        tab.current_url = url
        tab.title = self._title_for(host, tab.incognito)
        tab.last_response = None
        tab.last_event = None
        self._update_tab_label(tab)
        if add_history and not tab.incognito:
            self._add_history(url)
            self._save_state()
        self._set_status(self._webengine_status_text(url))
        tab.view.load(QUrl(url))

    def _on_view_load_started(self, tab: BrowserTab):
        if tab.current_url.startswith(("http://", "https://")) and not self._should_use_custom_loader_from_url(tab.current_url):
            self._set_status(self._webengine_status_text(tab.current_url))

    def _on_view_load_progress(self, tab: BrowserTab, progress: int):
        if tab.current_url.startswith(("http://", "https://")) and not self._should_use_custom_loader_from_url(tab.current_url):
            self._set_status(self._webengine_status_text(tab.current_url, progress))

    def _on_view_load_finished(self, tab: BrowserTab, ok: bool):
        if not tab.current_url.startswith(("http://", "https://")):
            return
        if self._should_use_custom_loader_from_url(tab.current_url):
            return
        self._set_status("Ready." if ok else "Page load failed.")
        if ok:
            self._run_post_load_phishing(tab)
        self._refresh_all()
        self._sync_toolbar()

    def _on_view_url_changed(self, tab: BrowserTab, url: QUrl):
        target = url.toString()
        if not target.startswith(("http://", "https://")):
            return
        if self._should_use_custom_loader_from_url(target):
            return
        tab.current_url = target
        self._sync_toolbar()

    def _on_view_title_changed(self, tab: BrowserTab, title: str):
        if not title or tab.current_url.startswith("internal:"):
            return
        tab.title = title[:80]
        self._update_tab_label(tab)
        self._sync_toolbar()

    def _on_view_icon_changed(self, tab: BrowserTab, icon: QIcon):
        if icon is None or icon.isNull():
            return
        tab.icon = icon
        parsed = urlparse(tab.current_url if "://" in tab.current_url else "")
        if parsed.hostname:
            self._favicon_cache[parsed.hostname] = icon
        self._update_tab_label(tab)

    async def _load_same_origin_assets(self, html_body: str, ip: str, port: int, tab: BrowserTab) -> str:
        """Inline same-origin CSS as <style> tags and convert same-origin images to data URIs."""
        host = tab.last_event.host if tab.last_event else ""
        use_tls = tab.last_event.url.startswith("https://") if tab.last_event else False
        scheme = "https" if use_tls else "http"

        css_link_patterns = [
            r'<link\s+[^>]*rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\'][^>]*>',
            r'<link\s+[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\']stylesheet["\'][^>]*>',
        ]
        img_pattern = r'<img\s+[^>]*src=["\']([^"\']+)["\'][^>]*>'

        def _is_same_origin(url_str: str) -> tuple[bool, str]:
            """Returns (is_same_origin, path_only)."""
            parsed = urlparse(url_str)
            if parsed.scheme and parsed.scheme not in ("http", "https"):
                return False, url_str
            if not parsed.netloc:
                if url_str.startswith("//"):
                    return False, url_str
                return True, url_str
            if parsed.hostname == host:
                path = parsed.path or "/"
                if parsed.query:
                    path += f"?{parsed.query}"
                return True, path
            return False, url_str

        def _skip_external(url: str, tag: str) -> str:
            if tab.last_event:
                tab.last_event.error += f"; skipped external: {url}" if tab.last_event.error else f"skipped external: {url}"
            return tag

        for pattern in css_link_patterns:
            matches = list(re.finditer(pattern, html_body, re.I))
            for match in reversed(matches):
                full_tag = match.group(0)
                href = match.group(1)
                is_same, request_path = _is_same_origin(href)
                if not is_same:
                    html_body = html_body[:match.start()] + _skip_external(href, full_tag) + html_body[match.end():]
                    continue
                try:
                    resp, _, _, _ = await self._custom_fetch(scheme=scheme, host=host, port=port, path=request_path, ip=ip, tab=tab)
                    if resp.is_ok:
                        replacement = f"<style>{resp.body}</style>"
                        html_body = html_body[:match.start()] + replacement + html_body[match.end():]
                except Exception:
                    pass

        img_matches = list(re.finditer(img_pattern, html_body, re.I))
        for match in reversed(img_matches):
            full_tag = match.group(0)
            src = match.group(1)
            is_same, request_path = _is_same_origin(src)
            if not is_same:
                if not src.startswith("data:") and is_same is False:
                    html_body = html_body[:match.start()] + _skip_external(src, full_tag) + html_body[match.end():]
                continue
            try:
                resp, _, _, _ = await self._custom_fetch(scheme=scheme, host=host, port=port, path=request_path, ip=ip, tab=tab)
                if resp.is_ok:
                    mime = resp.header("Content-Type", "application/octet-stream")
                    encoded = base64.b64encode(resp.body_bytes).decode("ascii")
                    data_uri = f"data:{mime};base64,{encoded}"
                    new_tag = full_tag.replace(f'src="{src}"', f'src="{data_uri}"', 1).replace(f"src='{src}'", f'src="{data_uri}"', 1)
                    html_body = html_body[:match.start()] + new_tag + html_body[match.end():]
            except Exception:
                pass

        return html_body

    def _page_header(
        self,
        eyebrow: str,
        title: str,
        lead: str,
        chips: Optional[list[str]] = None,
    ) -> str:
        chip_html = "".join(
            f"<span class='chip'>{html.escape(chip)}</span>"
            for chip in (chips or [])
            if chip.strip()
        )
        return (
            "<header class='page-hero'>"
            "<div class='page-copy'>"
            f"<p class='eyebrow'>{html.escape(eyebrow)}</p>"
            f"<h1>{html.escape(title)}</h1>"
            f"<p class='lead'>{html.escape(lead)}</p>"
            "</div>"
            f"<div class='page-chips'>{chip_html}</div>"
            "</header>"
        )

    @staticmethod
    def _display_host(url: str) -> str:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc
        return url.replace("http://", "").replace("https://", "").rstrip("/")

    @staticmethod
    def _favicon_url_for_url(url: str, size: int = 64) -> str:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname or ""
        if not host:
            return ""
        return f"https://www.google.com/s2/favicons?domain={quote_plus(host)}&sz={int(size)}"

    def _render_new_tab(self, tab: BrowserTab, show_add_shortcut: bool = False):
        logo_path = Path(__file__).resolve().parents[2] / "logo.png"
        logo_src = self._image_data_uri(logo_path)
        search_name = html.escape(self.settings.search_engine.title())
        shortcut_cards = "".join(
            (
                "<article class='shortcut-card'>"
                "<a class='shortcut-delete' href='internal:delete-shortcut?url={encoded}' aria-label='Delete shortcut'>×</a>"
                "<a class='shortcut-link' href='{url}'>"
                "<span class='shortcut-icon'>"
                "<img src='{icon_url}' alt='' onerror=\"this.style.display='none';this.nextElementSibling.style.display='block'\">"
                "<b>{letter}</b>"
                "</span>"
                "<span class='shortcut-label'>{label}</span>"
                "</a>"
                "</article>"
            ).format(
                encoded=quote_plus(self._shortcut_url(item)),
                url=html.escape(self._shortcut_url(item)),
                icon_url=html.escape(self._favicon_url_for_url(self._shortcut_url(item), 64)),
                letter=html.escape(self._shortcut_label(item)[:1].upper() or "W"),
                label=html.escape(self._shortcut_label(item)),
            )
            for item in self.shortcuts[:8]
        )
        logo_img = f"<img src='{html.escape(logo_src)}'>" if logo_src else ""
        add_shortcut_modal = ""
        if show_add_shortcut:
            add_shortcut_modal = """
            <div class="modal-backdrop">
              <section class="add-shortcut-dialog">
                <div class="dialog-head">
                  <h2>Add shortcut</h2>
                  <a class="dialog-close" href="internal:home" aria-label="Close">×</a>
                </div>
                <form class="shortcut-form" action="internal:add-shortcut" method="get">
                  <label class="field"><span>Name</span><input name="name" autofocus placeholder="Label"></label>
                  <label class="field"><span>URL</span><input name="url" placeholder="https://example.local"></label>
                  <div class="action-row">
                    <a class="ghost-link" href="internal:home">Cancel</a>
                    <button type="submit">Save shortcut</button>
                  </div>
                </form>
              </section>
            </div>
            """
        body = f"""
        <main class="page-shell home-shell">
          <section class="home-hero">
            <div class="home-brand">
              <div class="brand-mark">{logo_img}</div>
              <h1>WaterCat</h1>
            </div>
            <form class="home-search" action="internal:go" method="get">
              <div class="search-shell">
                <span class="search-glyph">&#8981;</span>
                <input name="q" autofocus placeholder="Search with {search_name} or enter address">
              </div>
            </form>
          </section>
          <section class="shortcuts-surface">
            <div class="shortcut-grid">
              {shortcut_cards}
              <article class="shortcut-card add-shortcut-card">
                <a class="shortcut-link" href="internal:add-shortcut-form">
                  <span class="shortcut-icon plus-icon">+</span>
                  <span class="shortcut-label">Add</span>
                </a>
              </article>
            </div>
          </section>
          {add_shortcut_modal}
        </main>
        """
        tab.view.setHtml(self._page_html("WaterCat Browser", body))

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
            (
                "<a class='list-card' href='{url}'>"
                "<div class='list-copy'>"
                "<span class='list-eyebrow'>Local match</span>"
                "<strong>{url}</strong>"
                "<p>{host}</p>"
                "</div>"
                "<span class='list-meta'>Open</span>"
                "</a>"
            ).format(
                url=html.escape(item),
                host=html.escape(self._display_host(item)),
            )
            for item in matches
        ) or (
            "<div class='empty-state'>"
            "<h3>No local matches yet</h3>"
            "<p>Search results from your history and bookmarks will appear here once you have visited or saved them.</p>"
            "</div>"
        )
        engine_url = self._engine_search_url(query)
        engine_results = "".join(
            (
                "<a class='result-card' href='{url}'>"
                "<span class='list-eyebrow'>External result</span>"
                "<strong>{title}</strong>"
                "<p>{url}</p>"
                "</a>"
            ).format(
                title=html.escape(title),
                url=html.escape(url),
            )
            for title, url in self._external_search_results(query)
        )
        engine_name = self.settings.search_engine.title()
        body = (
            "<main class='page-shell'>"
            + self._page_header(
                "Search",
                f"Search results for “{query or 'your query'}”",
                "WaterCat surfaces external search suggestions alongside the pages you already visited or saved locally.",
                [engine_name, f"{len(matches)} local matches"],
            )
            + "<section class='grid grid-2'>"
            + "<div class='surface'>"
            + "<div class='surface-head'>"
            + "<div><p class='section-kicker'>Search engine</p><h2>Web results</h2></div>"
            + f"<a class='ghost-link' href='{html.escape(engine_url)}'>Open {html.escape(engine_name)}</a>"
            + "</div>"
            + "<div class='result-stack'>"
            + (
                engine_results
                or "<div class='empty-state'><h3>No remote results</h3><p>WaterCat fell back to local suggestions because the search engine page could not be fetched.</p></div>"
            )
            + "</div></div>"
            + "<div class='surface'>"
            + "<div class='surface-head'><div><p class='section-kicker'>Library</p><h2>Local matches</h2></div></div>"
            + "<div class='list-stack'>"
            + local_links
            + "</div></div></section></main>"
        )
        tab.view.setHtml(self._page_html("Search", body))

    def _render_vpn_check_page(self, tab: BrowserTab):
        self._spawn_task(self._render_vpn_check_page_async(tab))

    async def _render_vpn_check_page_async(self, tab: BrowserTab):
        direct_ip, direct_error = await asyncio.to_thread(self._fetch_direct_ip)
        vpn_ip, vpn_error, vpn_source = await self._fetch_vpn_ip()
        direct_text = direct_ip or f"Error: {direct_error}"
        vpn_text = vpn_ip or f"Error: {vpn_error}"
        verdict = "VPN route is working." if vpn_ip and vpn_ip != direct_ip else "VPN route is not changing the visible IP."
        if vpn_ip and not direct_ip:
            verdict = "VPN route returned a public IP."

        rows = [
            ("Local direct IP", direct_text),
            ("Mini VPN IP", vpn_text),
            ("VPN endpoint", self.vpn_client.endpoint),
            ("VPN toggle", "On" if self.settings.enable_vpn else "Off"),
            ("Check source", vpn_source or "-"),
        ]
        row_html = "".join(
            "<div class='metric-row'>"
            f"<span>{html.escape(label)}</span>"
            f"<strong>{html.escape(value)}</strong>"
            "</div>"
            for label, value in rows
        )
        body = (
            "<main class='page-shell'>"
            + self._page_header(
                "Mini VPN",
                "VPN IP check",
                "This diagnostic uses the configured Mini VPN tunnel directly against HTTP IP endpoints.",
            )
            + "<section class='surface'>"
            + f"<h2>{html.escape(verdict)}</h2>"
            + "<div class='metric-list'>"
            + row_html
            + "</div>"
            + "<p class='muted-note'>HTTPS pages loaded by Qt WebEngine do not use this application-layer tunnel, so public IP checker sites opened normally can still show the local IP.</p>"
            + "<div class='action-row'>"
            + "<a class='button-link' href='internal:vpn-check'>Run again</a>"
            + "<a class='ghost-link' href='http://httpbin.org/ip'>Open HTTP test URL</a>"
            + "</div>"
            + "</section></main>"
        )
        tab.view.setHtml(self._page_html("VPN Check", body))
        self._set_status(verdict)

    def _fetch_direct_ip(self) -> tuple[str, str]:
        try:
            request = Request(
                "http://api.ipify.org/",
                headers={"User-Agent": "MiniWebBrowser/1.0", "Accept": "text/plain,*/*"},
            )
            with urlopen(request, timeout=4) as response:
                return response.read(128).decode("utf-8", errors="replace").strip(), ""
        except Exception as exc:
            return "", str(exc)

    async def _fetch_vpn_ip(self) -> tuple[str, str, str]:
        checks = [
            ("api.ipify.org", "/", "plain"),
            ("icanhazip.com", "/", "plain"),
            ("httpbin.org", "/ip", "json"),
        ]
        last_error = ""
        for host, path, response_type in checks:
            try:
                ip = await asyncio.to_thread(socket.gethostbyname, host)
                response = await self.vpn_client.get(ip=ip, port=80, path=path, host=host)
                body = response.body.strip()
                if response_type == "json":
                    parsed = json.loads(body)
                    body = str(parsed.get("origin", "")).strip()
                body = body.splitlines()[0].strip()
                if response.status_code == 200 and body:
                    return body, "", host
                last_error = f"{host}: {response.status_code} {response.status_text}"
            except Exception as exc:
                last_error = f"{host}: {exc}"
        return "", last_error, ""

    def _render_error(self, tab: BrowserTab, title: str, message: str, code: int = 500):
        if code == 404 or "not found" in title.lower():
            icon = "&#128269;"
            hint = "The page you're looking for doesn't exist. Check the address or jump back to the new tab page."
        elif "timeout" in title.lower() or code == 504:
            icon = "&#9203;"
            hint = "The server took too long to respond. Verify the stack is running and try again."
        elif "rate" in title.lower() or code == 429:
            icon = "&#9888;&#65039;"
            hint = "Too many requests hit the resolver. Wait briefly before retrying."
        elif "invalid" in title.lower() or "url" in title.lower():
            icon = "&#9888;&#65039;"
            hint = "The address format is invalid. Use http:// and include a valid host."
        elif "bad gateway" in title.lower() or code == 502:
            icon = "&#128268;"
            hint = "The upstream response could not be parsed cleanly. Check the HTTP server output."
        else:
            icon = "&#128683;"
            hint = "Check the DNS record, server IP, port, or whether the HTTP server is running."

        body = (
            "<main class='page-shell error-shell'>"
            "<section class='surface error-card'>"
            f"<div class='error-icon'>{icon}</div>"
            f"<p class='eyebrow'>Error {code}</p>"
            f"<h1>{html.escape(title)}</h1>"
            f"<p class='lead'>{html.escape(hint)}</p>"
            f"<pre>{html.escape(message)}</pre>"
            "<div class='action-row center'>"
            "<a class='button-link' href='internal:home'>Back to New Tab</a>"
            "</div>"
            "</section>"
            "</main>"
        )
        tab.view.setHtml(self._page_html(title, body, error=True))
        tab.title = title
        self._update_tab_label(tab)
        self._set_status(title)

    def _render_download_page(self, tab: BrowserTab, response: HTTPResponse):
        size = len(response.body_bytes)
        content_type = html.escape(response.header("Content-Type", "application/octet-stream"))
        size_str = f"{size:,}" if size >= 1000 else str(size)
        body = (
            "<main class='page-shell'>"
            + self._page_header(
                "Response",
                "Download ready",
                "The response body is available to save locally from the browser menu.",
                [content_type, f"{size_str} bytes"],
            )
            + "<section class='surface center-card'>"
            + "<div class='download-icon'>&#128229;</div>"
            + "<h2>Save the current response</h2>"
            + "<p class='lead compact'>Use Menu > Download to write the fetched bytes to disk without leaving the current tab.</p>"
            + "</section></main>"
        )
        tab.view.setHtml(self._page_html("Download ready", body))

    def _render_text_response(self, tab: BrowserTab, response: HTTPResponse):
        content_type = response.header("Content-Type", "text/plain")
        size = len(response.body_bytes)
        size_str = f"{size:,}" if size >= 1000 else str(size)
        body_text = response.body.strip()
        if "application/json" in content_type.lower():
            try:
                body_text = json.dumps(json.loads(response.body), indent=2)
            except json.JSONDecodeError:
                pass
        body = (
            "<main class='page-shell'>"
            + self._page_header(
                "Response",
                "Response body",
                "The custom loader received a displayable response.",
                [html.escape(content_type), f"{size_str} bytes"],
            )
            + "<section class='surface'>"
            + f"<pre>{html.escape(body_text)}</pre>"
            + "</section></main>"
        )
        tab.view.setHtml(self._page_html("Response", body))

    @staticmethod
    def _is_displayable_response(content_type: str) -> bool:
        content_type = (content_type or "").lower()
        return (
            content_type.startswith("text/")
            or "application/json" in content_type
            or "application/xml" in content_type
            or "application/javascript" in content_type
        )

    def _open_settings_page(self):
        self._show_settings_tab()

    def _show_settings_tab(self):
        self._new_tab("", False)
        tab = self._current_tab()
        if not tab:
            return
        cookie_count = len(self.cookie_jar)
        cache_count = self.http_cache.entry_count()

        blocked_html = ""
        trusted_html = ""
        if self._phishing_reputation:
            user_rules = load_user_rules_raw(PHISHING_RULES_PATH) if PHISHING_RULES_PATH.exists() else {}
            user_blocked = set(user_rules.get("blocked_domains", []))
            user_prefixes = list(user_rules.get("blocked_url_prefixes", []))
            user_keywords = set(user_rules.get("suspicious_keywords", []))
            user_trusted = set(user_rules.get("trusted_hosts", []))
            builtin_blocked = self._phishing_reputation.blocked_domains - user_blocked

            def _item_row(label, value, action_url):
                return (
                    "<div class='kv-row' style='align-items:center'>"
                    f"<span>{html.escape(label)}</span>"
                    "<div style='display:flex;align-items:center;gap:8px'>"
                    f"<code style='overflow-wrap:anywhere;max-width:240px'>{html.escape(value)}</code>"
                    f"<a class='ghost-link' href='{action_url}' style='font-size:12px;padding:4px 8px'>Remove</a>"
                    "</div></div>"
                )

            blocked_html = "<div class='kv-list'>"
            if builtin_blocked:
                builtin_list = ", ".join(sorted(builtin_blocked)[:10])
                blocked_html += f"<div class='kv-row'><span>Built-in</span><b style='color:var(--muted);font-size:13px'>{html.escape(builtin_list)}</b></div>"
            for d in sorted(user_blocked):
                blocked_html += _item_row("User", d, f"internal:phishing-remove-blocked?domain={quote_plus(d)}")
            for pfx in user_prefixes:
                blocked_html += _item_row("URL prefix", pfx, f"internal:phishing-remove-prefix?prefix={quote_plus(pfx)}")
            for kw in sorted(user_keywords):
                blocked_html += _item_row("Keyword", kw, f"internal:phishing-remove-keyword?keyword={quote_plus(kw)}")
            blocked_html += "</div>"

            if not user_blocked and not user_prefixes and not user_keywords and not builtin_blocked:
                blocked_html = "<p style='color:var(--muted)'>No custom rules yet. Add blocked domains, URL prefixes, or suspicious keywords below.</p>"

            trusted_html = "<div class='kv-list'>"
            for th in sorted(user_trusted):
                trusted_html += _item_row("Trusted host", th, f"internal:phishing-remove-trusted?host={quote_plus(th)}")
            trusted_html += "</div>"
            if not user_trusted:
                trusted_html = "<p style='color:var(--muted)'>No trusted hosts. Add hosts to suppress brand-impersonation warnings for legitimate subdomains.</p>"

        phishing_section = ""
        if self._phishing_enabled:
            phishing_section = (
                "<div class='surface'>"
                + "<div class='surface-head'><div><p class='section-kicker'>Security</p><h2>Phishing rules</h2></div></div>"
                + "<p class='section-kicker' style='margin-top:12px'>Blocked rules</p>"
                + blocked_html
                + "<form class='settings-form' style='margin-top:14px' action='internal:phishing-add-blocked' method='get'>"
                + "<label class='field'><span>Block domain</span>"
                + "<div style='display:flex;gap:8px'>"
                + "<input name='domain' placeholder='evil.example.com'>"
                + "<button type='submit'>Add</button>"
                + "</div></label></form>"
                + "<form class='settings-form' action='internal:phishing-add-prefix' method='get'>"
                + "<label class='field'><span>Block URL prefix</span>"
                + "<div style='display:flex;gap:8px'>"
                + "<input name='prefix' placeholder='https://evil.test/collect'>"
                + "<button type='submit'>Add</button>"
                + "</div></label></form>"
                + "<form class='settings-form' action='internal:phishing-add-keyword' method='get'>"
                + "<label class='field'><span>Suspicious keyword</span>"
                + "<div style='display:flex;gap:8px'>"
                + "<input name='keyword' placeholder='wallet-verify'>"
                + "<button type='submit'>Add</button>"
                + "</div></label></form>"
                + "</div>"
                + "<div class='surface'>"
                + "<div class='surface-head'><div><p class='section-kicker'>Trust</p><h2>Trusted hosts</h2></div></div>"
                + trusted_html
                + "<form class='settings-form' style='margin-top:8px' action='internal:phishing-add-trusted' method='get'>"
                + "<label class='field'><span>Trust host</span>"
                + "<div style='display:flex;gap:8px'>"
                + "<input name='host' placeholder='trusted.example.com'>"
                + "<button type='submit'>Add</button>"
                + "</div></label></form>"
                + "</div>"
                + "<div class='surface'>"
                + "<div class='surface-head'><div><p class='section-kicker'>Safe Browsing</p><h2>Google Safe Browsing</h2></div></div>"
                + ("<p style='color:var(--green)'>Enabled &mdash; URLs are checked against Google Safe Browsing API.</p>"
                   if GOOGLE_SAFE_BROWSING_API_KEY else
                   "<p style='color:var(--muted)'>Disabled. Set <code>BROWSER_GOOGLE_SAFE_BROWSING_API_KEY</code> in your <code>.env</code> to enable.</p>")
                + "<p class='kv-list' style='font-size:13px;color:var(--muted);margin-top:4px'>"
                + "Detects malware, social engineering, unwanted software, and potentially harmful applications."
                + "</p></div>"
            )

        body = (
            "<main class='page-shell'>"
            + self._page_header(
                "Preferences",
                "Settings",
                "Adjust the parts of WaterCat that matter day to day without touching the browser’s network configuration files.",
                [
                    f"Theme: {self.settings.theme.title()}",
                    f"Search: {self.settings.search_engine.title()}",
                    f"Font: {self.settings.font_size}px",
                ],
            )
            + "<section class='grid grid-2'>"
            + "<div class='surface'>"
            + "<div class='surface-head'><div><p class='section-kicker'>Appearance</p><h2>Browser look and feel</h2></div></div>"
            + "<form class='settings-form' action='internal:save-settings' method='get'>"
            + "<label class='field'><span>Theme</span>"
            + "<select name='theme'>"
            + f"<option value='light' {'selected' if self.settings.theme == 'light' else ''}>Light</option>"
            + f"<option value='dark' {'selected' if self.settings.theme == 'dark' else ''}>Dark</option>"
            + "</select></label>"
            + f"<label class='field'><span>Font size</span><input type='number' min='12' max='24' name='font_size' value='{self.settings.font_size}'></label>"
            + "<label class='field'><span>Search engine</span>"
            + "<select name='search_engine'>"
            + f"<option value='google' {'selected' if self.settings.search_engine == 'google' else ''}>Google</option>"
            + f"<option value='bing' {'selected' if self.settings.search_engine == 'bing' else ''}>Bing</option>"
            + "</select></label>"
            + "<label class='field'><span>Enable browser HTTP cache</span>"
            + f"<input type='hidden' name='enable_http_cache_off' value='off'>"
            + f"<input type='checkbox' name='enable_http_cache' value='on' {'checked' if self.settings.enable_http_cache else ''} style='width:auto'>"
            + "</label>"
            + "<div class='action-row'><button type='submit'>Save settings</button></div>"
            + "</form></div>"
            + "<div class='surface'>"
            + "<div class='surface-head'><div><p class='section-kicker'>Storage</p><h2>Manage local data</h2></div></div>"
            + "<div class='kv-list'>"
            + "<div class='kv-row'><span>Cookies</span><b>{cookie_count}</b></div>"
            + "<div class='kv-row'><span>HTTP cache entries</span><b>{cache_count}</b></div>"
            + "</div>"
            + "<a class='button-link' href='internal:clear-cookies'>Clear cookies</a>"
            + "<a class='button-link' href='internal:clear-cache'>Clear browser cache</a>"
            + "</div></div>"
            + "<div class='surface'>"
            + "<div class='surface-head'><div><p class='section-kicker'>Connection</p><h2>Current runtime values</h2></div></div>"
            + "<div class='kv-list'>"
            + f"<div class='kv-row'><span>DNS server</span><b>{html.escape(self.settings.dns_host)}:{self.settings.dns_port}</b></div>"
            + f"<div class='kv-row'><span>HTTP default port</span><b>{self.settings.http_default_port}</b></div>"
            + f"<div class='kv-row'><span>Home route</span><b>{html.escape(self.settings.home_url)}</b></div>"
            + f"<div class='kv-row'><span>Search route</span><b>{html.escape(self.settings.search_url)}</b></div>"
            + f"<div class='kv-row'><span>DNS cache</span><b>{'Enabled' if self.settings.enable_dns_cache else 'Disabled'}</b></div>"
            + "</div></div>"
            + phishing_section
            + "</section></main>"
        )
        tab.view.setHtml(self._page_html("Settings", body))
        tab.title = "Settings"
        self._update_tab_label(tab)

    def _page_html(self, title: str, body: str, error: bool = False) -> str:
        c = self._theme_colors()
        error_color = c["error"] if error else c["text"]
        return (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>{html.escape(title)}</title>"
            f"<style>:root{{--bg:{c['window']};--bg-alt:{c['window_alt']};--panel:{c['panel']};--panel-alt:{c['panel2']};--panel-soft:{c['panel3']};--text:{c['text']};--muted:{c['muted']};--muted-soft:{c['muted_soft']};--border:{c['border']};--border-soft:{c['border2']};--accent:{c['accent']};--accent-hover:{c['accent_hover']};--accent-soft:{c['accent_soft']};--accent-ring:{c['accent_ring']};--shadow:{c['shadow']};--shadow-soft:{c['shadow_soft']};--hero-1:{c['hero_1']};--hero-2:{c['hero_2']};--hero-3:{c['hero_3']};}}"
            "*{box-sizing:border-box}"
            f"body{{margin:0;min-height:100vh;font-family:'Segoe UI Variable Text','Aptos','Segoe UI','Inter',sans-serif;color:var(--text);background:radial-gradient(circle at 12% 15%, var(--hero-1), transparent 24%),radial-gradient(circle at 88% 18%, var(--hero-2), transparent 22%),radial-gradient(circle at 58% 82%, var(--hero-3), transparent 25%),linear-gradient(180deg, var(--bg-alt) 0%, var(--bg) 46%, var(--bg) 100%);font-size:{self.settings.font_size}px;line-height:1.5}}"
            "a{color:var(--accent);text-decoration:none}"
            "a:hover{color:var(--accent-hover)}"
            "h1,h2,h3,p{margin:0}"
            f"h1{{color:{error_color}}}"
            "pre{white-space:pre-wrap;background:var(--panel-alt);border:1px solid var(--border);padding:18px 20px;border-radius:18px;overflow:auto;text-align:left}"
            "input,select,button{font:inherit}"
            "input,select{width:100%;background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:14px;padding:12px 14px;outline:none;transition:border-color .18s,box-shadow .18s}"
            "input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 4px var(--accent-ring)}"
            "button,.button-link{display:inline-flex;align-items:center;justify-content:center;gap:8px;background:var(--accent);color:white;border:0;border-radius:14px;padding:12px 18px;font-weight:600;cursor:pointer;transition:transform .18s,background .18s;box-shadow:0 10px 20px var(--shadow-soft)}"
            "button:hover,.button-link:hover{background:var(--accent-hover);color:white;transform:translateY(-1px)}"
            ".ghost-link{display:inline-flex;align-items:center;justify-content:center;border:1px solid var(--border);border-radius:999px;padding:9px 14px;background:var(--panel-alt);color:var(--text)}"
            ".ghost-link:hover{border-color:var(--accent);color:var(--accent)}"
            ".page-shell{max-width:1180px;margin:0 auto;padding:36px 30px 56px}"
            ".home-shell{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding-top:72px;padding-bottom:80px}"
            ".page-hero{display:flex;justify-content:space-between;gap:24px;align-items:flex-end;margin-bottom:24px}"
            ".page-copy{max-width:720px}"
            ".eyebrow,.section-kicker,.list-eyebrow,.brand-badge{font-size:12px;line-height:1.2;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);font-weight:700}"
            "h1{font-size:clamp(36px,5vw,54px);letter-spacing:-.045em}"
            "h2{font-size:26px;letter-spacing:-.03em}"
            ".lead{margin-top:12px;color:var(--muted);font-size:18px;max-width:660px}"
            ".lead.compact{max-width:560px;margin:12px auto 0}"
            ".page-chips{display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end;align-self:flex-start}"
            ".chip{display:inline-flex;align-items:center;gap:8px;padding:9px 14px;border-radius:999px;background:var(--panel-alt);border:1px solid var(--border);color:var(--muted);font-size:13px}"
            ".surface{background:linear-gradient(180deg, var(--panel) 0%, var(--panel-alt) 100%);border:1px solid var(--border);border-radius:28px;padding:24px;box-shadow:0 18px 40px var(--shadow-soft)}"
            ".surface-head{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;margin-bottom:18px}"
            ".surface-note{max-width:320px;color:var(--muted);font-size:14px;text-align:right}"
            ".grid{display:grid;gap:20px}"
            ".grid-2{grid-template-columns:minmax(0,1.35fr) minmax(280px,.95fr)}"
            ".brand{display:flex;justify-content:flex-start;gap:28px;align-items:flex-start;flex-wrap:wrap}"
            ".home-brand{display:flex;align-items:center;justify-content:center;gap:18px;margin-bottom:42px}"
            ".brand-mark{width:76px;height:76px;border-radius:22px;background:rgba(255,255,255,.74);border:1px solid var(--border);display:grid;place-items:center;box-shadow:0 16px 34px var(--shadow-soft)}"
            ".brand-mark img{width:64px;height:64px;object-fit:contain}"
            ".home-brand h1{font-size:40px;letter-spacing:0;font-weight:700;color:var(--text)}"
            ".brand-copy{max-width:700px}"
            ".brand-copy h1{margin-top:10px}"
            ".brand-copy p{margin-top:12px;color:var(--muted);font-size:18px;max-width:620px}"
            ".hero-chips{margin-top:6px}"
            ".home-hero{position:relative;width:min(980px,100%);padding:0}"
            ".home-search{margin:0 auto;width:100%}"
            ".search-shell{display:flex;align-items:center;gap:12px;height:64px;padding:0 18px;background:#4b4a56;border:0;border-radius:32px;box-shadow:0 10px 22px var(--shadow-soft)}"
            ".search-glyph{display:grid;place-items:center;width:32px;height:32px;border-radius:16px;background:transparent;border:0;color:white;font-size:18px;flex:0 0 auto}"
            ".search-shell input{flex:1;border:0;background:transparent;color:white;box-shadow:none;padding:10px 0;font-size:18px}"
            ".search-shell input::placeholder{color:rgba(255,255,255,.58)}"
            ".search-shell input:focus{box-shadow:none}"
            ".search-shell button{display:none}"
            ".shortcuts-surface{width:min(780px,100%);margin-top:54px}"
            ".shortcut-grid{display:flex;justify-content:center;align-items:flex-start;gap:28px;flex-wrap:wrap}"
            ".shortcut-card{position:relative;width:80px;min-height:112px;background:transparent;border:0;border-radius:16px}"
            ".shortcut-link{display:flex;flex-direction:column;align-items:center;gap:12px;color:var(--text)}"
            ".shortcut-link:hover{color:var(--text)}"
            ".shortcut-icon{display:grid;place-items:center;width:80px;height:80px;border-radius:13px;background:#55545f;border:0;font-size:28px;font-weight:700;color:white;box-shadow:0 8px 18px var(--shadow-soft)}"
            ".shortcut-icon img{width:48px;height:48px;object-fit:contain}"
            ".shortcut-icon b{display:none;font-size:28px;color:white}"
            ".plus-icon{font-size:38px;font-weight:400;color:rgba(255,255,255,.9)}"
            ".shortcut-label{display:block;width:104px;margin-left:-12px;text-align:center;color:var(--text);font-size:15px;font-weight:500;line-height:1.2;overflow:hidden;text-overflow:ellipsis}"
            ".shortcut-delete{position:absolute;top:-8px;right:-8px;display:grid;place-items:center;width:22px;height:22px;border-radius:999px;background:rgba(239,68,68,.92);border:1px solid rgba(255,255,255,.7);color:white;font-weight:700;opacity:0;transition:opacity .15s}"
            ".shortcut-card:hover .shortcut-delete{opacity:1}"
            ".shortcut-delete:hover{background:rgba(239,68,68,.2);color:var(--error)}"
            ".modal-backdrop{position:fixed;inset:0;display:grid;place-items:center;background:rgba(17,24,39,.28);backdrop-filter:blur(4px);padding:24px;z-index:20}"
            ".add-shortcut-dialog{width:min(440px,100%);background:var(--panel);border:1px solid var(--border);border-radius:18px;box-shadow:0 24px 70px var(--shadow);padding:22px}"
            ".dialog-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}"
            ".dialog-head h2{font-size:22px;letter-spacing:0}"
            ".dialog-close{display:grid;place-items:center;width:32px;height:32px;border-radius:999px;background:var(--panel-alt);border:1px solid var(--border);color:var(--text);font-size:18px;font-weight:700}"
            ".shortcut-form{display:flex;flex-direction:column;gap:14px}"
            ".settings-form{display:grid;gap:14px}"
            ".field{display:grid;gap:8px;color:var(--muted);font-weight:600}"
            ".action-row{display:flex;gap:12px;align-items:center;margin-top:8px;flex-wrap:wrap}"
            ".action-row.center{justify-content:center}"
            ".kv-list,.list-stack,.result-stack{display:grid;gap:12px}"
            ".kv-row{display:flex;justify-content:space-between;gap:18px;align-items:flex-start;padding:14px 0;border-bottom:1px solid var(--border-soft)}"
            ".kv-row:last-child{border-bottom:0;padding-bottom:0}"
            ".kv-row span{color:var(--muted)}"
            ".kv-row b{font-weight:600;text-align:right;overflow-wrap:anywhere}"
            ".metric-list{display:grid;gap:0;margin-top:18px;margin-bottom:18px;border:1px solid var(--border);border-radius:18px;overflow:hidden;background:var(--panel)}"
            ".metric-row{display:flex;justify-content:space-between;gap:18px;padding:14px 16px;border-bottom:1px solid var(--border-soft)}"
            ".metric-row:last-child{border-bottom:0}"
            ".metric-row span{color:var(--muted)}"
            ".metric-row strong{text-align:right;overflow-wrap:anywhere}"
            ".muted-note{color:var(--muted);margin:10px 0 16px}"
            ".list-card,.result-card{display:flex;justify-content:space-between;gap:18px;padding:18px 20px;border:1px solid var(--border);border-radius:20px;background:var(--panel);box-shadow:0 10px 20px var(--shadow-soft);color:var(--text);transition:border-color .18s,transform .18s}"
            ".list-card:hover,.result-card:hover{border-color:var(--accent);color:var(--text);transform:translateY(-1px)}"
            ".list-copy{display:grid;gap:8px;min-width:0}"
            ".list-copy strong,.result-card strong{font-size:16px;letter-spacing:-.02em;overflow-wrap:anywhere}"
            ".list-copy p,.result-card p{color:var(--muted);font-size:14px;overflow-wrap:anywhere}"
            ".list-meta{color:var(--muted);font-size:13px;white-space:nowrap;align-self:center}"
            ".empty-state,.center-card{padding:28px;border:1px dashed var(--border);border-radius:22px;background:rgba(255,255,255,.22);text-align:center}"
            ".empty-state h3{font-size:22px;letter-spacing:-.03em}"
            ".empty-state p{margin-top:10px;color:var(--muted)}"
            ".error-shell{display:grid;place-items:center;min-height:100vh}"
            ".error-card{max-width:760px;text-align:center}"
            ".error-icon,.download-icon{display:grid;place-items:center;width:88px;height:88px;margin:0 auto 18px;border-radius:26px;background:var(--panel);border:1px solid var(--border);font-size:40px;box-shadow:0 16px 30px var(--shadow-soft)}"
            "@media (max-width: 900px){.page-shell{padding:26px 18px 40px}.page-hero,.brand,.surface-head{display:grid;grid-template-columns:1fr}.grid-2{grid-template-columns:1fr}.page-chips,.hero-chips{justify-content:flex-start}.surface-note{text-align:left;max-width:none}.search-shell{flex-wrap:wrap}.search-shell button{width:100%}.shortcut-grid{grid-template-columns:repeat(auto-fit,minmax(140px,1fr))}.kv-row,.list-card,.result-card{flex-direction:column}.list-meta{align-self:flex-start}}"
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

    def _request_headers(self, host: str, scheme: str, request_path: str, tab: BrowserTab) -> dict[str, str]:
        jar = self._get_cookie_jar(tab)
        cookie_header = jar.request_cookie_header(host, scheme, request_path)
        if cookie_header:
            return {"Cookie": cookie_header}
        return {}

    def _store_cookies(self, host: str, scheme: str, request_path: str, response: HTTPResponse, tab: BrowserTab):
        if not response.set_cookie_headers:
            return
        jar = self._get_cookie_jar(tab)
        new_cookies = jar.store_from_response(response.set_cookie_headers, host, scheme, request_path)
        if not tab.incognito:
            jar.save()
            for cookie in new_cookies:
                self._set_qt_cookie(cookie)

    async def _custom_fetch(
        self,
        scheme: str,
        host: str,
        port: int,
        path: str,
        ip: str,
        tab: BrowserTab,
    ) -> tuple[HTTPResponse, str, dict[str, str], dict[str, str]]:
        """Centralized fetch helper: DNS already resolved, handles cookies + cache.
        Returns (response, cache_state, request_headers, route_meta)."""
        request_headers = self._request_headers(host, scheme, path, tab)
        use_vpn = self._should_use_vpn(host)
        route_meta = {
            "route": "vpn" if use_vpn else "direct",
            "vpn_server": self.vpn_client.endpoint if use_vpn else "",
        }
        cache_state = "bypass"
        cached_entry = None

        if self.settings.enable_http_cache:
            cached_entry = await self.http_cache.lookup_async(scheme, host, port, path)
            if cached_entry:
                if cached_entry.is_fresh:
                    response = HTTPResponse(
                        status_code=cached_entry.status_code,
                        status_text=cached_entry.status_text,
                        headers=dict(cached_entry.headers),
                        body=cached_entry.body_bytes.decode("utf-8", errors="replace"),
                        raw=cached_entry.body_bytes.decode("utf-8", errors="replace"),
                        raw_bytes=cached_entry.body_bytes,
                        body_bytes=cached_entry.body_bytes,
                        set_cookie_headers=[],
                    )
                    # Inject form interception into HTML pages
                    if response.status_code == 200 and response.header("Content-Type").startswith("text/html"):
                        response.body_bytes = inject_form_intercept(response.body_bytes, f"{scheme}://{host}{path}")
                        response.body = response.body_bytes.decode("utf-8", errors="replace")
                    return response, "hit", request_headers, route_meta
                elif cached_entry.can_revalidate():
                    if cached_entry.etag:
                        request_headers["If-None-Match"] = cached_entry.etag
                    if cached_entry.last_modified:
                        request_headers["If-Modified-Since"] = cached_entry.last_modified

        client = self.vpn_client if use_vpn else self.http_client
        response = await client.get(
            ip=ip,
            port=port,
            path=path,
            host=host,
            extra_headers=request_headers,
            use_tls=(scheme == "https"),
        )

        self._store_cookies(host, scheme, path, response, tab)

        cc = response.header("Cache-Control").lower()
        if self.settings.enable_http_cache:
            cookie_in_use = bool(request_headers.get("Cookie"))
            has_set_cookie = bool(response.set_cookie_headers)
            if not cookie_in_use and not has_set_cookie and "no-store" not in cc:
                if response.status_code == 304 and cached_entry:
                    merged_headers = dict(cached_entry.headers)
                    for k, v in response.headers.items():
                        merged_headers[k] = v
                    response = HTTPResponse(
                        status_code=cached_entry.status_code,
                        status_text=cached_entry.status_text,
                        headers=merged_headers,
                        body=cached_entry.body_bytes.decode("utf-8", errors="replace"),
                        raw="",
                        raw_bytes=cached_entry.body_bytes,
                        body_bytes=cached_entry.body_bytes,
                        set_cookie_headers=response.set_cookie_headers,
                    )
                    cache_state = "revalidated"
                    await self.http_cache.store_async(
                        scheme, host, port, path,
                        cached_entry.status_code, cached_entry.status_text,
                        merged_headers, cached_entry.body_bytes,
                    )
                elif response.status_code == 200:
                    cache_state = "miss"
                    await self.http_cache.store_async(
                        scheme, host, port, path,
                        response.status_code, response.status_text,
                        dict(response.headers), response.body_bytes,
                    )
                else:
                    cache_state = "miss"
            else:
                cache_state = "miss"
        else:
            cache_state = "miss"

        # Inject form interception into HTML pages
        if response.status_code == 200 and response.header("Content-Type").startswith("text/html"):
            response.body_bytes = inject_form_intercept(response.body_bytes, f"{scheme}://{host}{path}")
            response.body = response.body_bytes.decode("utf-8", errors="replace")

        return response, cache_state, request_headers, route_meta

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
            disposition = tab.last_response.header("Content-Disposition")
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
        items = "".join(
            (
                "<a class='list-card' href='{url}'>"
                "<div class='list-copy'>"
                "<span class='list-eyebrow'>{visited_at}</span>"
                "<strong>{url}</strong>"
                "<p>{host}</p>"
                "</div>"
                "<span class='list-meta'>Open</span>"
                "</a>"
            ).format(
                visited_at=html.escape(entry.get("visited_at", "")),
                url=html.escape(entry.get("url", "")),
                host=html.escape(self._display_host(entry.get("url", ""))),
            )
            for entry in self.history
        ) or (
            "<div class='empty-state'>"
            "<h3>No history yet</h3>"
            "<p>Visited pages will appear here once you start browsing through the custom stack.</p>"
            "</div>"
        )
        body = (
            "<main class='page-shell'>"
            + self._page_header(
                "Library",
                "History",
                "Review the pages you opened recently and jump back into any route with one click.",
                [f"{len(self.history)} entries"],
            )
            + "<section class='surface'><div class='list-stack'>"
            + items
            + "</div></section></main>"
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
            (
                "<a class='list-card' href='{url}'>"
                "<div class='list-copy'>"
                "<span class='list-eyebrow'>Saved page</span>"
                "<strong>{url}</strong>"
                "<p>{host}</p>"
                "</div>"
                "<span class='list-meta'>Open</span>"
                "</a>"
            ).format(
                url=html.escape(url),
                host=html.escape(self._display_host(url)),
            )
            for url in self.bookmarks
        ) or (
            "<div class='empty-state'>"
            "<h3>No bookmarks yet</h3>"
            "<p>Save pages from the menu and they will appear here for quick access.</p>"
            "</div>"
        )
        body = (
            "<main class='page-shell'>"
            + self._page_header(
                "Library",
                "Bookmarks",
                "Keep important routes close so demos and repeat checks are only one click away.",
                [f"{len(self.bookmarks)} saved"],
            )
            + "<section class='surface'><div class='list-stack'>"
            + cards
            + "</div></section></main>"
        )
        tab.view.setHtml(self._page_html("Bookmarks", body))
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

    def _toggle_assistant(self, show: bool):
        if show:
            self._ai_assistant_init_check()
            self._assistant_sidebar.show()
            self.ai_assistant_action.setChecked(True)
            self._render_assistant_sidebar()
        else:
            self._assistant_sidebar.hide()
            self.ai_assistant_action.setChecked(False)

    def _ai_assistant_init_check(self):
        if self._ai_client is None:
            return
        if not self._ai_client.is_ready:
            err = self._ai_client.setup_error or "AI assistant is not available"
            session = self._get_assistant_session()
            session.last_error = err

    def _get_assistant_session(self) -> AssistantSessionState:
        tab = self._current_tab()
        if tab is None:
            sid = session.session_id if 'session' in dir() else id(0)
            if sid not in self._assistant_sessions:
                self._assistant_sessions[sid] = AssistantSessionState()
            return self._assistant_sessions[sid]
        sid = id(tab)
        if sid not in self._assistant_sessions:
            self._assistant_sessions[sid] = AssistantSessionState()
        return self._assistant_sessions[sid]

    @staticmethod
    def _strip_html_text(source: str) -> str:
        if not source:
            return ""
        from html.parser import HTMLParser

        class _Stripper(HTMLParser):
            def __init__(self):
                super().__init__()
                self.text: list[str] = []

            def handle_data(self, data):
                self.text.append(data)

        try:
            stripper = _Stripper()
            stripper.feed(source)
            stripper.close()
        except Exception:
            return ""

        return " ".join(chunk for chunk in stripper.text if chunk.strip()).strip()

    def _fallback_page_text(self, tab: BrowserTab) -> str:
        if not tab.last_response or not tab.last_response.body:
            return ""
        return self._strip_html_text(tab.last_response.body)

    def _capture_page_context(
        self,
        session: AssistantSessionState,
        on_ready: Callable[[], None],
        preferred_selection: str = "",
    ):
        tab = self._current_tab()
        session.attached_url = ""
        session.attached_title = ""
        session.attached_page_text = ""
        session.attached_selection = preferred_selection.strip()

        if tab is None:
            on_ready()
            return
        if tab.current_url and not tab.current_url.startswith("internal:"):
            session.attached_url = tab.current_url
        session.attached_title = tab.title or ""
        if tab.last_event and tab.last_event.host:
            session.attached_title = session.attached_title or tab.last_event.host

        page = tab.view.page()
        if not session.attached_selection and page is not None:
            try:
                session.attached_selection = page.selectedText().strip()
            except Exception:
                session.attached_selection = ""

        if page is None:
            session.attached_page_text = self._fallback_page_text(tab)
            on_ready()
            return

        def _finish_capture(raw_text: str):
            page_text = (raw_text or "").strip()
            session.attached_page_text = page_text or self._fallback_page_text(tab)
            on_ready()

        try:
            page.toPlainText(_finish_capture)
            return
        except Exception:
            pass

        try:
            page.toHtml(lambda html_text: _finish_capture(self._strip_html_text(html_text)))
            return
        except Exception:
            session.attached_page_text = self._fallback_page_text(tab)
            on_ready()

    def _render_assistant_sidebar(self):
        session = self._get_assistant_session()
        err = session.last_error
        if self._ai_client and not self._ai_client.is_ready:
            err = self._ai_client.setup_error or err

        if err and not session.messages:
            c = self._theme_colors()
            html_body = (
                "<div style='padding:24px;text-align:center'>"
                f"<p style='font-size:32px;margin:0 0 12px'>&#129302;</p>"
                f"<h3 style='margin:0 0 8px;color:{c['text']}'>AI Assistant Setup</h3>"
                f"<p style='color:{c['muted']};font-size:13px'>{html.escape(err)}</p>"
                "</div>"
            )
            self.asst_transcript.setHtml(html_body)
            self.asst_streaming_label.hide()
            self.asst_transcript.show()
            return

        c = self._theme_colors()
        lines = []
        for msg in session.messages:
            lines.append(self._assistant_message_bubble_html(msg, c))
        transcript_html = "".join(lines) or (
            f"<p style='color:{c['muted_soft']};text-align:center;padding:20px'>"
            "Ask about this page or anything else."
            "</p>"
        )

        if session.has_context:
            chip_parts = []
            if session.attached_url:
                chip_parts.append(f"<span style='background:{c['accent_soft']};padding:2px 8px;border-radius:8px;margin:2px'>{html.escape(session.attached_url[:50])}</span>")
            if session.attached_selection:
                chip_parts.append("<span style='background:{};padding:2px 8px;border-radius:8px;margin:2px'>selection</span>".format(c['accent_soft']))
            if session.attached_page_text:
                chip_parts.append("<span style='background:{};padding:2px 8px;border-radius:8px;margin:2px'>page text</span>".format(c['accent_soft']))
            self.asst_context_chips.setText("".join(chip_parts))
            self.asst_context_chips.show()
        else:
            self.asst_context_chips.hide()

        self.asst_transcript.setHtml(
            f"<div style='font-family:system-ui;font-size:13px;line-height:1.5'>{transcript_html}</div>"
        )
        self.asst_transcript.verticalScrollBar().setValue(
            self.asst_transcript.verticalScrollBar().maximum()
        )

        streaming = session.streaming_text()
        if session.in_flight and streaming:
            self.asst_streaming_label.setText(streaming)
            self.asst_streaming_label.show()
        elif session.in_flight:
            self.asst_streaming_label.setText("Thinking...")
            self.asst_streaming_label.show()
        else:
            self.asst_streaming_label.hide()

        if session.in_flight:
            self.asst_send_btn.hide()
            self.asst_stop_btn.show()
        else:
            self.asst_send_btn.show()
            self.asst_stop_btn.hide()

    def _asst_preset(self, preset: str, selection: str = ""):
        session = self._get_assistant_session()
        if session.in_flight:
            return

        def _send_preset():
            request = build_preset_request(preset, session, self._ai_config)
            if request is None:
                session.last_error = "No page content available for this request."
                self._render_assistant_sidebar()
                return
            session.last_error = ""
            session.messages.append(
                AssistantMessage(
                    role="user",
                    content=request.display_content,
                    model_content=request.model_content,
                )
            )
            self._render_assistant_sidebar()
            self._asst_start_stream(session, request)

        self._capture_page_context(session, _send_preset, preferred_selection=selection)

    def _asst_send(self):
        text = self.asst_composer.text().strip()
        if not text:
            return
        session = self._get_assistant_session()
        if session.in_flight:
            return
        self.asst_composer.clear()

        def _send_custom():
            session.last_error = ""
            request = build_custom_request(text, session, self._ai_config)
            session.messages.append(
                AssistantMessage(
                    role="user",
                    content=request.display_content,
                    model_content=request.model_content,
                )
            )
            self._render_assistant_sidebar()
            self._asst_start_stream(session, request)

        self._capture_page_context(session, _send_custom)

    def _asst_start_stream(
        self,
        session: Optional[AssistantSessionState] = None,
        request: Optional[AssistantRequest] = None,
    ):
        session = session or self._get_assistant_session()
        request = request or AssistantRequest(
            display_content="",
            model_content="",
            mode="page-summary",
            use_grounding=False,
            stream=self._ai_config.stream,
        )
        if session.in_flight:
            return
        if self._ai_client is None or not self._ai_client.is_ready:
            session.last_error = self._ai_client.setup_error if self._ai_client else "AI assistant is not available"
            self._render_assistant_sidebar()
            return

        session.cancelled = False
        session.in_flight = True
        session.pending_accumulated = ""
        session.last_error = ""
        self._render_assistant_sidebar()

        poll = QTimer()
        poll.timeout.connect(lambda: self._asst_poll(session, poll))
        poll.start(200)
        self._asst_worker_start(session, request)

    def _asst_poll(self, session: AssistantSessionState, poll_timer: QTimer):
        if not session.in_flight:
            poll_timer.stop()
            poll_timer.deleteLater()
            self._render_assistant_sidebar()

    def _asst_stop(self):
        session = self._get_assistant_session()
        session.cancelled = True

    def _asst_clear(self):
        session = self._get_assistant_session()
        session.cancelled = True
        session.messages.clear()
        session.attached_url = ""
        session.attached_title = ""
        session.attached_page_text = ""
        session.attached_selection = ""
        session.last_error = ""
        self._render_assistant_sidebar()

    def _asst_worker_start(self, session: AssistantSessionState, request: AssistantRequest):
        from threading import Thread

        def _run():
            accumulated = ""
            try:
                if request.stream:
                    for chunk_text in self._ai_client.generate_stream(session, request):
                        if session.cancelled:
                            break
                        accumulated += chunk_text
                        session.pending_accumulated = accumulated
                    if not session.cancelled and accumulated:
                        session.messages.append(
                            AssistantMessage(
                                role="assistant",
                                content=accumulated,
                                rendered_html=render_assistant_message_html(accumulated),
                            )
                        )
                else:
                    response = self._ai_client.generate_response(session, request)
                    if not session.cancelled and response.text:
                        session.messages.append(
                            AssistantMessage(
                                role="assistant",
                                content=response.text,
                                rendered_html=response.rendered_html or render_assistant_message_html(response.text),
                            )
                        )
            except Exception as e:
                if not session.cancelled:
                    session.last_error = str(e)
            finally:
                session.in_flight = False
                session.pending_accumulated = ""

        Thread(target=_run, daemon=True).start()

    def _assistant_message_bubble_html(self, msg: AssistantMessage, colors: dict[str, str]) -> str:
        if msg.role == "user":
            return (
                f"<div style='margin:6px 0;text-align:right'>"
                f"<div style='background:{colors['accent_soft']};color:{colors['accent']};padding:6px 12px;"
                f"border-radius:14px;font-size:13px;display:inline-block;max-width:85%;text-align:left'>"
                f"{html.escape(msg.content)}</div></div>"
            )

        body_html = msg.rendered_html or render_assistant_message_html(msg.content)
        return (
            f"<div style='margin:6px 0;text-align:left'>"
            f"<div style='background:{colors['panel2']};color:{colors['text']};padding:8px 12px;"
            f"border-radius:14px;font-size:13px;display:inline-block;max-width:85%;text-align:left'>"
            f"{body_html}</div></div>"
        )

    def _asst_open_for_action(self, preset: str = "", selection: str = ""):
        self._toggle_assistant(True)
        session = self._get_assistant_session()
        if preset:
            self._asst_preset(preset, selection)
        else:
            self._capture_page_context(
                session,
                self._render_assistant_sidebar,
                preferred_selection=selection,
            )

    def _open_assistant_tab(self):
        session = self._get_assistant_session()
        tab = self._current_tab()
        source_tab_id = str(id(tab)) if tab else ""
        url = "internal:assistant?source_tab={}&session_id={}".format(source_tab_id, session.session_id)
        self._new_tab("", False)
        assistant_tab = self._current_tab()
        if assistant_tab:
            assistant_tab.current_url = url
            assistant_tab.title = "AI Assistant"
            self._update_tab_label(assistant_tab)
            self._show_assistant_tab(assistant_tab, source_tab_id)

    def _show_assistant_tab(self, tab: BrowserTab, source_tab_id: str = ""):
        from urllib.parse import parse_qs
        url = tab.current_url
        params = parse_qs(urlparse(url).query)
        sid = params.get("source_tab", [source_tab_id])[0]

        source_session = None
        for tab_id, session in self._assistant_sessions.items():
            if str(tab_id) == sid:
                source_session = session
                break
        if source_session is None:
            source_session = self._get_assistant_session()

        c = self._theme_colors()
        msg_parts = []
        for m in source_session.messages:
            msg_parts.append(self._assistant_message_bubble_html(m, c))
        msgs = "".join(msg_parts) or (
            "<p style='color:{};text-align:center;padding:40px'>"
            "No conversation yet. Open the assistant sidebar to start.</p>"
        ).format(c['muted_soft'])

        body = (
            "<main class='page-shell'>"
            + self._page_header("Assistant", "AI Assistant", "Ask about the current page or anything else.")
            + "<section class='surface'><div style='font-family:system-ui;font-size:13px;line-height:1.5'>"
            + msgs
            + "</div></section></main>"
        )
        tab.view.setHtml(self._page_html("AI Assistant", body))

    def _show_context_menu(self, view: QWebEngineView, pos):
        tab = view.property("browser_tab")
        menu = QMenu(view)

        selection_text = ""
        page = view.page()
        try:
            selection_text = page.selectedText().strip()
        except Exception:
            pass

        if selection_text:
            menu.addAction("Summarize Selection").triggered.connect(
                lambda: self._asst_open_for_action("summarize", selection_text)
            )
            menu.addAction("Explain Selection").triggered.connect(
                lambda: self._asst_open_for_action("explain", selection_text)
            )
            menu.addAction("What Is This?").triggered.connect(
                lambda: self._asst_open_for_action("what-is-this", selection_text)
            )
            ai_ask = menu.addAction("Ask Assistant...")
            ai_ask.triggered.connect(
                lambda: self._asst_open_for_action("", selection_text)
            )
            menu.addSeparator()

        menu.addAction("Summarize Page").triggered.connect(
            lambda: self._asst_open_for_action("summarize")
        )
        menu.addAction("What Is This Page?").triggered.connect(
            lambda: self._asst_open_for_action("what-is-this")
        )
        menu.addAction("Ask About This Page...").triggered.connect(
            lambda: self._asst_open_for_action("")
        )
        menu.addSeparator()

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
        if action == "vpn-check":
            self._render_vpn_check_page(tab)
            self._mark_internal_tab(tab, "internal:vpn-check", "VPN Check", record_navigation)
            return
        if action == "add-shortcut-form":
            self._render_new_tab(tab, show_add_shortcut=True)
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
        if action == "clear-cookies":
            self.cookie_jar.clear()
            self.cookie_jar.save()
            for jar in self._incognito_jars.values():
                jar.clear()
            self._set_status("Cookies cleared.")
            self._show_settings_tab()
            return
        if action == "clear-cache":
            self.http_cache.clear()
            self._set_status("Browser cache cleared.")
            self._show_settings_tab()
            return
        if action == "phishing-continue":
            target = values.get("url", [""])[0]
            if target:
                decoded = unquote_plus(target)
                host = (urlparse(decoded).hostname or decoded).lower()
                self._phishing_session_host_allow.add(host)
                self._navigate(decoded, tab=tab, record_navigation=record_navigation)
            return
        if action == "phishing-add-blocked":
            domain = values.get("domain", [""])[0].strip()
            if domain:
                rules = load_user_rules_raw(PHISHING_RULES_PATH)
                rules.setdefault("blocked_domains", [])
                if domain not in rules["blocked_domains"]:
                    rules["blocked_domains"].append(domain)
                    save_user_rules(PHISHING_RULES_PATH, rules)
                    self._phishing_reputation = load_reputation(PHISHING_RULES_PATH)
            self._show_settings_tab()
            return
        if action == "phishing-remove-blocked":
            domain = values.get("domain", [""])[0]
            if domain:
                rules = load_user_rules_raw(PHISHING_RULES_PATH)
                rules["blocked_domains"] = [d for d in rules.get("blocked_domains", []) if d != domain]
                save_user_rules(PHISHING_RULES_PATH, rules)
                self._phishing_reputation = load_reputation(PHISHING_RULES_PATH)
            self._show_settings_tab()
            return
        if action == "phishing-add-prefix":
            prefix = values.get("prefix", [""])[0].strip()
            if prefix:
                rules = load_user_rules_raw(PHISHING_RULES_PATH)
                rules.setdefault("blocked_url_prefixes", [])
                if prefix not in rules["blocked_url_prefixes"]:
                    rules["blocked_url_prefixes"].append(prefix)
                    save_user_rules(PHISHING_RULES_PATH, rules)
                    self._phishing_reputation = load_reputation(PHISHING_RULES_PATH)
            self._show_settings_tab()
            return
        if action == "phishing-remove-prefix":
            prefix = values.get("prefix", [""])[0]
            if prefix:
                rules = load_user_rules_raw(PHISHING_RULES_PATH)
                rules["blocked_url_prefixes"] = [p for p in rules.get("blocked_url_prefixes", []) if p != prefix]
                save_user_rules(PHISHING_RULES_PATH, rules)
                self._phishing_reputation = load_reputation(PHISHING_RULES_PATH)
            self._show_settings_tab()
            return
        if action == "phishing-add-keyword":
            keyword = values.get("keyword", [""])[0].strip()
            if keyword:
                rules = load_user_rules_raw(PHISHING_RULES_PATH)
                rules.setdefault("suspicious_keywords", [])
                if keyword not in rules["suspicious_keywords"]:
                    rules["suspicious_keywords"].append(keyword)
                    save_user_rules(PHISHING_RULES_PATH, rules)
                    self._phishing_reputation = load_reputation(PHISHING_RULES_PATH)
            self._show_settings_tab()
            return
        if action == "phishing-remove-keyword":
            keyword = values.get("keyword", [""])[0]
            if keyword:
                rules = load_user_rules_raw(PHISHING_RULES_PATH)
                rules["suspicious_keywords"] = [k for k in rules.get("suspicious_keywords", []) if k != keyword]
                save_user_rules(PHISHING_RULES_PATH, rules)
                self._phishing_reputation = load_reputation(PHISHING_RULES_PATH)
            self._show_settings_tab()
            return
        if action == "phishing-add-trusted":
            host = values.get("host", [""])[0].strip()
            if host:
                rules = load_user_rules_raw(PHISHING_RULES_PATH)
                rules.setdefault("trusted_hosts", [])
                if host not in rules["trusted_hosts"]:
                    rules["trusted_hosts"].append(host)
                    save_user_rules(PHISHING_RULES_PATH, rules)
                    self._phishing_reputation = load_reputation(PHISHING_RULES_PATH)
            self._show_settings_tab()
            return
        if action == "phishing-remove-trusted":
            host = values.get("host", [""])[0]
            if host:
                rules = load_user_rules_raw(PHISHING_RULES_PATH)
                rules["trusted_hosts"] = [h for h in rules.get("trusted_hosts", []) if h != host]
                save_user_rules(PHISHING_RULES_PATH, rules)
                self._phishing_reputation = load_reputation(PHISHING_RULES_PATH)
            self._show_settings_tab()
            return
        if action == "assistant":
            source_tab_id = values.get("source_tab", [""])[0]
            self._show_assistant_tab(tab, source_tab_id)
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
        self.settings.enable_http_cache = "enable_http_cache" in values
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
        success = QColor(c["success"])
        warning = QColor(c["warning"])
        error = QColor(c["error"])
        for row, event in enumerate(self.network_events):
            self.network_table.insertRow(row)
            values = [
                event.url,
                event.route,
                event.vpn_server,
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
                if col == 7 and event.status:
                    try:
                        code = int(event.status.split(" ", 1)[0])
                        if 200 <= code < 300:
                            item.setForeground(success)
                        elif 300 <= code < 400:
                            item.setForeground(warning)
                        elif code >= 400:
                            item.setForeground(error)
                    except (ValueError, IndexError):
                        pass
                if col == 10 and event.error:
                    item.setForeground(error)
                self.network_table.setItem(row, col, item)

    def _refresh_cookies_table(self):
        self.cookies_table.setRowCount(0)
        for row, cookie in enumerate(self.cookie_jar.cookie_list):
            if cookie.is_expired():
                continue
            self.cookies_table.insertRow(row)
            for col, text in enumerate([cookie.domain, cookie.name, cookie.value]):
                self.cookies_table.setItem(row, col, QTableWidgetItem(text))

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
        if hasattr(self, "vpn_button"):
            self.vpn_button.blockSignals(True)
            self.vpn_button.setChecked(self.settings.enable_vpn)
            self.vpn_button.blockSignals(False)
        if hasattr(self, "vpn_toggle_action"):
            self.vpn_toggle_action.blockSignals(True)
            self.vpn_toggle_action.setChecked(self.settings.enable_vpn)
            self.vpn_toggle_action.blockSignals(False)
        label = tab.title or "New Tab"
        if tab.incognito:
            label = f"Incognito - {label}"
        display_name = self.current_user.get("display_name") or self.current_user.get("username", "")
        mode = "Guest" if self.current_user.get("is_local") else "Synced"
        self.window.setWindowTitle(f"{label} - WaterCat Browser ({mode}: {display_name})")

    def _update_account_actions(self) -> None:
        if not hasattr(self, "account_action"):
            return
        display_name = self.current_user.get("display_name") or self.current_user.get("username", "")
        if self.current_user.get("is_local"):
            self.account_action.setText("Profile: Guest (ephemeral)")
            self.sign_in_action.setEnabled(True)
            self.sign_up_action.setEnabled(True)
            self.sign_out_action.setEnabled(False)
            return
        self.account_action.setText(f"Profile: {display_name} (synced)")
        self.sign_in_action.setEnabled(True)
        self.sign_up_action.setEnabled(True)
        self.sign_out_action.setEnabled(True)

    def _update_tab_label(self, tab: BrowserTab):
        for index in range(self.tabs.count()):
            widget = self.tabs.widget(index)
            if widget and widget.property("browser_tab") is tab:
                label = tab.title[:24]
                if tab.incognito:
                    label = f"\U0001F576 {label}"
                self.tabs.setTabText(index, label)
                icon = tab.icon or self._tab_icon_for_url(tab.current_url)
                if icon is not None and not icon.isNull():
                    self.tabs.setTabIcon(index, icon)
                return

    def _make_dns_client(self) -> DNSClient:
        return DNSClient(
            server_host=self.settings.dns_host,
            server_port=self.settings.dns_port,
            timeout=self.settings.dns_timeout,
            enable_cache=self.settings.enable_dns_cache,
        )

    def _make_vpn_client(self) -> VPNClient:
        return VPNClient(
            host=self.settings.vpn_host,
            port=self.settings.vpn_port,
            token=self.settings.vpn_token,
            timeout=self.settings.vpn_timeout,
        )

    def _tab_icon_for_url(self, url: str) -> QIcon:
        if not url:
            return QIcon()
        if url.startswith("internal:home"):
            return self._theme_icon("go-home", QStyle.StandardPixmap.SP_DirHomeIcon)
        if url.startswith("internal:settings"):
            return self._theme_icon("preferences-system", QStyle.StandardPixmap.SP_FileDialogDetailedView)
        if url.startswith("internal:"):
            return self._theme_icon("text-html", QStyle.StandardPixmap.SP_FileIcon)

        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname or ""
        if not host:
            return QIcon()
        cached = self._favicon_cache.get(host)
        if cached is not None:
            return cached
        return QIcon()

    def _set_vpn_enabled(self, enabled: bool):
        if self.settings.enable_vpn == enabled:
            if hasattr(self, "vpn_button"):
                self.vpn_button.blockSignals(True)
                self.vpn_button.setChecked(enabled)
                self.vpn_button.blockSignals(False)
            if hasattr(self, "vpn_toggle_action"):
                self.vpn_toggle_action.blockSignals(True)
                self.vpn_toggle_action.setChecked(enabled)
                self.vpn_toggle_action.blockSignals(False)
            return
        self.settings.enable_vpn = enabled
        self.vpn_client = self._make_vpn_client()
        if hasattr(self, "vpn_button"):
            self.vpn_button.blockSignals(True)
            self.vpn_button.setChecked(enabled)
            self.vpn_button.blockSignals(False)
        if hasattr(self, "vpn_toggle_action"):
            self.vpn_toggle_action.blockSignals(True)
            self.vpn_toggle_action.setChecked(enabled)
            self.vpn_toggle_action.blockSignals(False)
        self._save_state()
        self._set_status(f"Mini VPN {'enabled' if enabled else 'disabled'}.")

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
        return is_ipv4_address(value)

    def _is_account_url(self, url: str) -> bool:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        account = urlparse(ACCOUNT_BASE_URL if "://" in ACCOUNT_BASE_URL else f"http://{ACCOUNT_BASE_URL}")
        host = (parsed.hostname or "").lower()
        account_host = (account.hostname or "").lower()
        if not host or host != account_host:
            return False
        path = parsed.path or "/"
        return path in {"/login", "/register"} or path.startswith("/auth/")

    def _should_use_webengine_proxy(self, host: str) -> bool:
        host = (host or "").strip().lower()
        return bool(host) and FORCE_CUSTOM_DNS_ALL_HOSTS and not should_use_custom_dns(host, force_all_hosts=False)

    def _should_use_custom_loader(self, host: str, scheme: str = "") -> bool:
        if should_use_custom_dns(host, force_all_hosts=False):
            return True
        if self._should_use_webengine_proxy(host):
            return False
        return scheme == "http" and self._should_use_vpn(host)

    def _should_use_custom_loader_from_url(self, url: str) -> bool:
        if self._is_account_url(url):
            return False
        parsed = urlparse(url)
        return self._should_use_custom_loader(parsed.hostname or "", parsed.scheme)

    def _webengine_status_text(self, url: str, progress: Optional[int] = None) -> str:
        if self._is_account_url(url):
            prefix = "Loading account page in Qt WebEngine"
            if progress is None:
                return f"{prefix}..."
            return f"{prefix}... {progress}%"
        host = (urlparse(url).hostname or "").lower()
        prefix = "Loading page in Qt WebEngine via local proxy" if self._should_use_webengine_proxy(host) else "Loading page in Qt WebEngine"
        if progress is None:
            return f"{prefix}..."
        return f"{prefix}... {progress}%"

    def _should_use_vpn(self, host: str) -> bool:
        if not self.settings.enable_vpn:
            return False
        mode = self.settings.vpn_mode if self.settings.vpn_mode in {"all", "domains"} else "all"
        if mode == "all":
            return True
        normalized = (host or "").strip().lower()
        for rule in self.settings.vpn_domains:
            rule = rule.strip().lower()
            if not rule:
                continue
            if rule.startswith(".") and normalized.endswith(rule):
                return True
            if normalized == rule:
                return True
        return False

    @staticmethod
    def _header_value(headers: dict[str, str], name: str) -> str:
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
        return ""

    def _redirect_target(self, current_url: str, response: HTTPResponse) -> str:
        if not 300 <= response.status_code < 400:
            return ""
        location = self._header_value(response.headers, "Location").strip()
        if not location:
            return ""
        return urljoin(current_url, location)

    @staticmethod
    def _request_path(raw_url: str, fallback_path: str) -> str:
        parsed = urlparse(raw_url)
        path = parsed.path or fallback_path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path

    def _effective_port(self, raw_url: str, scheme: str, host: str, parsed_port: int) -> int:
        try:
            explicit_port = urlparse(raw_url).port
        except ValueError:
            explicit_port = parsed_port
        if explicit_port is not None:
            return explicit_port
        return effective_port_for_host(
            scheme,
            host,
            None,
            self.settings.http_default_port,
            self.settings.https_default_port,
        )

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
        raw = self._profile_cache.get("settings", {}) if hasattr(self, "_profile_cache") else {}
        if not isinstance(raw, dict):
            raw = {}
        return BrowserSettings(
            dns_host=self._setting_str(raw, "dns_host", "BROWSER_DNS_HOST", DNS_HOST),
            dns_port=self._setting_int(raw, "dns_port", "BROWSER_DNS_PORT", DNS_PORT),
            dns_timeout=self._setting_float(raw, "dns_timeout", "BROWSER_DNS_TIMEOUT", DNS_TIMEOUT),
            http_default_port=self._setting_int(
                raw, "http_default_port", "BROWSER_HTTP_DEFAULT_PORT", HTTP_DEFAULT_PORT
            ),
            https_default_port=self._setting_int(
                raw, "https_default_port", "BROWSER_HTTPS_DEFAULT_PORT", HTTPS_DEFAULT_PORT
            ),
            enable_dns_cache=bool(
                self._setting_raw(raw, "enable_dns_cache", "BROWSER_ENABLE_DNS_CACHE", ENABLE_DNS_CACHE)
            ),
            enable_http_cache=bool(
                self._setting_raw(raw, "enable_http_cache", "BROWSER_ENABLE_HTTP_CACHE", ENABLE_HTTP_CACHE)
            ),
            enable_vpn=bool(
                self._setting_raw(raw, "enable_vpn", "BROWSER_ENABLE_VPN", ENABLE_VPN)
            ),
            vpn_host=self._setting_str(raw, "vpn_host", "BROWSER_VPN_HOST", VPN_HOST),
            vpn_port=self._setting_int(raw, "vpn_port", "BROWSER_VPN_PORT", VPN_PORT),
            vpn_token=self._setting_str(raw, "vpn_token", "BROWSER_VPN_TOKEN", VPN_TOKEN),
            vpn_timeout=self._setting_float(raw, "vpn_timeout", "BROWSER_VPN_TIMEOUT", VPN_TIMEOUT),
            vpn_mode=self._normalize_vpn_mode(
                self._setting_str(raw, "vpn_mode", "BROWSER_VPN_MODE", VPN_MODE)
            ),
            vpn_domains=self._setting_list(raw, "vpn_domains", "BROWSER_VPN_DOMAINS", VPN_DOMAINS),
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
        if key == "bookmarks":
            values = self._profile_cache.get("bookmarks", default)
        else:
            values = self._profile_cache.get(key, default)
        if not isinstance(values, list):
            return list(default)
        return [str(value) for value in values if str(value).strip()]

    def _load_shortcuts(self, default: list[str]) -> list[Any]:
        values = self._profile_cache.get("shortcuts", default)
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
        values = self._profile_cache.get("history", [])
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

    def _read_state(self) -> dict[str, Any]:
        try:
            with open(STATE_PATH, "r", encoding="utf-8") as file_obj:
                data = json.load(file_obj)
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _settings_data(self) -> dict[str, Any]:
        return {
            "dns_host": self.settings.dns_host,
            "dns_port": self.settings.dns_port,
            "dns_timeout": self.settings.dns_timeout,
            "http_default_port": self.settings.http_default_port,
            "https_default_port": self.settings.https_default_port,
            "enable_dns_cache": self.settings.enable_dns_cache,
            "enable_http_cache": self.settings.enable_http_cache,
            "enable_vpn": self.settings.enable_vpn,
            "vpn_host": self.settings.vpn_host,
            "vpn_port": self.settings.vpn_port,
            "vpn_token": self.settings.vpn_token,
            "vpn_timeout": self.settings.vpn_timeout,
            "vpn_mode": self.settings.vpn_mode,
            "vpn_domains": self.settings.vpn_domains,
            "home_url": self.settings.home_url,
            "search_url": self.settings.search_url,
            "theme": self.settings.theme,
            "font_size": self.settings.font_size,
            "search_engine": self.settings.search_engine,
        }

    def _save_state(self, immediate: bool = False):
        if immediate:
            self._save_state_now()
            return
        self._state_save_pending = True
        self._state_save_timer.start(200)

    def _save_state_now(self):
        self._state_save_pending = False
        profile_payload = {
            "settings": self._settings_data(),
            "bookmarks": list(self.bookmarks),
            "shortcuts": list(self.shortcuts),
            "history": list(self.history),
        }
        self._profile_cache = profile_payload
        if isinstance(self.profile_store, RemoteEncryptedProfileStore):
            self._spawn_task(self._sync_remote_profile_state())
        else:
            self._spawn_task(
                self.profile_store.sync_state(
                    profile_payload["settings"],
                    profile_payload["bookmarks"],
                    profile_payload["shortcuts"],
                    profile_payload["history"],
                )
            )

        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "current_user": self.current_user["username"],
            "encrypted_profile": bool(self.current_user.get("encrypted")),
        }
        data.update(self.cookie_jar._state_data())
        try:
            with open(STATE_PATH, "w", encoding="utf-8") as file_obj:
                json.dump(data, file_obj, indent=2)
        except OSError as exc:
            self._set_status(f"Could not save state: {exc}")

    async def _sync_remote_profile_state(self) -> None:
        if not isinstance(self.profile_store, RemoteEncryptedProfileStore):
            return
        try:
            merged = await self.profile_store.sync_state(
                self._settings_data(),
                self.bookmarks,
                self.shortcuts,
                self.history,
            )
        except Exception as exc:
            self._set_status(f"Could not sync encrypted profile: {exc}")
            return
        self._profile_cache = merged
        self.settings = self._load_settings()
        self.bookmarks = self._load_list("bookmarks", DEFAULT_BOOKMARKS)
        self.shortcuts = self._load_shortcuts(DEFAULT_BOOKMARKS)
        self.history = self._load_history()
        self.dns_client = self._make_dns_client()
        self.vpn_client = self._make_vpn_client()
        self._refresh_side_lists()

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

    def _setting_list(self, raw: dict[str, Any], state_key: str, env_key: str, config_value: list[str]) -> list[str]:
        value = self._setting_raw(raw, state_key, env_key, config_value)
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return list(config_value)

    @staticmethod
    def _normalize_theme(value: str) -> str:
        return value if value in {"light", "dark"} else "light"

    @staticmethod
    def _normalize_search_engine(value: str) -> str:
        return value if value in {"google", "bing"} else "google"

    @staticmethod
    def _normalize_vpn_mode(value: str) -> str:
        return value if value in {"all", "domains"} else "all"


def main():
    if QEventLoop is None:
        raise SystemExit("Missing qasync. Install with: python -m pip install qasync")
    app = QApplication(sys.argv)
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)
    browser = BrowserApp()
    app.aboutToQuit.connect(browser._save_state_now)
    browser.window.show()
    with loop:
        try:
            loop.run_until_complete(browser.start_background_services())
            loop.run_forever()
        finally:
            loop.run_until_complete(browser.shutdown_async())


if __name__ == "__main__":
    main()
