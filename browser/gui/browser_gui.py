import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import sys
import os

# Add root directory to path to import core modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

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
      [toolbar]  -  address bar + Go/Clear buttons
      [log]      -  step-by-step log (DNS query, HTTP request...)
      [content]  -  rendered body content
      [statusbar]
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Mini Web Browser")
        self.root.geometry("820x640")
        self.root.minsize(600, 400)

        self.dns_client = DNSClient(
            server_host=DNS_SERVER_HOST,
            server_port=DNS_SERVER_PORT,
        )
        self.http_client = HTTPClient()

        self._build_ui()
        self._bind_shortcuts()


    def _build_ui(self):
        # Toolbar
        toolbar = tk.Frame(self.root, pady=6, padx=8)
        toolbar.pack(side=tk.TOP, fill=tk.X)

        tk.Label(toolbar, text="URL:").pack(side=tk.LEFT)

        self.url_var = tk.StringVar()
        self.url_entry = tk.Entry(toolbar, textvariable=self.url_var, width=55, font=("Courier", 11))
        self.url_entry.pack(side=tk.LEFT, padx=(4, 6), ipady=3)
        self.url_entry.insert(0, "http://example.local/")

        self.go_btn = tk.Button(
            toolbar, text="Go", width=6, command=self._on_go,
            bg="#4CAF50", fg="white", font=("Arial", 10, "bold"),
            relief=tk.FLAT, cursor="hand2",
        )
        self.go_btn.pack(side=tk.LEFT)

        tk.Button(
            toolbar, text="Clear", width=6, command=self._on_clear,
            relief=tk.FLAT, cursor="hand2",
        ).pack(side=tk.LEFT, padx=(4, 0))

        # Bookmark buttons
        tk.Label(toolbar, text="   Quick:").pack(side=tk.LEFT)
        for bm in BOOKMARKS:
            short = bm.replace("http://", "").rstrip("/") or "/"
            tk.Button(
                toolbar, text=short, relief=tk.FLAT,
                fg="#1565C0", cursor="hand2",
                command=lambda u=bm: self._navigate_to(u),
            ).pack(side=tk.LEFT, padx=2)

        # Separator
        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X)

        # Paned window: log top / content bottom
        paned = tk.PanedWindow(self.root, orient=tk.VERTICAL, sashrelief=tk.RAISED)
        paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Log panel
        log_frame = tk.LabelFrame(paned, text=" Request Log ", padx=4, pady=4)
        paned.add(log_frame, minsize=120, height=170)

        self.log_text = scrolledtext.ScrolledText(
            log_frame, height=7, font=("Courier", 9),
            state=tk.DISABLED, wrap=tk.WORD,
            bg="#1e1e2e", fg="#cdd6f4",
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Log color tags
        self.log_text.tag_config("info",    foreground="#89b4fa")  # blue
        self.log_text.tag_config("ok",      foreground="#a6e3a1")  # green
        self.log_text.tag_config("warn",    foreground="#f9e2af")  # yellow
        self.log_text.tag_config("error",   foreground="#f38ba8")  # red
        self.log_text.tag_config("header",  foreground="#cba6f7")  # purple
        self.log_text.tag_config("dim",     foreground="#6c7086")  # gray

        # Content panel
        content_frame = tk.LabelFrame(paned, text=" Page Content ", padx=4, pady=4)
        paned.add(content_frame, minsize=200)

        self.content_text = scrolledtext.ScrolledText(
            content_frame, font=("Courier", 10),
            state=tk.DISABLED, wrap=tk.WORD,
        )
        self.content_text.pack(fill=tk.BOTH, expand=True)

        # Status bar
        self.status_var = tk.StringVar(value="Ready.")
        status_bar = tk.Label(
            self.root, textvariable=self.status_var,
            anchor=tk.W, padx=8, pady=2,
            relief=tk.SUNKEN, font=("Arial", 9),
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _bind_shortcuts(self):
        self.url_entry.bind("<Return>", lambda e: self._on_go())
        self.root.bind("<Control-l>", lambda e: (self.url_entry.focus(), self.url_entry.select_range(0, tk.END)))

    # Event handlers

    def _on_go(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Missing URL", "Please enter a URL.")
            return
        self._navigate(url)

    def _on_clear(self):
        self._clear_log()
        self._clear_content()
        self.status_var.set("Ready.")

    def _navigate_to(self, url: str):
        self.url_var.set(url)
        self._navigate(url)

    # Navigation (runs in separate thread)

    def _navigate(self, url: str):
        """Starts navigation in background thread"""
        self._clear_log()
        self._clear_content()
        self._set_loading(True)
        threading.Thread(target=self._fetch_url, args=(url,), daemon=True).start()

    def _fetch_url(self, url: str):
        """
        Flow: parse -> DNS -> HTTP -> render
        Updates UI via after()
        """
        start = time.time()

        try:
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
            self._set_status(f"{response.status_code} {response.status_text}  |  {len(response.body)} bytes  |  {elapsed*1000:.0f}ms")
            self._render_content(response)

        finally:
            self._set_loading(False)

    # UI update helpers (thread-safe)

    def _log(self, msg: str, tag: str = ""):
        def _do():
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, msg + "\n", tag)
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        self.root.after(0, _do)

    def _clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _clear_content(self):
        self.content_text.config(state=tk.NORMAL)
        self.content_text.delete("1.0", tk.END)
        self.content_text.config(state=tk.DISABLED)

    def _render_content(self, response):
        """Displays response body in content panel"""
        def _do():
            self.content_text.config(state=tk.NORMAL)
            self.content_text.delete("1.0", tk.END)

            if response.is_ok:
                self.content_text.insert(tk.END, response.body)
            else:
                # Simple error page
                self.content_text.insert(
                    tk.END,
                    f"{'─'*40}\n"
                    f"  {response.status_code} {response.status_text}\n"
                    f"{'─'*40}\n\n"
                    f"{response.body}",
                )

            self.content_text.config(state=tk.DISABLED)
        self.root.after(0, _do)

    def _show_error(self, msg: str):
        def _do():
            self.content_text.config(state=tk.NORMAL)
            self.content_text.delete("1.0", tk.END)
            self.content_text.insert(tk.END, f"❌  {msg}")
            self.content_text.config(state=tk.DISABLED)
            self.status_var.set("Error.")
        self.root.after(0, _do)

    def _set_status(self, msg: str):
        self.root.after(0, lambda: self.status_var.set(msg))

    def _set_loading(self, loading: bool):
        def _do():
            if loading:
                self.go_btn.config(state=tk.DISABLED, text="...")
                self.status_var.set("Loading...")
            else:
                self.go_btn.config(state=tk.NORMAL, text="Go")
        self.root.after(0, _do)


def main():
    root = tk.Tk()
    app = BrowserApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
