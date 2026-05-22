# Browser

## Structure

- `core/url_parser.py`: parse and validate URL (`http/https`, host, port, path, query).
- `core/dns_client.py`: send UDP JSON DNS query to the configured DNS server with TTL cache.
- `core/http_client.py`: send raw HTTP requests via TCP and parse status, headers, body.
- `gui/browser_gui.py`: Chrome-like GUI browser with tabs, custom DNS, history, bookmarks, downloads, cookies/session, incognito mode, settings, and DevTools panel.

## How to run

From `web-stack` root:

```bash
python -m pip install -r browser/requirements.txt
cp browser/.env.example browser/.env
python browser/gui/browser_gui.py
```

Edit `browser/.env` to point the browser to a DNS server hosted on a VPS:

```env
BROWSER_DNS_HOST=YOUR_VPS_IP
BROWSER_DNS_PORT=53
```

Environment variables override values in `browser/.env`. You can also change DNS host, DNS port, timeout, default HTTP port, home URL, search URL, and DNS cache behavior inside the GUI Settings dialog.

For local development without `sudo`, use the same high UDP port as the DNS server, for example:

```env
BROWSER_DNS_HOST=127.0.0.1
BROWSER_DNS_PORT=5336
BROWSER_HTTP_DEFAULT_PORT=80
```

## Configuration

Use `browser/.env.example` as the template:

- `BROWSER_DNS_HOST`, `BROWSER_DNS_PORT`, `BROWSER_DNS_TIMEOUT`
- `BROWSER_ENABLE_DNS_CACHE`
- `BROWSER_HTTP_DEFAULT_PORT`, `BROWSER_HTTP_TIMEOUT`
- `BROWSER_HOME_URL`, `BROWSER_SEARCH_URL`, `BROWSER_DEFAULT_BOOKMARKS`
- `BROWSER_THEME` (`light` or `dark`)
- `BROWSER_STATE_DIR` or `BROWSER_STATE_PATH`

## GUI features

- URL bar accepts full URLs, domains, trailing slashes, and direct IPv4 addresses.
- Back, Forward, Reload, Home, New Tab with compact toolbar icons.
- Multi-tab browsing.
- HTML/CSS/JS rendering through Qt WebEngine.
- Home page with browser logo, search prompt, shortcuts, and add-shortcut flow.
- History and bookmarks are available from the main menu.
- Download current response/file from the menu.
- Cookie/session support for normal tabs; incognito tabs keep cookies in memory only.
- Incognito tab mode.
- Settings dialog and settings page.
- Print to PDF from the main menu.
- Light/dark mode, font size, and Google/Bing search engine selection from Settings.
- DevTools panel with Network, Headers, Cookies, History, and Bookmarks.
- Built-in error pages for URL, DNS, and HTTP errors.

Search uses `BROWSER_SEARCH_URL`. The default value is an internal search page, so normal search input will not cause a DNS error. Settings can show Google/Bing result-page links without opening those pages through custom DNS.

## Local state

History, bookmarks, settings, and normal browsing cookies are stored in `~/.mini_web_browser/browser_state.json`.

## Expected workflow

1. Input URL (for example: `http://example.local/about`)
2. Browser parses URL into host/port/path
3. Browser asks DNS server for IP
4. Browser sends HTTP request to HTTP server
5. Browser displays response headers, and GUI mode renders HTML + CSS + JavaScript
