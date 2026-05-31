# Browser

## Structure

- `core/url_parser.py`: parse and validate URL (`http/https`, host, port, path, query).
- `core/dns_client.py`: send UDP JSON v1 DNS queries to the configured DNS server with TTL cache.
- `core/host_routing.py`: decide which hostnames should go through the custom DNS stack.
- `core/http_client.py`: send raw HTTP requests via TCP and parse status, headers, body.
- `core/vpn_client.py`: send raw HTTP requests through the Mini VPN tunnel server.
- `gui/browser_gui.py`: GUI browser with tabs, custom DNS, Mini VPN toggle, history, bookmarks, downloads, cookies/session, incognito mode, settings, and DevTools panel.

## How to run

From `web-stack` root:

```bash
python -m pip install 'PySide6>=6.7'
cp browser/.env.example browser/.env
python browser/gui/browser_gui.py
```

Edit `.env` to point the browser to a DNS server hosted on a VPS:

```env
BROWSER_DNS_HOST=YOUR_VPS_IP
BROWSER_DNS_PORT=53
```

Environment variables override values in `.env`. You can also change DNS, HTTP cache, Mini VPN, theme, font, and search settings inside the GUI Settings page.

For local development without `sudo`, use the same high UDP port as the DNS server, for example:

```env
BROWSER_DNS_HOST=127.0.0.1
BROWSER_DNS_PORT=5336
BROWSER_HTTP_DEFAULT_PORT=8443
BROWSER_ACCOUNT_BASE_URL=http://127.0.0.1:8443
BROWSER_ENABLE_VPN=false
BROWSER_VPN_HOST=127.0.0.1
BROWSER_VPN_PORT=9443
BROWSER_VPN_TOKEN=demo-token
```

## Configuration

Use `browser/.env.example` as the template:

- `BROWSER_DNS_HOST`, `BROWSER_DNS_PORT`, `BROWSER_DNS_TIMEOUT`
- `BROWSER_ENABLE_DNS_CACHE`
- `BROWSER_FORCE_CUSTOM_DNS_ALL_HOSTS`
- `BROWSER_WEBENGINE_PROXY_HOST`, `BROWSER_WEBENGINE_PROXY_PORT`
- `BROWSER_HTTP_DEFAULT_PORT`, `BROWSER_HTTP_TIMEOUT`
- `BROWSER_ENABLE_VPN`, `BROWSER_VPN_HOST`, `BROWSER_VPN_PORT`, `BROWSER_VPN_TOKEN`
- `BROWSER_VPN_MODE` (`all` or `domains`), `BROWSER_VPN_DOMAINS`
- `BROWSER_HOME_URL`, `BROWSER_SEARCH_URL`, `BROWSER_DEFAULT_BOOKMARKS`
- `BROWSER_ACCOUNT_BASE_URL` for `/login`, `/register`, and encrypted profile sync
- `BROWSER_THEME` (`light` or `dark`)
- `BROWSER_STATE_DIR` or `BROWSER_STATE_PATH`

## GUI features

- Browser opens in ephemeral guest mode by default; Sign In and Create Account are available from the menu for the shared encrypted profile.
- URL bar accepts full URLs, domains, trailing slashes, and direct IPv4 addresses.
- Back, Forward, Reload, Home, New Tab with compact toolbar icons.
- Multi-tab browsing.
- HTML/CSS/JS rendering through Qt WebEngine.
- Home page with browser logo, search prompt, shortcuts, and add-shortcut flow.
- Mini VPN toolbar toggle, menu toggle, and `Check VPN IP` diagnostic for routing custom-loaded HTTP through `vpn/vpn_server.py`.
- History and bookmarks are available from the main menu.
- Download current response/file from the menu.
- Cookie/session support for normal tabs; incognito tabs keep cookies in memory only.
- Incognito tab mode.
- Settings dialog and settings page.
- Print to PDF from the main menu.
- Light/dark mode, font size, and Google/Bing search engine selection from Settings.
- DevTools panel with Network route/VPN columns, Headers, Cookies, History, and Bookmarks.
- Built-in error pages for URL, DNS, and HTTP errors.

Search uses `BROWSER_SEARCH_URL`. The default value is an internal search page, so normal search input will not cause a DNS error. Settings can show Google/Bing result-page links without opening those pages through custom DNS.

By default, the custom DNS loader is used for `localhost`, `.local` hostnames, and direct IPv4 addresses. Set `BROWSER_FORCE_CUSTOM_DNS_ALL_HOSTS=true` to resolve all hostnames through the custom DNS client. Public hostnames still render through Qt WebEngine; the browser uses its local WebEngine proxy for those requests.

Mini VPN is not a system-level VPN. It always applies to WaterCat's custom-loaded HTTP requests. When `BROWSER_FORCE_CUSTOM_DNS_ALL_HOSTS=true`, the local WebEngine proxy can also route public WebEngine traffic through the Mini VPN when the VPN rules match.

## Profile Storage

Settings, bookmarks, shortcuts, and synced history are stored in PostgreSQL through the app API. The browser encrypts that profile data client-side before upload, so the server only stores ciphertext plus wrap metadata for the profile key.

Normal browsing cookies still use `~/.mini_web_browser/cookies.json`; incognito cookies stay in memory only. Device-local browser state such as cookies, cache, and the remembered profile-unlock key still lives under `BROWSER_STATE_DIR`.

## Expected workflow

1. Input URL (for example: `http://example.local/about`)
2. Browser parses URL into host/port/path
3. Browser asks DNS server for IP
4. If Mini VPN is off, Browser sends HTTP request directly to HTTP server
5. If Mini VPN is on, Browser sends the raw HTTP request to VPN server, which forwards it to HTTP server
6. Browser displays response headers, and GUI mode renders HTML + CSS + JavaScript
