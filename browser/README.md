# Browser

## Structure

- `core/url_parser.py`: parse and validate URL (`http/https`, host, port, path, query).
- `core/dns_client.py`: send UDP JSON DNS query to the configured DNS server with TTL cache.
- `core/http_client.py`: send raw HTTP requests via TCP and parse status, headers, body.
- `gui/browser_gui.py`: GUI browser with navigation, DNS cache, history, bookmarks, settings, and network inspector.

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
BROWSER_DNS_PORT=5200
```

Environment variables override values in `browser/.env`. You can also change DNS host, DNS port, timeout, default HTTP port, home URL, and DNS cache behavior inside the GUI Settings dialog.

## Configuration

Use `browser/.env.example` as the template:

- `BROWSER_DNS_HOST`, `BROWSER_DNS_PORT`, `BROWSER_DNS_TIMEOUT`
- `BROWSER_ENABLE_DNS_CACHE`
- `BROWSER_HTTP_DEFAULT_PORT`, `BROWSER_HTTP_TIMEOUT`
- `BROWSER_HOME_URL`, `BROWSER_DEFAULT_BOOKMARKS`
- `BROWSER_STATE_DIR` or `BROWSER_STATE_PATH`

## GUI features

- Address bar with Back, Forward, Reload, Home, Go.
- DNS TTL cache view with domain, IP, remaining TTL, expiry time, and clear action.
- History panel with clear action, saved locally.
- Bookmarks panel with add/remove actions, saved locally.
- Settings dialog for DNS/browser behavior.
- Network inspector with DNS result, cache usage, HTTP endpoint, status, timing, errors, and headers.

## Local state

History, bookmarks, and settings are stored in `~/.mini_web_browser/browser_state.json`.

## Expected workflow

1. Input URL (for example: `http://example.local/about`)
2. Browser parses URL into host/port/path
3. Browser asks DNS server for IP
4. Browser sends HTTP request to HTTP server
5. Browser displays response headers, and GUI mode renders HTML + CSS + JavaScript
