# Browser

## Structure

- `core/url_parser.py`: parse and validate URL (`http/https`, host, port, path, query).
- `core/dns_client.py`: send UDP DNS query to DNS server (`127.0.0.1:5300`) with simple cache.
- `core/http_client.py`: send raw HTTP requests via TCP and parse status, headers, body.
- `browser_cli.py`: command-line browser flow (parse -> DNS -> HTTP -> display).
- `gui/browser_gui.py`: Tkinter GUI browser with log panel and content panel.

## How to run

From `web-stack` root:

```bash
python browser/browser_cli.py http://example.local/
```

Interactive CLI mode:

```bash
python browser/browser_cli.py
```

GUI mode:

```bash
python browser/gui/browser_gui.py
```

## Expected workflow

1. Input URL (for example: `http://example.local/about`)
2. Browser parses URL into host/port/path
3. Browser asks DNS server for IP
4. Browser sends HTTP request to HTTP server
5. Browser displays response headers and body
