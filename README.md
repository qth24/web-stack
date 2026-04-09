# HTTP Server (Web server)

### Features
- Listen TCP socket (Port 8000)
- Get HTTP request from browser
- Parse request
- Response HTTP

## Current skeleton

This repository now contains a basic HTTP server implemented directly on top of
Python TCP sockets, without using web frameworks.

Implemented:
- Listen on `0.0.0.0:8000`
- Accept TCP connections from a browser/client
- Read raw HTTP request data
- Parse request line, headers, and body
- Route `GET /` to a static HTML page
- Route `GET /health` to a JSON response
- Return `404 Not Found` for missing files
- Return `405 Method Not Allowed` for unsupported methods
- Serve static files from the `public/` folder

## Project structure

```text
.
├── README.md
├── public/
│   ├── index.html
│   └── styles.css
├── requirements.txt
└── src/
    ├── config.py
    ├── http_parser.py
    ├── http_response.py
    ├── mime_types.py
    ├── router.py
    └── server.py
```

## Run the server

```bash
python3 src/server.py
```

Open in browser:

```text
http://127.0.0.1:8000
```

## Quick test

```bash
curl -i http://127.0.0.1:8000/
curl -i http://127.0.0.1:8000/health
curl -i -X POST http://127.0.0.1:8000/
```

## Suggested next steps for the project

- Add support for `POST`
- Parse query string and request body more fully
- Add logging to file
- Add multi-client handling with threading or async
- Add more HTTP status codes and better error pages
- Add configuration by environment variables
