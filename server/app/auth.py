"""PBKDF2 password hashing and session-based authentication handlers."""
# Handles signup, login, session cookies, and password hashing.
import asyncio
import hashlib
import html
import json
import secrets
from urllib.parse import parse_qs, quote, urlparse

from server.app.models import (
    create_session,
    create_user,
    delete_session,
    get_user_by_username,
    validate_session_token,
)
from server.shared.response import Response


SESSION_COOKIE_NAME = "wc_session"
JSON_HEADERS = {"content-type": "application/json"}
HTML_HEADERS = {"content-type": "text/html; charset=utf-8"}


def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    # Password KDF used before storing credentials.
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 210000)
    return dk.hex(), salt


def extract_session_cookie(headers: dict) -> str | None:
    # Pulls the WaterCat session token from request cookies.
    cookie = headers.get("cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith(f"{SESSION_COOKIE_NAME}="):
            return part.split("=", 1)[1]
    return None


def _session_cookie_header(token: str, *, expire: bool = False) -> str:
    cookie = f"{SESSION_COOKIE_NAME}={token}; HttpOnly; SameSite=Lax; Path=/"
    if expire:
        return f"{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
    return cookie


def _wants_form_response(headers: dict | None) -> bool:
    content_type = (headers or {}).get("content-type", "")
    return content_type.startswith("application/x-www-form-urlencoded")


def _parse_request_target(target: str) -> tuple[str, dict[str, list[str]]]:
    parsed = urlparse(target or "")
    return parsed.path or "/", parse_qs(parsed.query, keep_blank_values=True)


def _parse_form_body(body: bytes) -> dict[str, str]:
    try:
        parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    except UnicodeDecodeError:
        return {}
    return {key: (values[-1] if values else "") for key, values in parsed.items()}


def _auth_form_values(
    body: bytes,
    headers: dict | None = None,
) -> tuple[dict[str, str], bool]:
    if _wants_form_response(headers):
        return _parse_form_body(body), True
    try:
        parsed = json.loads(body or b"{}")
    except json.JSONDecodeError as exc:
        raise ValueError("invalid_json") from exc
    return {
        "username": str(parsed.get("username", "")),
        "password": str(parsed.get("password", "")),
        "display_name": str(parsed.get("display_name", "")),
        "next": str(parsed.get("next", "/")),
    }, False


def render_auth_page(
    mode: str,
    *,
    next_url: str = "/",
    error: str = "",
    values: dict[str, str] | None = None,
) -> Response:
    values = values or {}
    is_register = mode == "register"
    title = "Create Account" if is_register else "Sign In"
    action = "/auth/register" if is_register else "/auth/login"
    alternate_path = "/login" if is_register else "/register"
    alternate_url = f"{alternate_path}?next={quote(next_url, safe='/:?=&%')}"
    alternate_label = "Already have an account? Sign in" if is_register else "Need an account? Register"
    username = html.escape(values.get("username", ""))
    display_name = html.escape(values.get("display_name", ""))
    safe_next = html.escape(next_url, quote=True)
    safe_error = html.escape(error)
    page_mode = "register" if is_register else "login"
    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg-left: #dbe7fb;
      --bg-right: #f6efe5;
      --panel: rgba(255,255,255,0.9);
      --border: rgba(18, 37, 77, 0.12);
      --text: #14284c;
      --muted: #637a9d;
      --accent: #2f66e6;
      --danger: #c73c45;
      --danger-bg: rgba(199, 60, 69, 0.08);
      --shadow: 0 18px 40px rgba(18, 37, 77, 0.12);
      font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 32px 16px;
      background: linear-gradient(120deg, var(--bg-left), var(--bg-right));
      color: var(--text);
    }}
    .shell {{
      width: min(460px, 100%);
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 28px;
      box-shadow: var(--shadow);
      padding: 28px;
      backdrop-filter: blur(10px);
    }}
    h1 {{
      margin: 0 0 8px;
      font-size: 34px;
      letter-spacing: -0.04em;
    }}
    p {{
      margin: 0;
      color: var(--muted);
      line-height: 1.5;
    }}
    form {{
      display: grid;
      gap: 14px;
      margin-top: 22px;
    }}
    label {{
      display: grid;
      gap: 8px;
      font-size: 14px;
      color: var(--muted);
    }}
    input {{
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 12px 14px;
      font-size: 15px;
      color: var(--text);
      background: rgba(255,255,255,0.96);
    }}
    input:focus {{
      outline: 2px solid rgba(47, 102, 230, 0.22);
      border-color: var(--accent);
    }}
    button {{
      border: 0;
      border-radius: 14px;
      padding: 13px 18px;
      font-size: 15px;
      font-weight: 600;
      color: white;
      background: var(--accent);
      cursor: pointer;
    }}
    button[disabled] {{
      opacity: 0.7;
      cursor: wait;
    }}
    .error {{
      min-height: 22px;
      border-radius: 14px;
      padding: { "12px 14px" if error else "0" };
      background: { "var(--danger-bg)" if error else "transparent" };
      color: var(--danger);
      font-size: 14px;
    }}
    .alt {{
      margin-top: 18px;
      text-align: center;
      font-size: 14px;
    }}
    .alt a {{
      color: var(--accent);
      text-decoration: none;
      font-weight: 600;
    }}
  </style>
</head>
<body>
  <main class="shell">
    <h1>{title}</h1>
    <p>{'Create a shared WaterCat account and encrypted browser profile.' if is_register else 'Sign in to your shared WaterCat account and browser profile.'}</p>
    <div id="auth-error" class="error">{safe_error}</div>
    <form id="auth-form" method="post" action="{action}">
      <input type="hidden" name="next" value="{safe_next}">
      <label>Username
        <input required minlength="3" maxlength="64" name="username" autocomplete="username" value="{username}">
      </label>
      {('<label>Display name<input maxlength="128" name="display_name" autocomplete="nickname" value="' + display_name + '"></label>') if is_register else ''}
      <label>Password
        <input required minlength="6" type="password" name="password" autocomplete="current-password">
      </label>
      {('<label>Confirm password<input required minlength="6" type="password" name="confirm_password" autocomplete="new-password"></label>') if is_register else ''}
      <button id="auth-submit" type="submit">{'Create Account' if is_register else 'Sign In'}</button>
    </form>
    <div class="alt"><a href="{alternate_url}">{alternate_label}</a></div>
  </main>
  <script>
    (function () {{
      const form = document.getElementById("auth-form");
      const submit = document.getElementById("auth-submit");
      const errorBox = document.getElementById("auth-error");
      const mode = {json.dumps(page_mode)};
      let bridge = null;

      function setBusy(busy) {{
        submit.disabled = busy;
        submit.textContent = busy ? "Working..." : ({json.dumps("Create Account" if is_register else "Sign In")});
      }}

      function showError(message) {{
        errorBox.textContent = message || "";
        errorBox.style.padding = message ? "12px 14px" : "0";
        errorBox.style.background = message ? "var(--danger-bg)" : "transparent";
      }}

      function payloadFromForm() {{
        const data = new FormData(form);
        return {{
          mode,
          next: data.get("next") || "/",
          username: (data.get("username") || "").toString(),
          display_name: (data.get("display_name") || "").toString(),
          password: (data.get("password") || "").toString(),
          confirm_password: (data.get("confirm_password") || "").toString(),
        }};
      }}

      async function initBridge() {{
        if (!window.qt || !window.qt.webChannelTransport) {{
          return;
        }}
        await new Promise((resolve) => {{
          const script = document.createElement("script");
          script.src = "qrc:///qtwebchannel/qwebchannel.js";
          script.onload = resolve;
          script.onerror = resolve;
          document.head.appendChild(script);
        }});
        if (typeof QWebChannel !== "function") {{
          return;
        }}
        bridge = await new Promise((resolve) => {{
          new QWebChannel(window.qt.webChannelTransport, (channel) => resolve(channel.objects.watercatAuth || null));
        }});
        if (!bridge) {{
          return;
        }}
        bridge.authResult.connect((raw) => {{
          try {{
            const message = JSON.parse(raw);
            if (message.mode && message.mode !== mode) {{
              return;
            }}
            if (message.success) {{
              if (message.redirect) {{
                window.location.href = message.redirect;
              }}
              return;
            }}
            setBusy(false);
            showError(message.error || "Authentication failed.");
          }} catch (err) {{
            setBusy(false);
            showError("Authentication failed.");
          }}
        }});
        form.addEventListener("submit", (event) => {{
          event.preventDefault();
          const payload = payloadFromForm();
          if (payload.mode === "register" && payload.password !== payload.confirm_password) {{
            showError("Password confirmation does not match.");
            return;
          }}
          setBusy(true);
          showError("");
          bridge.submitAuth(JSON.stringify(payload));
        }});
      }}

      initBridge();
    }}());
  </script>
</body>
</html>"""
    return Response(200, body=html_body.encode("utf-8"), headers=HTML_HEADERS.copy())


def _redirect_response(location: str, *, cookie_header: str | None = None) -> Response:
    headers = {"location": location}
    if cookie_header:
        headers["set-cookie"] = cookie_header
    return Response(302, body=b"", headers=headers)


def _json_error(status_code: int, message: str) -> Response:
    return Response(status_code, body=json.dumps({"error": message}).encode(), headers=JSON_HEADERS.copy())


async def handle_register(
    body: bytes,
    *,
    headers: dict | None = None,
    target: str = "/auth/register",
) -> Response:
    # Creates the user and immediately starts a session.
    try:
        data, wants_form = _auth_form_values(body, headers)
    except ValueError:
        return Response(400, body=b'{"error":"invalid JSON"}', headers=JSON_HEADERS.copy())

    _, query = _parse_request_target(target)
    next_url = str(data.get("next") or query.get("next", ["/"])[-1] or "/").strip() or "/"
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()
    display_name = str(data.get("display_name", "")).strip()
    confirm_password = str(data.get("confirm_password", "")).strip()

    if not username or not password:
        if wants_form:
            return render_auth_page("register", next_url=next_url, error="Username and password are required.", values=data)
        return _json_error(400, "username and password required")
    if wants_form and password != confirm_password:
        return render_auth_page("register", next_url=next_url, error="Password confirmation does not match.", values=data)
    if len(username) > 64 or len(password) < 6:
        if wants_form:
            return render_auth_page("register", next_url=next_url, error="Username or password does not meet length requirements.", values=data)
        return _json_error(422, "invalid username or password length")
    if await get_user_by_username(username):
        if wants_form:
            return render_auth_page("register", next_url=next_url, error="Username already exists.", values=data)
        return _json_error(409, "username taken")

    pw_hash, pw_salt = await asyncio.to_thread(hash_password, password)
    user_id = await create_user(username, pw_hash, pw_salt, display_name or username)
    token = await create_session(user_id)

    body_data = json.dumps({"id": user_id, "username": username, "display_name": display_name or username})
    response = Response(201, body=body_data.encode(), headers=JSON_HEADERS.copy())
    response.headers["set-cookie"] = _session_cookie_header(token)
    if wants_form:
        return _redirect_response(next_url, cookie_header=response.headers["set-cookie"])
    return response


async def handle_login(
    body: bytes,
    *,
    headers: dict | None = None,
    target: str = "/auth/login",
) -> Response:
    # Verifies credentials and issues a new session token.
    try:
        data, wants_form = _auth_form_values(body, headers)
    except ValueError:
        return Response(400, body=b'{"error":"invalid JSON"}', headers=JSON_HEADERS.copy())

    _, query = _parse_request_target(target)
    next_url = str(data.get("next") or query.get("next", ["/"])[-1] or "/").strip() or "/"
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    if not username or not password:
        if wants_form:
            return render_auth_page("login", next_url=next_url, error="Username and password are required.", values=data)
        return _json_error(400, "username and password required")

    user = await get_user_by_username(username)
    if user is None:
        if wants_form:
            return render_auth_page("login", next_url=next_url, error="Invalid username or password.", values=data)
        return _json_error(401, "invalid credentials")

    pw_hash, _ = await asyncio.to_thread(hash_password, password, user["password_salt"])
    if not secrets.compare_digest(pw_hash, user["password_hash"]):
        if wants_form:
            return render_auth_page("login", next_url=next_url, error="Invalid username or password.", values=data)
        return _json_error(401, "invalid credentials")

    token = await create_session(user["id"])
    body_data = json.dumps({"id": user["id"], "username": user["username"], "display_name": user["display_name"]})
    response = Response(200, body=body_data.encode(), headers=JSON_HEADERS.copy())
    response.headers["set-cookie"] = _session_cookie_header(token)
    if wants_form:
        return _redirect_response(next_url, cookie_header=response.headers["set-cookie"])
    return response


async def handle_logout(token: str | None) -> Response:
    if token:
        await delete_session(token)
    response = Response(200, body=b'{"message":"logged out"}', headers=JSON_HEADERS.copy())
    response.headers["set-cookie"] = _session_cookie_header("", expire=True)
    return response


async def handle_me(token: str | None) -> Response:
    # Lightweight authenticated user lookup.
    if not token:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(), headers=JSON_HEADERS.copy())
    user = await validate_session_token(token)
    if user is None:
        return Response(401, body=json.dumps({"error": "not authenticated"}).encode(), headers=JSON_HEADERS.copy())
    return Response(200, body=json.dumps(user).encode(), headers=JSON_HEADERS.copy())
