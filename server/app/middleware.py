"""Session authentication middleware."""
import json
from server.app.auth import extract_session_cookie
from server.app.models import validate_session_token
from server.shared.response import Response


def auth_required(handler):
    """Decorator: validates wc_session cookie, sets request['user'] and request['session_token']."""
    def wrapper(request: dict, *args, **kwargs):
        token = extract_session_cookie(request.get("headers", {}))
        user = validate_session_token(token) if token else None
        if user is None:
            return Response(401, body=json.dumps({"error": "not authenticated"}).encode(),
                          headers={"content-type": "application/json"})
        request["user"] = user
        request["session_token"] = token
        return handler(request, *args, **kwargs)
    return wrapper
