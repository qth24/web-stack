"""Form submission interception for custom-loaded pages."""
import json


def inject_form_intercept(html: bytes, base_url: str) -> bytes:
    """Inject JavaScript that intercepts form submissions and routes through custom loader.
    Forms GET/POST with application/x-www-form-urlencoded are supported."""
    script = b"""
<script>
(function() {
    document.addEventListener('submit', function(e) {
        var form = e.target;
        var method = (form.method || 'GET').toUpperCase();
        var action = form.action || '';
        try {
            action = new URL(action, window.location.href).href;
        } catch(_) {}
        var data = new FormData(form);
        var params = new URLSearchParams(data).toString();
        var fullUrl = action;
        if (method === 'GET' && params) {
            fullUrl = action + (action.indexOf('?') >= 0 ? '&' : '?') + params;
        }
        window.location.href = 'watercat-form://' + btoa(JSON.stringify({
            method: method,
            url: fullUrl,
            body: method === 'POST' ? params : '',
            contentType: 'application/x-www-form-urlencoded'
        }));
        e.preventDefault();
    });
})();
</script>
"""
    end_body = html.lower().rfind(b'</body>')
    if end_body != -1:
        return html[:end_body] + script + html[end_body:]
    return html + script
