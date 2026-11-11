"""Small JSON transport with no credential-bearing redirects or error bodies."""
import http.client
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class RequestError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def json_request(url, *, headers=None, method="GET", body=None, timeout=30, limit=2_000_000):
    req = Request(url, method=method, headers=headers or {},
                  data=None if body is None else json.dumps(body, ensure_ascii=True, allow_nan=False).encode())
    try:
        handlers = [NoRedirect()]
        if urlsplit(url).hostname in ("127.0.0.1", "::1", "localhost"):
            handlers.append(ProxyHandler({}))
        with build_opener(*handlers).open(req, timeout=timeout) as resp:
            raw = resp.read(limit + 1)
    except HTTPError as exc:
        exc.close()
        raise RequestError(f"HTTP {exc.code}", exc.code) from None
    except (URLError, OSError, http.client.HTTPException, ValueError):
        raise RequestError("Network or TLS error") from None
    if len(raw) > limit:
        raise RequestError("Response exceeds the size limit")
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        raise RequestError("Invalid JSON response") from None
