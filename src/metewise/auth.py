"""Login recipes: turn credentials into an auth header, so you don't paste
short-lived tokens by hand -- and so metewise can re-authenticate when a token
expires mid-run.

A principal may carry a `login` block instead of (or alongside) static headers:

    "alice": {
      "tenant": "acme",
      "login": {
        "url": "https://api.example.com/login",
        "method": "POST",
        "body": {"username": "alice", "password": "s3cret"},
        "token_path": "$.auth_token",
        "header": "Authorization",
        "format": "Bearer {token}"
      }
    }

`acquire_headers` runs that request, pulls the token from the response by
`token_path`, and returns `{header: format.format(token=...)}`.
"""

from __future__ import annotations

from . import http
from .shape import get_path


class LoginError(RuntimeError):
    pass


def acquire_headers(login: dict) -> dict[str, str]:
    """Perform a login recipe and return the auth header(s) it yields."""
    url = login.get("url")
    if not url:
        raise LoginError("login recipe needs a 'url'")
    method = login.get("method", "POST").upper()
    body = login.get("body")
    req_headers = dict(login.get("headers", {}))

    status, _, resp = http.request(method, url, req_headers, body)
    if status // 100 != 2:
        raise LoginError(f"login to {url} returned {status}")

    token_path = login.get("token_path", "$.token")
    token = get_path(resp, token_path)
    if token is None:
        raise LoginError(
            f"login response had no token at '{token_path}' "
            f"(check the path against the actual response)"
        )

    header = login.get("header", "Authorization")
    fmt = login.get("format", "Bearer {token}")
    return {header: fmt.format(token=token)}


def refresh(principal) -> bool:
    """Re-run a principal's login recipe and update its headers in place.
    Returns True on success. No-op (False) if the principal has no recipe."""
    if not principal.login:
        return False
    try:
        principal.headers.update(acquire_headers(principal.login))
        return True
    except LoginError:
        return False

