"""Ingest a HAR capture into Exchange records, attributing each request to a
principal.

HAR (HTTP Archive) is what every browser devtools "Export" and every proxy
(mitmproxy, Charles, Burp) can emit, so it's the universal on-ramp: capture a
short session per user, and metewise works out the rest.

Principal attribution is by header match. A request belongs to a principal when
every one of that principal's identifying headers is present on the request with
a matching (substring) value -- which covers bearer tokens, `X-User`, and
`Cookie: session=...` alike.
"""

from __future__ import annotations

import json

from .model import Exchange, Principal


def _headers_to_dict(entries: list[dict]) -> dict[str, str]:
    # HAR stores headers as a list; later values win, matching most servers.
    out: dict[str, str] = {}
    for h in entries or []:
        out[h.get("name", "")] = h.get("value", "")
    return out


def _body(container: dict) -> object:
    """Pull the parsed body from a HAR request.postData or response.content."""
    if not container:
        return None
    text = container.get("text")
    if text is None:
        return None
    mime = (container.get("mimeType") or "").lower()
    if "json" in mime and text.strip():
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    return text


def _get(headers: dict[str, str], name: str) -> str | None:
    low = name.lower()
    for k, v in headers.items():
        if k.lower() == low:
            return v
    return None


def attribute(req_headers: dict[str, str], principals: dict[str, Principal]) -> str:
    """Return the name of the principal whose identifying headers all match this
    request, or "anon" if none match. First match wins on ties."""
    for name, p in principals.items():
        if not p.headers:
            continue  # anon-like principals never claim a request
        if all(
            (_get(req_headers, hk) or "").find(hv) >= 0 and _get(req_headers, hk) is not None
            for hk, hv in p.headers.items()
        ):
            return name
    return "anon"


def parse(har: dict, principals: dict[str, Principal]) -> list[Exchange]:
    exchanges: list[Exchange] = []
    for entry in har.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        resp = entry.get("response", {})
        req_headers = _headers_to_dict(req.get("headers"))
        exchanges.append(
            Exchange(
                method=req.get("method", "GET").upper(),
                url=req.get("url", ""),
                principal=attribute(req_headers, principals),
                status=resp.get("status", 0),
                req_headers=req_headers,
                req_body=_body(req.get("postData", {})),
                resp_headers=_headers_to_dict(resp.get("headers")),
                resp_body=_body(resp.get("content", {})),
            )
        )
    return exchanges


def load(path: str, principals: dict[str, Principal]) -> list[Exchange]:
    with open(path) as fh:
        return parse(json.load(fh), principals)
