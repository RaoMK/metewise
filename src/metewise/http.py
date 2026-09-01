"""Minimal stdlib HTTP client. No third-party dependency for v1.

Returns (status, headers, parsed_body) where body is parsed JSON when the
response is JSON, else the raw text.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request


def request(
    method: str, url: str, headers: dict[str, str] | None = None,
    body: object = None, timeout: float = 10.0,
) -> tuple[int, dict[str, str], object]:
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return _read(resp.status, dict(resp.headers), resp.read())
    except urllib.error.HTTPError as e:
        # 4xx/5xx are expected outcomes, not exceptions, for a security tool.
        try:
            return _read(e.code, dict(e.headers), e.read())
        finally:
            e.close()


def _read(status: int, headers: dict[str, str], raw: bytes) -> tuple[int, dict, object]:
    text = raw.decode("utf-8", "replace")
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v.lower()
    body: object = text
    if "json" in ct and text.strip():
        try:
            body = json.loads(text)
        except json.JSONDecodeError:
            body = text
    return status, headers, body
