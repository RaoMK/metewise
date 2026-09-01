"""Shape signatures and value extraction.

A *shape signature* captures the structure of a response while dropping the
data: status, content-type family, and the set of JSON paths present (with a
type tag per leaf, array indices collapsed). Two responses with the same shape
are "the same kind of answer" even if every value differs.

    {"id": "x", "total": 5}          -> {$.id:str, $.total:num}
    {"error": "forbidden"}           -> {$.error:str}

Comparing shapes -- rather than body length, which is what most tools do --
is what lets a soft-403 (`200 {"error": ...}`) classify as a denial instead of
a leak.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


def _type_tag(v: object) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "num"
    if isinstance(v, str):
        return "str"
    if isinstance(v, list):
        return "arr"
    if isinstance(v, dict):
        return "obj"
    return "unk"


def _walk(node: object, path: str, out: dict[str, str]) -> None:
    """Collect {jsonpath: type_tag}. Array indices are collapsed to [] so a
    list of 3 items and a list of 30 items share a shape."""
    tag = _type_tag(node)
    if isinstance(node, dict):
        out[path] = "obj"
        for k in sorted(node):
            _walk(node[k], f"{path}.{k}", out)
    elif isinstance(node, list):
        out[path] = "arr"
        # Merge the shapes of all elements under a single [] path so that
        # element count never affects the signature.
        for item in node:
            _walk(item, f"{path}[]", out)
    else:
        out[path] = tag


def _content_family(headers: dict[str, str]) -> str:
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v
            break
    ct = ct.split(";")[0].strip().lower()
    if "json" in ct:
        return "json"
    if "html" in ct:
        return "html"
    if "text" in ct:
        return "text"
    return ct or "none"


@dataclass(frozen=True)
class ShapeSignature:
    status_class: int             # 2, 3, 4, 5 -- the status *class*, not exact code
    status: int
    content: str                  # json | html | text | ...
    paths: frozenset[str]         # {"$.id:str", "$.total:num", ...}

    @classmethod
    def of(cls, status: int, headers: dict[str, str], body: object) -> "ShapeSignature":
        paths: dict[str, str] = {}
        if isinstance(body, (dict, list)):
            _walk(body, "$", paths)
        tagged = frozenset(f"{p}:{t}" for p, t in paths.items())
        return cls(
            status_class=status // 100,
            status=status,
            content=_content_family(headers),
            paths=tagged,
        )

    def similarity(self, other: "ShapeSignature") -> float:
        """0..1 Jaccard over paths, gated by status class and content family.

        A different status *class* (2xx vs 4xx) is a hard mismatch -> 0, because
        that distinction is the strongest denial signal we have. Within the same
        class we fall back to structural overlap.
        """
        if self.status_class != other.status_class:
            return 0.0
        if self.content != other.content:
            return 0.1
        if not self.paths and not other.paths:
            return 1.0
        inter = len(self.paths & other.paths)
        union = len(self.paths | other.paths)
        return inter / union if union else 1.0


# ---------------------------------------------------------------------------
# Value extraction and volatility
# ---------------------------------------------------------------------------

def leaf_values(body: object) -> dict[str, object]:
    """Flatten a JSON body to {jsonpath: leaf_value} for scalar leaves.

    Used to prove a leak: if the probe response shares concrete leaf values
    with the victim's baseline, the actor genuinely received the victim's data.
    """
    out: dict[str, object] = {}

    def rec(node: object, path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                rec(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                rec(v, f"{path}[{i}]")
        else:
            out[path] = node

    rec(body, "$")
    return out


def volatile_paths(body_a: object, body_b: object) -> set[str]:
    """Paths whose leaf values differ between two identical requests.

    Timestamps, ETags, request IDs, CSRF tokens. These must be excluded from
    the leak proof or they generate false positives. Cheap insurance: fetch the
    baseline twice and diff.
    """
    la, lb = leaf_values(body_a), leaf_values(body_b)
    vol = {p for p in la.keys() & lb.keys() if la[p] != lb[p]}
    vol |= la.keys() ^ lb.keys()  # paths present in only one draw are volatile too
    return vol


# ---------------------------------------------------------------------------
# Reference-value detection (for parameter role classification)
# ---------------------------------------------------------------------------

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_INT = re.compile(r"^\d+$")
_SLUG = re.compile(r"^[a-z0-9]+(?:[-_][a-z0-9]+)*$", re.I)


def classify_value(v: str) -> str:
    """Guess the kind of an identifier so we can synthesize a matching control."""
    if _UUID.match(v):
        return "uuid"
    if _INT.match(v):
        return "int"
    if _SLUG.match(v) and not v.isdigit():
        return "slug"
    return "opaque"
