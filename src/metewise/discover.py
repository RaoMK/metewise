"""Turn observed traffic into a probe plan, with no hand-written scenario.

The pipeline:

  1. collect_identifiers  -- every scalar the API *emitted* in a response body,
     tagged with the principal(s) who produced it. This is the key idea: a value
     the server handed back is an object identifier we can reason about; a static
     route word ("invoices") never appears as response data, so it self-filters.

  2. templatize           -- rewrite each observed URL into one template per
     id-like segment (`/invoices/{id}`), holding the other segments fixed. A
     segment is a parameter if it's a uuid/int, or if its value is one of the
     identifiers the API emitted.

  3. plan                 -- for each discovered object, whose owner is the
     principal that produced it, schedule a probe by every *other* principal.

Only reads (GET/HEAD) are planned in v1; write-side probing is opt-in and lives
on the roadmap.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

from .model import Exchange, ObjectRef, Principal
from .shape import classify_value, leaf_values


def _looks_identifier(s: str, kind: str) -> bool:
    """Is this scalar plausibly an object id worth reasoning about?

    Deliberately broad on collection (URL usage filters later) but excludes
    trivia -- single-digit flags, short enums -- that would only add noise.
    """
    if kind == "uuid":
        return True
    if kind == "int":
        return len(s) >= 3            # skip counts, versions, small flags
    return len(s) >= 6                # slug / opaque: emails, tokens, names


def collect_identifiers(exchanges: list[Exchange]) -> dict[str, dict]:
    """value -> {"kind": str, "producers": set[str]}."""
    ids: dict[str, dict] = {}
    for ex in exchanges:
        if ex.status // 100 != 2:
            continue                  # only trust identifiers from real responses
        for _, val in leaf_values(ex.resp_body).items():
            if not isinstance(val, (str, int)) or isinstance(val, bool):
                continue
            s = str(val)
            kind = classify_value(s)
            if not _looks_identifier(s, kind):
                continue
            entry = ids.setdefault(s, {"kind": kind, "producers": set()})
            entry["producers"].add(ex.principal)
    return ids


def templatize(url: str, ids: dict[str, dict]) -> list[tuple[str, str, str]]:
    """Return (template, value, kind) once per id-like slot in the URL.

    `template` uses a single `{id}` placeholder at the varying slot; every other
    slot is concretised to its observed value, so each probe isolates one object
    dimension (`/users/{id}/orders/7` vs `/users/3/orders/{id}`).
    """
    sp = urlsplit(url)
    path_segs = sp.path.split("/")
    query = parse_qsl(sp.query, keep_blank_values=True)

    def seg_is_param(raw: str) -> tuple[bool, str]:
        dec = unquote(raw)
        if not dec:
            return False, ""
        kind = classify_value(dec)
        if kind in ("uuid", "int") and _looks_identifier(dec, kind):
            return True, kind
        if dec in ids:
            return True, ids[dec]["kind"]
        return False, ""

    slots: list[tuple[str, str, str]] = []  # (locator, value, kind)
    for i, raw in enumerate(path_segs):
        ok, kind = seg_is_param(raw)
        if ok:
            slots.append((f"path:{i}", unquote(raw), kind))
    for qi, (k, v) in enumerate(query):
        ok, kind = seg_is_param(v)
        if ok:
            slots.append((f"query:{qi}", v, kind))

    results: list[tuple[str, str, str]] = []
    for locator, value, kind in slots:
        segs = list(path_segs)
        q = list(query)
        if locator.startswith("path:"):
            segs[int(locator.split(":")[1])] = "{id}"
        else:
            qi = int(locator.split(":")[1])
            q[qi] = (q[qi][0], "{id}")
        template = "/".join(segs)
        if q:
            # urlencode would escape the braces; assemble by hand so {id} survives.
            template += "?" + "&".join(f"{k}={v}" for k, v in q)
        results.append((template, value, kind))
    return results


@dataclass
class Plan:
    base_url: str
    template: str
    method: str
    ref: ObjectRef
    owner: Principal
    actor: Principal


def _base_url(url: str) -> str:
    sp = urlsplit(url)
    return f"{sp.scheme}://{sp.netloc}"


def plan_probes(
    exchanges: list[Exchange], principals: dict[str, Principal],
) -> list[Plan]:
    ids = collect_identifiers(exchanges)
    actors = dict(principals)
    actors.setdefault("anon", Principal("anon", headers={}))

    plans: dict[tuple, Plan] = {}
    for ex in exchanges:
        if ex.method not in ("GET", "HEAD"):
            continue  # read-side only in v1
        if ex.status // 100 != 2:
            continue  # template from requests we know succeeded for their caller
        base = _base_url(ex.url)
        for template, value, kind in templatize(ex.url, ids):
            owner_name = _owner_of(value, ids, ex.principal)
            if owner_name is None or owner_name not in principals:
                continue  # ambiguous/shared owner, or an unmapped principal
            owner = principals[owner_name]
            ref = ObjectRef(value, kind, owner_name, owner.tenant)
            for actor_name, actor in actors.items():
                if actor_name == owner_name:
                    continue
                key = (ex.method, template, value, actor_name)
                if key in plans:
                    continue
                plans[key] = Plan(base, template, ex.method, ref, owner, actor)
    return list(plans.values())


def _owner_of(value: str, ids: dict[str, dict], fallback: str) -> str | None:
    entry = ids.get(value)
    if entry is None:
        return fallback                       # never seen produced; attribute to user
    producers = entry["producers"]
    if len(producers) == 1:
        return next(iter(producers))          # sole producer owns it
    return None                               # produced by several -> shared/public
