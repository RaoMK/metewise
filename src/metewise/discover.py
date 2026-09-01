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
from urllib.parse import parse_qsl, unquote, urlsplit

from .model import (
    CreateRecipe, Exchange, ObjectRef, Principal, Tier, WritePlan, tier_of,
)
from .shape import classify_value, leaf_values, looks_identifier

# Back-compat alias: this heuristic now lives in shape.py.
_looks_identifier = looks_identifier


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


# ---------------------------------------------------------------------------
# Write-side: create recipes (for seeding) and write-probe plans
# ---------------------------------------------------------------------------

def collect_create_recipes(exchanges: list[Exchange]) -> dict[str, CreateRecipe]:
    """Learn how to mint throwaway objects from observed POSTs.

    A POST that returns an identifier the request didn't send is a creation
    endpoint; replaying it lets destructive probes act on a fresh object rather
    than on real data. Keyed by collection path (e.g. "/invoices").
    """
    recipes: dict[str, CreateRecipe] = {}
    for ex in exchanges:
        if ex.method != "POST" or ex.status // 100 != 2:
            continue
        sp = urlsplit(ex.url)
        req_vals = {str(v) for v in leaf_values(ex.req_body or {}).values()}
        for path, val in leaf_values(ex.resp_body).items():
            if not isinstance(val, (str, int)) or isinstance(val, bool):
                continue
            s = str(val)
            kind = classify_value(s)
            if not looks_identifier(s, kind) or s in req_vals:
                continue                      # not a server-generated id
            recipes[sp.path] = CreateRecipe(
                base_url=f"{sp.scheme}://{sp.netloc}", path=sp.path,
                method="POST", body=ex.req_body, id_path=path, kind=kind,
            )
            break
    return recipes


def plan_write_probes(
    exchanges: list[Exchange], principals: dict[str, Principal],
    *, allow_destructive: bool = False,
) -> list[WritePlan]:
    """Plan PUT/PATCH/DELETE probes. Forbidden endpoints are dropped; DELETE is
    planned only when `allow_destructive` and a create recipe exists to seed a
    throwaway."""
    ids = collect_identifiers(exchanges)
    recipes = collect_create_recipes(exchanges)
    actors = dict(principals)
    actors.setdefault("anon", Principal("anon", headers={}))

    plans: dict[tuple, WritePlan] = {}
    for ex in exchanges:
        if ex.method not in ("PUT", "PATCH", "DELETE"):
            continue
        if ex.status // 100 != 2:
            continue
        base = _base_url(ex.url)
        for template, value, kind in templatize(ex.url, ids):
            tier = tier_of(ex.method, template)
            if tier is Tier.FORBIDDEN:
                continue
            if tier is Tier.DESTRUCTIVE and not allow_destructive:
                continue
            owner_name = _owner_of(value, ids, ex.principal)
            if owner_name is None or owner_name not in principals:
                continue
            owner = principals[owner_name]
            ref = ObjectRef(value, kind, owner_name, owner.tenant)

            recipe = None
            path = template.split("?")[0]
            if path.endswith("/{id}"):
                recipe = recipes.get(path[: -len("/{id}")])
            if tier is Tier.DESTRUCTIVE and recipe is None:
                continue  # no safe way to seed a throwaway -> skip destructive

            for actor_name, actor in actors.items():
                if actor_name == owner_name:
                    continue
                # Destructive probes seed their own object, so the specific
                # discovered value is irrelevant -> dedupe without it.
                key = (
                    (ex.method, template, actor_name) if tier is Tier.DESTRUCTIVE
                    else (ex.method, template, value, actor_name)
                )
                if key in plans:
                    continue
                plans[key] = WritePlan(
                    base, template, ex.method, ref, owner, actor, tier, recipe,
                )
    return list(plans.values())
