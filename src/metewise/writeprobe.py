"""Write-side BOLA probing: does another user get to *change* or *delete* your
object, not just read it?

Reads can be judged by comparing response bodies. Writes can't -- a successful
unauthorized DELETE just returns 204, and the damage only shows when the owner
looks again. So the write oracle is **effect-based**: perform the write as the
attacker, then check, as the owner, whether the object actually changed.

Two tiers, both designed to be safe to run:

  MUTATE (PUT/PATCH)  snapshot the object as the owner, have the attacker write
                      a marked sentinel, check whether it stuck, then restore
                      the original value and verify the restore.

  DESTRUCTIVE (DELETE)  never touch a real object. Seed a throwaway via the
                        create recipe, have the attacker delete *that*, and check
                        whether it vanished. Clean up the seed if it survived.
"""

from __future__ import annotations

import uuid

from . import auth, http
from .model import (
    Adjudication, CreateRecipe, Principal, Probe, Tier, Verdict, WritePlan,
)
from .shape import get_path


def probe_write(plan: WritePlan) -> Adjudication:
    if plan.tier is Tier.MUTATE:
        return _mutate(plan)
    if plan.tier is Tier.DESTRUCTIVE:
        return _destroy(plan)
    return _adj(plan, Verdict.UNKNOWN, "n/a",
                f"tier {plan.tier.name} is not probed")


# ---------------------------------------------------------------------------
# MUTATE: snapshot -> attacker writes sentinel -> check -> restore
# ---------------------------------------------------------------------------

def _mutate(plan: WritePlan) -> Adjudication:
    url = plan.base_url.rstrip("/") + plan.template.format(id=plan.ref.value)

    snap_status, _, snap_body = http.request("GET", url, plan.owner.headers)
    if snap_status // 100 != 2 and (plan.owner.login or plan.actor.login):
        auth.refresh(plan.owner)
        auth.refresh(plan.actor)
        snap_status, _, snap_body = http.request("GET", url, plan.owner.headers)
    if snap_status // 100 != 2 or not isinstance(snap_body, dict):
        return _adj(plan, Verdict.INVALID, "n/a",
                    f"owner '{plan.owner.name}' could not read the object to "
                    f"snapshot (status {snap_status}); cannot test safely")

    field, original = _pick_mutable_field(snap_body)
    if field is None:
        return _adj(plan, Verdict.UNKNOWN, "n/a",
                    "no mutable scalar field found to test")

    sentinel = _sentinel(original)
    http.request(plan.method, url, plan.actor.headers, {field: sentinel})

    _, _, after = http.request("GET", url, plan.owner.headers)
    changed = isinstance(after, dict) and str(after.get(field)) == str(sentinel)

    if not changed:
        return _adj(plan, Verdict.DENIED, "n/a",
                    f"attacker's {plan.method} did not change the owner's "
                    f"'{field}'; write refused")

    # Leak. Put the original value back and confirm the restore took.
    http.request(plan.method, url, plan.owner.headers, {field: original})
    _, _, restored_body = http.request("GET", url, plan.owner.headers)
    restored = isinstance(restored_body, dict) and \
        str(restored_body.get(field)) == str(original)
    warn = "" if restored else "  !! RESTORE FAILED -- data left modified"
    return _adj(
        plan, Verdict.LEAK, "confirmed",
        f"attacker modified the owner's object via {plan.method}{warn}",
        leaked={field: f"{original!r} -> {sentinel!r} (then restored)"
                if restored else f"{original!r} -> {sentinel!r}"},
    )


# ---------------------------------------------------------------------------
# DESTRUCTIVE: seed throwaway -> attacker deletes -> check gone -> cleanup
# ---------------------------------------------------------------------------

def _destroy(plan: WritePlan) -> Adjudication:
    if plan.recipe is None:
        return _adj(plan, Verdict.UNKNOWN, "n/a",
                    "no create recipe to seed a throwaway; destructive probe skipped")

    seeded = _seed(plan.recipe, plan.owner)
    if seeded is None and plan.owner.login:
        auth.refresh(plan.owner)
        seeded = _seed(plan.recipe, plan.owner)
    if seeded is None:
        return _adj(plan, Verdict.INVALID, "n/a",
                    f"could not seed a throwaway object as '{plan.owner.name}'")

    read_url = plan.base_url.rstrip("/") + plan.template.format(id=seeded)
    http.request("DELETE", read_url, plan.actor.headers)

    gone_status, _, _ = http.request("GET", read_url, plan.owner.headers)
    if gone_status in (404, 410):
        return _adj(plan, Verdict.LEAK, "confirmed",
                    "attacker deleted an object owned by someone else "
                    "(tested on a seeded throwaway)",
                    leaked={"deleted_object": seeded})

    # Survived -> not a leak. Remove our seed so we leave nothing behind.
    http.request("DELETE", read_url, plan.owner.headers)
    return _adj(plan, Verdict.DENIED, "n/a",
                f"attacker's DELETE did not remove the object (status {gone_status} "
                f"on owner re-read); delete refused")


def _seed(recipe: CreateRecipe, owner: Principal) -> str | None:
    url = recipe.base_url.rstrip("/") + recipe.path
    status, _, body = http.request(recipe.method, url, owner.headers, recipe.body)
    if status // 100 != 2:
        return None
    val = get_path(body, recipe.id_path)
    if val is None:
        val = _first_identifier(body)
    return str(val) if val is not None else None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _pick_mutable_field(body: dict) -> tuple[str | None, object]:
    """Choose a scalar field safe to change: not an identity/ownership field.
    Prefer strings (unambiguous to sentinel and restore)."""
    reserved = {"id", "owner", "tenant", "created_at", "updated_at"}
    best = None
    for k, v in body.items():
        if k.lower() in reserved:
            continue
        if isinstance(v, str):
            return k, v
        if isinstance(v, (int, float)) and not isinstance(v, bool) and best is None:
            best = (k, v)
    return best if best else (None, None)


def _sentinel(original: object) -> object:
    token = uuid.uuid4().hex[:8]
    if isinstance(original, str):
        return f"metewise-canary-{token}"
    if isinstance(original, bool):
        return not original
    if isinstance(original, int):
        return -999_000_000 - (int(original) if str(original).isdigit() else 0)
    if isinstance(original, float):
        return -9.99e8
    return f"metewise-canary-{token}"


def _first_identifier(body: object) -> object | None:
    from .shape import classify_value, leaf_values, looks_identifier
    for _, v in leaf_values(body).items():
        if isinstance(v, (str, int)) and not isinstance(v, bool):
            s = str(v)
            if looks_identifier(s, classify_value(s)):
                return v
    return None


def _adj(plan: WritePlan, verdict: Verdict, confidence: str, reason: str,
         leaked: dict | None = None) -> Adjudication:
    probe = Probe(plan.template, plan.method, plan.actor.name, plan.ref,
                  plan.tier, plan.base_url + plan.template)
    return Adjudication(probe=probe, verdict=verdict, confidence=confidence,
                        reason=reason, leaked_fields=leaked or {})
