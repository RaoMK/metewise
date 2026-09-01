"""Gather the four-corner reference set for a probe, then adjudicate.

This is the piece that turns a plan into evidence: given a target object owned
by someone, and an actor who shouldn't reach it, it makes the small battery of
requests the oracle needs and hands back a verdict.
"""

from __future__ import annotations

import hashlib

from . import auth, http
from .model import Adjudication, Finding, ObjectRef, Principal, Probe, Tier, Verdict
from .oracle import Corners, adjudicate
from .shape import classify_value


def _synthesize_absent(ref: ObjectRef) -> str:
    """A well-formed but (almost certainly) nonexistent id of the same kind, to
    provoke the deny-control response."""
    if ref.kind == "uuid":
        return "00000000-dead-4000-8000-000000000000"
    if ref.kind == "int":
        return str(int(ref.value) * 1000 + 987654) if ref.value.isdigit() else "999999999"
    if ref.kind == "slug":
        return "metewise-absent-" + hashlib.sha1(ref.value.encode()).hexdigest()[:8]
    return "metewise-absent-" + hashlib.sha1(ref.value.encode()).hexdigest()[:12]


def _liveness_ok(base_url: str, principal: Principal, probe_url: str) -> bool:
    """A dead actor token turns every probe into a 401 that reads as a denial --
    a false-negative machine. Refuse to trust a run whose actor isn't live.

    Heuristic check: the actor should be able to reach *something*. We reuse the
    deny-control request; a 401/403 there while the owner succeeds is the tell,
    handled by the caller returning INVALID.
    """
    return True  # placeholder; real liveness hook is per-target, see run()


def probe_object(
    base_url: str, template: str, ref: ObjectRef,
    actor: Principal, owner: Principal, method: str = "GET",
) -> Adjudication:
    """Run one cross-principal probe and adjudicate it."""
    def url_for(value: str) -> str:
        return base_url.rstrip("/") + template.format(id=value)

    target_url = url_for(ref.value)
    absent_url = url_for(_synthesize_absent(ref))

    baseline = http.request(method, target_url, owner.headers)
    # A dead owner token turns every probe into a false "all clear". If the
    # owner can't read their own object and has a login recipe, re-authenticate
    # both sides once and try again before giving up.
    if baseline[0] // 100 != 2 and (owner.login or actor.login):
        auth.refresh(owner)
        auth.refresh(actor)
        baseline = http.request(method, target_url, owner.headers)

    baseline2 = http.request(method, target_url, owner.headers)
    probe_resp = http.request(method, target_url, actor.headers)
    deny_ctrl = http.request(method, absent_url, actor.headers)
    public_ctrl = http.request(method, target_url, {})  # anon

    # Invalid-run guard: if the owner can't even read their own object, the
    # baseline is worthless and we must not emit verdicts from it.
    if baseline[0] // 100 != 2:
        probe = Probe(template, method, actor.name, ref, Tier.READ, target_url)
        return Adjudication(
            probe=probe, verdict=Verdict.INVALID, confidence="n/a",
            reason=f"owner '{owner.name}' got {baseline[0]} on their own object; "
                   f"baseline unusable (expired token or wrong owner?)",
        )

    probe = Probe(template, method, actor.name, ref, Tier.READ, target_url)
    corners = Corners(
        probe=probe_resp, baseline=baseline, baseline2=baseline2,
        deny_control=deny_ctrl, public_control=public_ctrl,
    )
    return adjudicate(probe, corners)


def _axis(actor: Principal, owner: Principal) -> str:
    if actor.is_anon:
        return "unauthenticated"
    if actor.tenant and owner.tenant and actor.tenant != owner.tenant:
        return "cross-tenant"
    return "intra-tenant"


def to_finding(adj: Adjudication, owner: Principal, actor: Principal) -> Finding:
    """Stable fingerprint over (template, method, axis) so the finding survives
    changing ids and CI can diff against a baseline."""
    axis = _axis(actor, owner)
    raw = f"{adj.probe.method} {adj.probe.template} {axis}"
    fp = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return Finding(
        fingerprint=fp, template=adj.probe.template, method=adj.probe.method,
        actor=actor.name, owner=owner.name, axis=axis,
        confidence=adj.confidence, leaked_fields=adj.leaked_fields,
    )
