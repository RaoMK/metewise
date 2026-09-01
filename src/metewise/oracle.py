"""The four-corner oracle.

For a probe -- actor B requesting an object owned by A -- we hold up to four
reference responses:

                    A's object        B's own object     nonexistent
    as owner (A)    baseline (x2)         --                 --
    as actor (B)    THE PROBE          allow-control      deny-control

The verdict is a *classification* of the probe against the two controls, not a
comparison of two responses:

    probe ~ deny-control                       -> DENIED
    probe ~ allow-control  AND shares baseline
        leaf values (minus volatile ones)      -> LEAK (confirmed)
    probe ~ baseline shape, no controls        -> LEAK (probable)
    matches neither                            -> UNKNOWN

Corners may be missing (we can't always mint a "B's own object"); the oracle
degrades to the best verdict the available evidence supports and records why.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Adjudication, Probe, Verdict
from .shape import ShapeSignature, leaf_values, volatile_paths

# A probe within this similarity of a control is treated as "the same kind of
# answer" as that control.
_MATCH = 0.75


@dataclass
class Corners:
    """The reference responses available for one probe. Each is (status,
    headers, body). Any but `probe` may be None when it couldn't be gathered."""

    probe: tuple[int, dict, object]
    baseline: tuple[int, dict, object] | None = None
    baseline2: tuple[int, dict, object] | None = None   # second draw, for volatility
    allow_control: tuple[int, dict, object] | None = None
    deny_control: tuple[int, dict, object] | None = None
    public_control: tuple[int, dict, object] | None = None  # same object fetched anon

    def _sig(self, corner) -> ShapeSignature | None:
        if corner is None:
            return None
        status, headers, body = corner
        return ShapeSignature.of(status, headers, body)


def adjudicate(probe: Probe, c: Corners) -> Adjudication:
    probe_sig = c._sig(c.probe)
    deny_sig = c._sig(c.deny_control)
    allow_sig = c._sig(c.allow_control)
    base_sig = c._sig(c.baseline)

    sim_deny = probe_sig.similarity(deny_sig) if deny_sig else None
    sim_allow = probe_sig.similarity(allow_sig) if allow_sig else None
    sim_base = probe_sig.similarity(base_sig) if base_sig else None

    def result(verdict, confidence, reason, leaked=None):
        return Adjudication(
            probe=probe, verdict=verdict, confidence=confidence,
            reason=reason, leaked_fields=leaked or {},
        )

    # 0. Public resource: if an unauthenticated principal receives the same
    #    object, this is a shared/public endpoint, not a broken ownership check.
    #    Distinguishing "B read A's private data" from "everyone can read this"
    #    is the false-positive that sinks naive BOLA tools.
    pub_sig = c._sig(c.public_control)
    if pub_sig is not None and pub_sig.status_class == 2:
        sim_pub = probe_sig.similarity(pub_sig)
        if sim_pub >= _MATCH:
            return result(
                Verdict.DENIED, "n/a",
                f"object is also served to an unauthenticated client "
                f"(sim={sim_pub:.2f}); public resource, not a BOLA",
            )

    # 1. Clear denial: probe resembles the deny-control and is unlike an allow.
    if sim_deny is not None and sim_deny >= _MATCH:
        if sim_allow is None or sim_deny >= sim_allow:
            return result(
                Verdict.DENIED, "n/a",
                f"probe matches deny-control (sim={sim_deny:.2f}); access refused",
            )

    # 2. Confirmed leak: probe looks like a real object AND carries the victim's
    #    own leaf values. This is the gold verdict -- it names the leaked data.
    if base_sig is not None and sim_base is not None and sim_base >= _MATCH:
        _, _, probe_body = c.probe
        _, _, base_body = c.baseline
        vol: set[str] = set()
        if c.baseline2 is not None:
            _, _, base_body2 = c.baseline2
            vol = volatile_paths(base_body, base_body2)

        base_leaves = leaf_values(base_body)
        probe_leaves = leaf_values(probe_body)
        shared = {
            p: base_leaves[p]
            for p in base_leaves.keys() & probe_leaves.keys()
            if p not in vol
            and base_leaves[p] == probe_leaves[p]
            and _is_identifying(base_leaves[p])
        }
        if shared:
            return result(
                Verdict.LEAK, "confirmed",
                f"actor received owner's object (sim={sim_base:.2f}); "
                f"{len(shared)} stable leaf value(s) match the victim baseline",
                leaked=shared,
            )
        # Same shape as a real object, but no distinguishing values matched.
        # Could be a legitimately shared/empty resource -> probable, not confirmed.
        return result(
            Verdict.LEAK, "probable",
            f"probe matches object shape (sim={sim_base:.2f}) but no unique "
            f"leaf values overlapped; verify manually",
        )

    # 3. Probe looks like an allowed object and we lack a baseline to prove it.
    if sim_allow is not None and sim_allow >= _MATCH:
        return result(
            Verdict.LEAK, "probable",
            f"probe matches allow-control object shape (sim={sim_allow:.2f}); "
            f"no baseline available to confirm data leak",
        )

    # 4. Nothing matched cleanly. Hand it to a human rather than guess.
    parts = []
    if sim_deny is not None:
        parts.append(f"deny={sim_deny:.2f}")
    if sim_allow is not None:
        parts.append(f"allow={sim_allow:.2f}")
    if sim_base is not None:
        parts.append(f"base={sim_base:.2f}")
    return result(
        Verdict.UNKNOWN, "n/a",
        "probe matched no reference within threshold (" + ", ".join(parts) + ")",
    )


def _is_identifying(v: object) -> bool:
    """A leaf value distinctive enough that sharing it proves a data leak.

    Filters out values so common (empty string, 0, True, small enums) that an
    overlap would be coincidental rather than evidence.
    """
    if isinstance(v, bool) or v is None:
        return False
    if isinstance(v, (int, float)):
        return abs(v) >= 1000            # ids, totals, timestamps -- not flags/counts
    if isinstance(v, str):
        return len(v) >= 6               # emails, names, uuids, tokens
    return False
