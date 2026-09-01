"""Run metewise against a target and collect the endpoints it flags.

Kept separate from any one target so the same collection logic scores the local
fixture and a Dockerised app (crAPI, VAmPI, ...) identically. A target supplies
three things: a base URL, a captured/observed set of Exchanges, and the
principals; this returns the set of (METHOD, template) pairs metewise reports as
leaks -- exactly what benchmark/score.py compares to ground truth.
"""

from __future__ import annotations

import pathlib
import sys

SRC = pathlib.Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from metewise.discover import plan_probes, plan_write_probes  # noqa: E402
from metewise.engine import probe_object  # noqa: E402
from metewise.model import Exchange, Principal, Verdict  # noqa: E402
from metewise.writeprobe import probe_write  # noqa: E402

from score import key  # noqa: E402


def collect_findings(
    exchanges: list[Exchange], principals: dict[str, Principal],
    *, write: bool = True, allow_destructive: bool = True,
) -> set[tuple[str, str]]:
    """Return the (METHOD, template) pairs metewise flags as leaks."""
    found: set[tuple[str, str]] = set()

    for p in plan_probes(exchanges, principals):
        adj = probe_object(
            p.base_url, p.template, p.ref, actor=p.actor, owner=p.owner,
            method=p.method,
        )
        if adj.verdict is Verdict.LEAK:
            found.add(key(p.method, p.template))

    if write:
        for wp in plan_write_probes(
            exchanges, principals, allow_destructive=allow_destructive
        ):
            adj = probe_write(wp)
            if adj.verdict is Verdict.LEAK:
                found.add(key(wp.method, wp.template))

    return found
