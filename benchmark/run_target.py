"""Benchmark metewise against any running target from a captured HAR.

Unlike run_fixture.py (which starts its own app), this scores an already-running
target -- typically a Dockerised vulnerable app such as crAPI or VAmPI. The
script itself needs no Docker; it just needs the target reachable and a HAR
captured against it.

    python3 benchmark/run_target.py \
        --har captures/vampi.har \
        --principals captures/vampi.principals.json \
        --expectations expectations/vampi.json \
        [--no-destructive]

Exit code 0 if precision and recall are both 100%, else 1.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "src"))

from metewise import har  # noqa: E402
from metewise.model import Principal  # noqa: E402

from harness import collect_findings  # noqa: E402
from score import Expectations, report, score  # noqa: E402


def _principals(path: str) -> dict[str, Principal]:
    with open(path) as fh:
        raw = json.load(fh)
    return {
        name: Principal(name=name, tenant=spec.get("tenant"),
                        role=spec.get("role", "member"), headers=spec.get("headers", {}))
        for name, spec in raw.items()
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--har", nargs="+", required=True)
    ap.add_argument("--principals", required=True)
    ap.add_argument("--expectations", required=True)
    ap.add_argument("--no-destructive", action="store_true",
                    help="skip DELETE probing (safer on shared targets)")
    args = ap.parse_args()

    principals = _principals(args.principals)
    exchanges = []
    for h in args.har:
        exchanges.extend(har.load(h, principals))

    found = collect_findings(
        exchanges, principals, write=True,
        allow_destructive=not args.no_destructive,
    )
    s = score(found, Expectations.load(args.expectations))
    print(report(s))
    return 0 if s.perfect else 1


if __name__ == "__main__":
    raise SystemExit(main())
