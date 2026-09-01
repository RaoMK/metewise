"""metewise CLI.

Two ways in:

  metewise scan-har capture.har --principals principals.json
      Ingest a real HAR capture, auto-discover object references and their
      owners, and probe every one across principals. No hand-written objects.

  metewise scan scenario.json
      Run an explicit scenario (target, principals, and objects spelled out).
      Useful for narrow, hand-aimed checks and for testing.

Exit codes are CI-shaped:
    0  clean: no leaks
    1  usage / config error
    2  run INVALID: could not be trusted (e.g. an owner token was dead)
    3  leaks found
"""

from __future__ import annotations

import argparse
import json
import sys

from . import har
from .discover import plan_probes
from .engine import probe_object, to_finding
from .model import ObjectRef, Principal, Verdict


def _load_principals(raw: dict) -> dict[str, Principal]:
    out = {}
    for name, spec in raw.items():
        out[name] = Principal(
            name=name, tenant=spec.get("tenant"),
            role=spec.get("role", "member"), headers=spec.get("headers", {}),
        )
    return out


# ---------------------------------------------------------------------------
# scan  (explicit scenario)
# ---------------------------------------------------------------------------

def run_scenario(scenario: dict) -> int:
    base = scenario["base_url"]
    principals = _load_principals(scenario["principals"])
    findings, invalid = [], []
    for obj in scenario["objects"]:
        owner = principals[obj["owner"]]
        ref = ObjectRef(obj["value"], obj["kind"], owner.name, owner.tenant)
        for name, actor in principals.items():
            if name == owner.name:
                continue
            adj = probe_object(
                base, obj["template"], ref, actor=actor, owner=owner,
                method=obj.get("method", "GET"),
            )
            _sort(adj, owner, actor, findings, invalid)
    _report(findings, invalid)
    return _exit_code(findings, invalid)


# ---------------------------------------------------------------------------
# scan-har  (ingest capture, auto-discover)
# ---------------------------------------------------------------------------

def run_har(har_path: str, principals_path: str) -> int:
    with open(principals_path) as fh:
        principals = _load_principals(json.load(fh))
    exchanges = har.load(har_path, principals)
    plans = plan_probes(exchanges, principals)

    print(
        f"ingested {len(exchanges)} exchanges; "
        f"planned {len(plans)} cross-principal probe(s)\n",
        file=sys.stderr,
    )
    findings, invalid = [], []
    for p in plans:
        adj = probe_object(
            p.base_url, p.template, p.ref, actor=p.actor, owner=p.owner,
            method=p.method,
        )
        _sort(adj, p.owner, p.actor, findings, invalid)
    _report(findings, invalid)
    return _exit_code(findings, invalid)


# ---------------------------------------------------------------------------
# shared reporting
# ---------------------------------------------------------------------------

def _sort(adj, owner, actor, findings, invalid) -> None:
    if adj.verdict is Verdict.INVALID:
        invalid.append(adj)
    elif adj.verdict.is_finding:
        findings.append((adj, owner, actor))


def _exit_code(findings, invalid) -> int:
    if invalid:
        return 2
    if findings:
        return 3
    return 0


def _report(findings, invalid) -> None:
    if invalid:
        print("RUN INVALID -- results cannot be trusted:\n")
        for adj in invalid:
            print(f"  ! {adj.probe.method} {adj.probe.template}: {adj.reason}")
        print()

    if not findings:
        print("No object-authorization leaks found.")
        return

    # Deduplicate by fingerprint for the headline, but keep every instance.
    seen: set[str] = set()
    print(f"{len(findings)} finding(s):\n")
    for adj, owner, actor in findings:
        f = to_finding(adj, owner, actor)
        dup = " (repeat)" if f.fingerprint in seen else ""
        seen.add(f.fingerprint)
        mark = "CONFIRMED" if adj.confidence == "confirmed" else "PROBABLE "
        print(f"  [{mark}] {f.fingerprint}  {f.method} {f.template}{dup}")
        print(f"      axis: {f.axis}   actor '{actor.name}' read '{owner.name}' object")
        print(f"      {adj.reason}")
        for path, val in adj.leaked_fields.items():
            print(f"        leaked {path} = {val!r}")
        print()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="metewise", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("scan", help="run an explicit scenario JSON")
    s1.add_argument("scenario")

    s2 = sub.add_parser("scan-har", help="ingest a HAR capture and auto-discover")
    s2.add_argument("har")
    s2.add_argument("--principals", required=True, help="principals JSON file")

    args = ap.parse_args(argv)
    try:
        if args.cmd == "scan":
            with open(args.scenario) as fh:
                return run_scenario(json.load(fh))
        if args.cmd == "scan-har":
            return run_har(args.har, args.principals)
    except (OSError, json.JSONDecodeError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
