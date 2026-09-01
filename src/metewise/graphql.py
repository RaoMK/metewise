"""GraphQL BOLA probing.

GraphQL doesn't fit the REST URL-template model: every operation is a POST to a
single endpoint, and the object id lives in the request *body* -- in `variables`
(the recommended form) or as an inline literal in the query string. But the
response is still JSON, so metewise's four-corner oracle applies unchanged; only
discovery and request-shaping differ.

    POST /graphql
    {"query":"query($id:ID!){ invoice(id:$id){ id total } }",
     "variables":{"id":"A123"}}

metewise finds the id-bearing argument, re-issues the operation as another
principal (swapping only the id), and adjudicates the response the same way it
does a REST body.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import http
from .discover import _owner_of, collect_identifiers
from .engine import synthesize_absent
from .model import Adjudication, ObjectRef, Principal, Probe, Tier, Verdict
from .oracle import Corners, adjudicate
from .shape import classify_value, get_path, leaf_values, looks_identifier

# Matches an inline scalar argument:  id: "A123"   or   userId: 42
_INLINE_ARG = re.compile(r'(\w+)\s*:\s*(?:"([^"]+)"|(\d+))')
# First field after the opening brace of the operation, for a readable label.
_ROOT_FIELD = re.compile(r"\{\s*(\w+)")


def is_graphql(ex) -> bool:
    return (
        ex.method == "POST"
        and isinstance(ex.req_body, dict)
        and isinstance(ex.req_body.get("query"), str)
    )


@dataclass
class GraphQLOp:
    url: str
    query: str
    variables: dict
    id_arg: str          # variable name, or inline argument name
    id_value: str
    field: str           # root field, for reporting
    inline: bool = False

    def body(self, value: str | None = None) -> dict:
        """The request body, optionally with the id swapped to `value`."""
        if value is None:
            return {"query": self.query, "variables": self.variables}
        if self.inline:
            # Replace the literal once; keep everything else intact.
            q = self.query.replace(self.id_value, value, 1)
            return {"query": q, "variables": self.variables}
        return {"query": self.query, "variables": {**self.variables, self.id_arg: value}}

    @property
    def template(self) -> str:
        return f"/graphql [{self.field}({self.id_arg})]"


def _root_field(query: str) -> str:
    m = _ROOT_FIELD.search(query)
    return m.group(1) if m else "op"


def extract_ops(exchanges, ids: dict[str, dict]) -> list[tuple[GraphQLOp, str]]:
    """Return (op, requesting_principal) for every id-bearing GraphQL call."""
    out: list[tuple[GraphQLOp, str]] = []
    for ex in exchanges:
        if not is_graphql(ex) or ex.status // 100 != 2:
            continue
        query = ex.req_body["query"]
        if query.lstrip().startswith("mutation"):
            continue  # mutations are writes; v1 probes read-only queries only
        variables = ex.req_body.get("variables") or {}
        field = _root_field(query)
        seen: set[tuple[str, str]] = set()

        # 1) variables -- the standard, unambiguous case
        for k, v in variables.items():
            if isinstance(v, (str, int)) and not isinstance(v, bool):
                s = str(v)
                if looks_identifier(s, classify_value(s)) and (k, s) not in seen:
                    seen.add((k, s))
                    out.append((GraphQLOp(ex.url, query, variables, k, s, field, False),
                                ex.principal))

        # 2) inline literals in the query string (best-effort)
        if not variables:
            for name, sval, ival in _INLINE_ARG.findall(query):
                s = sval or ival
                if looks_identifier(s, classify_value(s)) and (name, s) not in seen:
                    seen.add((name, s))
                    out.append((GraphQLOp(ex.url, query, {}, name, s, field, True),
                                ex.principal))
    return out


@dataclass
class GraphQLPlan:
    op: GraphQLOp
    owner: Principal
    actor: Principal


def plan_graphql_probes(exchanges, principals: dict[str, Principal]) -> list[GraphQLPlan]:
    ids = collect_identifiers(exchanges)
    actors = dict(principals)
    actors.setdefault("anon", Principal("anon", headers={}))

    plans: dict[tuple, GraphQLPlan] = {}
    for op, requester in extract_ops(exchanges, ids):
        owner_name = _owner_of(op.id_value, ids, requester)
        if owner_name is None or owner_name not in principals:
            continue
        owner = principals[owner_name]
        for actor_name, actor in actors.items():
            if actor_name == owner_name:
                continue
            key = (op.field, op.id_arg, op.id_value, actor_name)
            if key in plans:
                continue
            plans[key] = GraphQLPlan(op, owner, actor)
    return list(plans.values())


def probe_graphql(plan: GraphQLPlan) -> Adjudication:
    op, owner, actor = plan.op, plan.owner, plan.actor
    ref = ObjectRef(op.id_value, classify_value(op.id_value), owner.name, owner.tenant)
    probe = Probe(op.template, "POST", actor.name, ref, Tier.READ, op.url)

    def send(value, headers):
        return http.request("POST", op.url, headers, op.body(value))

    baseline = send(None, owner.headers)
    if not _gql_ok(baseline) and (owner.login or actor.login):
        from . import auth
        auth.refresh(owner)
        auth.refresh(actor)
        baseline = send(None, owner.headers)
    if not _gql_ok(baseline):
        return Adjudication(
            probe=probe, verdict=Verdict.INVALID, confidence="n/a",
            reason=f"owner '{owner.name}' could not fetch their own GraphQL "
                   f"object (errors or null data); baseline unusable",
        )

    absent = synthesize_absent(op.id_value, ref.kind)
    corners = Corners(
        probe=send(None, actor.headers),
        baseline=baseline,
        baseline2=send(None, owner.headers),
        deny_control=send(absent, actor.headers),
        public_control=send(None, {}),
    )
    return adjudicate(probe, corners)


# ---------------------------------------------------------------------------
# Write-side: mutations (effect-verified via a paired read query)
# ---------------------------------------------------------------------------

import uuid as _uuid

from .model import Tier

_FIELD_ARGS = re.compile(r"(\w+)\s*\(([^)]*)\)")
_ONE_ARG = re.compile(r"(\w+)\s*:\s*(?:\$(\w+)|\"([^\"]+)\"|(\d+))")
_MUT_PREFIX = re.compile(r"^(create|add|new|update|edit|set|modify|delete|remove|destroy)",
                         re.I)


@dataclass
class MutationOp:
    url: str
    query: str
    variables: dict
    field: str
    args: dict                    # arg_name -> ("var", name) | ("lit", value)
    id_arg: str | None
    id_value: str | None
    object_base: str              # e.g. "invoice", for pairing with a read query
    kind: str                     # "create" | "update" | "delete"
    mutate_arg: str | None = None  # a non-id scalar arg to sentinel (updates)

    def body(self, id_value=None, overrides=None) -> dict:
        overrides = dict(overrides or {})
        vars_ = dict(self.variables)
        if id_value is not None and self.id_arg and self.args.get(self.id_arg, ("",))[0] == "var":
            vars_[self.args[self.id_arg][1]] = id_value
        for arg, val in overrides.items():
            src = self.args.get(arg)
            if src and src[0] == "var":
                vars_[src[1]] = val
        return {"query": self.query, "variables": vars_}

    @property
    def template(self) -> str:
        return f"/graphql [{self.field}({self.id_arg or 'input'})]"


def _parse_mutation_field(query: str):
    """Return (field_name, {arg: ('var',name)|('lit',value)}) for the first
    field in the mutation's selection set."""
    brace = query.find("{")
    body = query[brace + 1:] if brace >= 0 else query
    m = _FIELD_ARGS.search(body)
    if not m:
        return None, {}
    field, arglist = m.group(1), m.group(2)
    args: dict = {}
    for name, var, sval, ival in _ONE_ARG.findall(arglist):
        if var:
            args[name] = ("var", var)
        else:
            args[name] = ("lit", sval or ival)
    return field, args


def _resolve(src, variables):
    kind, ref = src
    return variables.get(ref) if kind == "var" else ref


def extract_mutations(exchanges, ids: dict[str, dict]):
    """Return (MutationOp, requesting_principal) for each mutation in the
    capture. Variable-based mutations only (inline mutations are v1 out-of-scope)."""
    out = []
    for ex in exchanges:
        if not is_graphql(ex) or ex.status // 100 != 2:
            continue
        query = ex.req_body["query"]
        if not query.lstrip().startswith("mutation"):
            continue
        variables = ex.req_body.get("variables") or {}
        field, args = _parse_mutation_field(query)
        if not field:
            continue
        pref = _MUT_PREFIX.match(field)
        kind = ("create" if pref and pref.group(1).lower() in ("create", "add", "new")
                else "delete" if pref and pref.group(1).lower() in ("delete", "remove", "destroy")
                else "update")
        base = _MUT_PREFIX.sub("", field).lstrip("_").lower() or field.lower()

        # id arg: an arg whose resolved value is an identifier
        id_arg = id_value = None
        for name, src in args.items():
            v = _resolve(src, variables)
            if isinstance(v, (str, int)) and not isinstance(v, bool):
                s = str(v)
                if looks_identifier(s, classify_value(s)):
                    id_arg, id_value = name, s
                    if name.lower() in ("id", f"{base}id", f"{base}_id"):
                        break
        # a non-id scalar arg to mutate (updates)
        mutate_arg = None
        for name, src in args.items():
            if name == id_arg:
                continue
            v = _resolve(src, variables)
            if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                mutate_arg = name
                break

        if kind in ("update", "delete") and id_arg is None:
            continue  # can't target an object without an id
        out.append((MutationOp(ex.url, query, variables, field, args,
                               id_arg, id_value, base, kind, mutate_arg), ex.principal))
    return out


@dataclass
class GraphQLWritePlan:
    mut: MutationOp
    read: GraphQLOp | None
    create: MutationOp | None
    owner: Principal
    actor: Principal
    tier: Tier


def plan_graphql_write_probes(exchanges, principals, *, allow_destructive=False):
    ids = collect_identifiers(exchanges)
    read_by_base = {}
    for op, _ in extract_ops(exchanges, ids):
        read_by_base.setdefault(op.field.lower(), op)
    muts = extract_mutations(exchanges, ids)
    create_by_base = {m.object_base: m for m, _ in muts if m.kind == "create"}
    actors = dict(principals)
    actors.setdefault("anon", Principal("anon", headers={}))

    plans: dict[tuple, GraphQLWritePlan] = {}
    for m, requester in muts:
        if m.kind == "create":
            continue
        owner_name = _owner_of(m.id_value, ids, requester)
        if owner_name is None or owner_name not in principals:
            continue
        read = read_by_base.get(m.object_base)
        tier = Tier.MUTATE if m.kind == "update" else Tier.DESTRUCTIVE
        if tier is Tier.DESTRUCTIVE and not allow_destructive:
            continue
        create = create_by_base.get(m.object_base) if tier is Tier.DESTRUCTIVE else None
        if tier is Tier.DESTRUCTIVE and create is None:
            continue  # no safe way to seed a throwaway to delete
        owner = principals[owner_name]
        for actor_name, actor in actors.items():
            if actor_name == owner_name:
                continue
            key = (m.field, m.id_arg, actor_name) if tier is Tier.DESTRUCTIVE \
                else (m.field, m.id_arg, m.id_value, actor_name)
            if key in plans:
                continue
            plans[key] = GraphQLWritePlan(m, read, create, owner, actor, tier)
    return list(plans.values())


def probe_graphql_write(plan: GraphQLWritePlan) -> Adjudication:
    if plan.tier is Tier.MUTATE:
        return _gql_update(plan)
    return _gql_delete(plan)


def _send(url, body, headers):
    return http.request("POST", url, headers, body)


def _adj(mut, actor, owner, verdict, confidence, reason, leaked=None):
    ref = ObjectRef(mut.id_value or "", classify_value(mut.id_value or ""),
                    owner.name, owner.tenant)
    probe = Probe(mut.template, "POST", actor.name, ref, Tier.READ, mut.url)
    return Adjudication(probe=probe, verdict=verdict, confidence=confidence,
                        reason=reason, leaked_fields=leaked or {})


def _read_object(read: GraphQLOp, id_value, headers):
    status, _, body = _send(read.url, read.body(id_value), headers)
    ok = (status // 100 == 2 and isinstance(body, dict) and not body.get("errors"))
    obj = get_path(body, f"$.data.{read.field}") if ok else None
    return obj


def _gql_update(plan: GraphQLWritePlan) -> Adjudication:
    m, read, owner, actor = plan.mut, plan.read, plan.owner, plan.actor
    if read is None:
        return _adj(m, actor, owner, Verdict.UNKNOWN, "n/a",
                    f"no read query for '{m.object_base}' to verify the mutation's effect")
    if not m.mutate_arg:
        return _adj(m, actor, owner, Verdict.UNKNOWN, "n/a",
                    "mutation has no non-id field to test")

    snap = _read_object(read, m.id_value, owner.headers)
    if not isinstance(snap, dict):
        return _adj(m, actor, owner, Verdict.INVALID, "n/a",
                    f"owner '{owner.name}' could not read the object to snapshot")
    original = snap.get(m.mutate_arg)
    sentinel = f"metewise-canary-{_uuid.uuid4().hex[:8]}"

    _send(m.url, m.body(id_value=m.id_value, overrides={m.mutate_arg: sentinel}),
          actor.headers)
    after = _read_object(read, m.id_value, owner.headers)
    changed = isinstance(after, dict) and str(after.get(m.mutate_arg)) == sentinel
    if not changed:
        return _adj(m, actor, owner, Verdict.DENIED, "n/a",
                    f"attacker's {m.field} did not change the owner's "
                    f"'{m.mutate_arg}'; write refused")

    _send(m.url, m.body(id_value=m.id_value, overrides={m.mutate_arg: original}),
          owner.headers)
    restored = isinstance(_read_object(read, m.id_value, owner.headers), dict) and \
        _read_object(read, m.id_value, owner.headers).get(m.mutate_arg) == original
    warn = "" if restored else "  !! RESTORE FAILED"
    return _adj(m, actor, owner, Verdict.LEAK, "confirmed",
                f"attacker modified the owner's object via GraphQL {m.field}{warn}",
                leaked={m.mutate_arg: f"{original!r} -> {sentinel!r}"
                        + ("" if restored else " (NOT restored)")})


def _gql_delete(plan: GraphQLWritePlan) -> Adjudication:
    m, read, create, owner, actor = plan.mut, plan.read, plan.create, plan.owner, plan.actor
    if read is None:
        return _adj(m, actor, owner, Verdict.UNKNOWN, "n/a",
                    f"no read query for '{m.object_base}' to verify the delete")
    status, _, body = _send(create.url, create.body(), owner.headers)
    seeded = get_path(body, f"$.data.{create.field}.id") if isinstance(body, dict) else None
    if seeded is None:
        return _adj(m, actor, owner, Verdict.INVALID, "n/a",
                    f"could not seed a throwaway object as '{owner.name}'")

    _send(m.url, m.body(id_value=str(seeded)), actor.headers)  # attacker deletes
    if _read_object(read, str(seeded), owner.headers) is None:
        return _adj(m, actor, owner, Verdict.LEAK, "confirmed",
                    "attacker deleted an object owned by someone else via GraphQL "
                    f"{m.field} (tested on a seeded throwaway)",
                    leaked={"deleted_object": str(seeded)})
    # survived -> clean up our seed
    _send(m.url, m.body(id_value=str(seeded)), owner.headers)
    return _adj(m, actor, owner, Verdict.DENIED, "n/a",
                f"attacker's {m.field} did not remove the object; delete refused")


def _gql_ok(resp: tuple) -> bool:
    """A usable GraphQL success: HTTP 2xx, no top-level errors, and non-null
    data. (GraphQL reports auth/args failures as 200 + errors, so status alone
    isn't enough.)"""
    status, _, body = resp
    if status // 100 != 2 or not isinstance(body, dict):
        return False
    if body.get("errors"):
        return False
    data = body.get("data")
    return isinstance(data, dict) and any(v is not None for v in data.values())
