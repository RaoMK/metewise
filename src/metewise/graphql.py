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
from .shape import classify_value, leaf_values, looks_identifier

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
