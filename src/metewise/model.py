"""Core data types for metewise.

The whole tool is a pipeline that moves these records from left to right:

    Exchange (observed) -> ObjectRef (extracted) -> Probe (planned)
        -> Adjudication (four-corner verdict) -> Finding (reported)

Everything is a plain dataclass so each stage can be dumped to / loaded from
JSONL. That is what lets the oracle be re-run over a recorded corpus without
ever touching the target app.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any


class Verdict(enum.Enum):
    """Outcome of adjudicating one probe against the four-corner oracle."""

    DENIED = "denied"            # probe looks like the deny-control: access correctly refused
    LEAK = "leak"               # probe looks like the baseline: another principal's object came back
    UNKNOWN = "unknown"         # probe matched neither control cleanly; needs a human
    INVALID = "invalid"         # the run itself is untrustworthy (e.g. actor token expired)

    @property
    def is_finding(self) -> bool:
        return self is Verdict.LEAK


class Tier(enum.IntEnum):
    """Safety tier of an HTTP operation. Higher = more destructive."""

    READ = 0        # GET, HEAD
    MUTATE = 1      # PUT, PATCH on run-created objects, with snapshot/restore
    DESTRUCTIVE = 2  # DELETE and side-effecting POSTs; opt-in only
    FORBIDDEN = 3   # payment / messaging / webhooks; never probed automatically


@dataclass(frozen=True)
class Principal:
    """An identity metewise can act as.

    `tenant` and `role` let us test the two orthogonal axes of BOLA:
    cross-tenant (different tenant) and intra-tenant (same tenant, other user).
    """

    name: str
    tenant: str | None = None
    role: str = "member"
    # Headers merged into every request made as this principal (auth token, etc).
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def is_anon(self) -> bool:
        return not self.headers


@dataclass
class Exchange:
    """One observed request/response pair, the raw material of the whole run."""

    method: str
    url: str                      # full URL as sent
    principal: str                # Principal.name that made this request
    status: int
    req_headers: dict[str, str] = field(default_factory=dict)
    req_body: Any = None          # parsed JSON if any, else raw string
    resp_headers: dict[str, str] = field(default_factory=dict)
    resp_body: Any = None         # parsed JSON if any, else raw string
    # Set during templating: "/invoices/{id}" derived from "/invoices/a3f1".
    template: str | None = None

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, d: dict) -> "Exchange":
        return cls(**d)


@dataclass(frozen=True)
class ObjectRef:
    """A value that flows through the API as a reference to an object.

    Discovered by watching a value appear in one response body and later be
    used as a path/query parameter. `owner` is the principal whose traffic
    first produced it -- the ground truth for "who should be allowed to read
    this".
    """

    value: str
    kind: str                     # uuid | int | slug | opaque
    owner: str                    # Principal.name that produced this value
    tenant: str | None = None


@dataclass
class Probe:
    """A planned cross-principal request: `actor` tries to touch `target_ref`."""

    template: str
    method: str
    actor: str                    # Principal.name performing the probe
    target_ref: ObjectRef        # object owned by someone else
    tier: Tier
    url: str                      # concrete URL with target_ref substituted in


@dataclass
class Adjudication:
    """The oracle's reasoned verdict for one probe, with its evidence."""

    probe: Probe
    verdict: Verdict
    confidence: str               # "confirmed" | "probable" | "n/a"
    reason: str
    leaked_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A stable, reportable result. `fingerprint` survives changing IDs so CI
    can fail only on *new* findings."""

    fingerprint: str
    template: str
    method: str
    actor: str
    owner: str
    axis: str                     # "cross-tenant" | "intra-tenant" | "unauthenticated"
    confidence: str
    leaked_fields: dict[str, Any] = field(default_factory=dict)
