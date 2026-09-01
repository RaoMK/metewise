# metewise

A broken-object-authorization (BOLA / IDOR) regression fuzzer.

Not a pentester's magnifying glass — **a regression test**. `metewise` replays
observed API traffic across principals and uses a *four-corner oracle* to
decide, with evidence, whether an object leaked across an ownership boundary.
Findings get stable fingerprints so CI can fail only on *new* leaks.

## Why another BOLA tool

Replaying a request with someone else's cookie is a solved, commodity move
(Autorize, Auth Analyzer, AuthMatrix). What those tools stop short of — and
what `metewise` is built around — is telling a real leak apart from the noise:

| Problem they hit | What `metewise` does |
|---|---|
| Soft-403 (`200 {"error":"forbidden"}`) reads as a bypass | Classifies the probe against a **deny-control**, by response *shape*, not length |
| Legitimately public resources look like leaks | An **anon control** — if an unauthenticated client gets the same object, it's public, not BOLA |
| "Bypassed! (length delta 1420)" isn't actionable | Proves the leak by matching the victim's **actual leaf values** (minus volatile fields), and prints them |
| An expired actor token makes every probe a false *negative* | An owner who can't read their own object → **INVALID run**, exit code 2, never "clean" |
| Findings churn as IDs rotate | Fingerprint over `(template, method, axis)` survives changing UUIDs |

It also tests the axis people forget: **intra-tenant** (same tenant, other
user), not just cross-tenant — that's where the bugs actually are, because the
query is already scoped by `tenant_id` and everyone assumes that's enough.

## The four-corner oracle

For a probe — actor B requesting an object owned by A:

```
                 A's object       B's own object    nonexistent      anon
   as owner A    baseline (x2)        —                 —             —
   as actor B    THE PROBE         allow-control     deny-control   public-ctl
```

The verdict is a *classification* of the probe against those references:

- probe ~ **public-control** (2xx) → public resource, **not** a finding
- probe ~ **deny-control** → access refused → **DENIED**
- probe ~ **baseline** shape *and* shares stable victim leaf values → **LEAK (confirmed)**
- probe ~ object shape but nothing distinctive overlapped → **LEAK (probable)**
- matches nothing within threshold → **UNKNOWN** (handed to a human)

## Try it

```sh
# terminal 1 — a deliberately vulnerable fixture API
python3 fixtures/vuln_app.py 8096

# terminal 2 — ingest a capture and let metewise discover everything itself
PYTHONPATH=src python3 -m metewise.cli \
    scan-har fixtures/capture.har --principals fixtures/principals.json
```

Expected: two CONFIRMED findings on `GET /invoices/{id}` — the BOLA in *both*
directions (bob reads alice's invoice, alice reads bob's) — with the leaked
`customer_email` / `id` / `total` printed. The soft-403 endpoint and the public
resource are discovered too, and correctly *not* flagged. Exit code `3`.

## Two ways in

**`scan-har` — the real workflow.** Capture a short session per user with any
proxy or browser devtools (mitmproxy, Burp, Charles, "Export HAR"), map each
principal to the header that identifies it, and metewise does the rest:
attributes every request to a principal, finds the values the API *emitted*,
templates the URLs around them, works out who owns what, and probes every object
across principals.

```sh
metewise scan-har capture.har --principals principals.json
```

```json
// principals.json — the header(s) that identify each user
{
  "alice": {"tenant": "acme",   "headers": {"X-User": "alice"}},
  "bob":   {"tenant": "globex", "headers": {"Authorization": "Bearer b-tok"}}
}
```

**`scan` — explicit scenario.** For narrow, hand-aimed checks: spell out the
target, principals, and objects yourself.

```sh
metewise scan fixtures/scenario.json
```

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The suite stands up the fixture app and asserts all four behaviours: the real
BOLA is confirmed *with evidence*, the soft-403 is a denial, the public resource
isn't flagged, and a dead owner token yields INVALID (not clean).

## Exit codes

| code | meaning |
|---|---|
| 0 | clean — no leaks |
| 1 | usage / config error |
| 2 | run INVALID — could not be trusted |
| 3 | leaks found |

## Scope of v1

REST + JSON only. No GraphQL/gRPC, no SSO/OIDC flows (bring your own tokens in
`headers`), no property-level (BOPLA) checks yet. Where an endpoint carries no
identifier in the request, metewise reports *no testable identifier* rather than
counting it clean.

## Roadmap

- [x] **Ingest**: derive probes from a HAR / mitmproxy capture — principal
  attribution, templating, and object-reference discovery with ownership.
- [ ] **Object graph**: observed producer→consumer edges so endpoints that need
  a freshly created object get one seeded first.
- [ ] **Write-side BOLA**: PUT/PATCH/DELETE probes with snapshot/restore and an
  opt-in destructive tier.
- [ ] **Validation harness**: precision/recall against crAPI, VAmPI, Juice Shop,
  DVGA — published numbers.

## Safety

Point `metewise` only at systems you own or are authorised to test. The roadmap's
write-side probing is destructive by nature and stays behind an explicit flag.
