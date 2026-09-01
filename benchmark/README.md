# metewise benchmark harness

Measures how well metewise actually works: run it against a target with **known**
vulnerabilities, compare what it flags to the ground truth, and report
**precision** (of what it flagged, how much was real) and **recall** (of the real
bugs, how many it caught).

## How scoring works

Each target has an *expectations* file (`expectations/<target>.json`) listing:

- `should_find` — the endpoints that really are vulnerable (planted bugs)
- `must_not_flag` — endpoints that are correctly defended or public

A finding is identified by `(METHOD, template)` — e.g. `("GET", "/invoices/{id}")`
— which is stable across changing IDs. Then:

- **true positive** — a `should_find` endpoint that metewise flagged
- **false negative** — a `should_find` endpoint it missed
- **false positive** — anything it flagged that isn't a known planted bug

`precision = TP / (TP + FP)` · `recall = TP / (TP + FN)` · `F1 = harmonic mean`.

The scorer is [`score.py`](score.py); the runners are below.

## Target 1 — the local fixture (no Docker) ✅

Scores metewise against [`fixtures/vuln_app.py`](../fixtures/vuln_app.py), which
has three planted BOLAs (read/update/delete on `/invoices`) and four
correctly-handled endpoints (a soft-403, a public resource, and two properly
defended writes).

```sh
python3 benchmark/run_fixture.py
```

**Current result** (see [`results/fixture.md`](results/fixture.md)):

| metric | value |
|---|---|
| precision | **100%** |
| recall | **100%** |
| f1 | **100%** |

3/3 planted bugs caught (GET, PUT, DELETE on `/invoices/{id}`); 0 false
positives — the soft-403, the public resource, and both defended writes were
correctly left alone. This runs in CI, so a regression that adds a false
positive or misses a bug fails the build.

## Target 2+ — Dockerised vulnerable apps (VAmPI, crAPI)

The same scorer runs against any live target from a captured HAR — the script
needs no Docker, only the target reachable and a capture.

```sh
# 1. bring the target up
docker compose -f benchmark/docker/docker-compose.vampi.yml up -d

# 2. capture a short session per user against it (browser devtools / mitmproxy),
#    save captures/vampi.har and a captures/vampi.principals.json

# 3. score
python3 benchmark/run_target.py \
    --har captures/vampi.har \
    --principals captures/vampi.principals.json \
    --expectations benchmark/expectations/vampi.json

# 4. tear down
docker compose -f benchmark/docker/docker-compose.vampi.yml down
```

For **crAPI**, use the project's own compose from
`github.com/OWASP/crAPI` (it ships a multi-service stack), point captures at
`http://localhost:8888`, and write `expectations/crapi.json` the same way.

> **Status:** the VAmPI/crAPI expectation files are **templates**, not verified
> numbers — the build machine has no Docker, so only the fixture numbers above
> are real. Fill the templates in from an actual capture before quoting any
> VAmPI/crAPI precision/recall. Never publish a number the harness didn't
> produce.

## Adding a target

1. Bring it up and capture a two-user HAR.
2. Write `expectations/<name>.json` (`should_find` / `must_not_flag`).
3. `python3 benchmark/run_target.py --har … --principals … --expectations …`.
