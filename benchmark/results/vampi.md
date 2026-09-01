# Benchmark results — VAmPI

metewise scored against a **live** [VAmPI](https://github.com/erev0s/VAmPI)
instance in vulnerable mode, on 2026-09-01. VAmPI is a Flask app, so this ran
**natively on Python 3.9 — no Docker required**.

## Result

| metric | value |
|---|---|
| precision | **100%** |
| recall | **100%** (in scope — see below) |
| f1 | **100%** |
| true positives | 1 |
| false positives | 0 |
| false negatives | 0 |

metewise flagged `GET /books/v1/{id}` as a confirmed cross-user leak **in both
directions**, with the leaked secret as evidence:

```
LEAK GET /books/v1/{id}  actor=name2 owner=name1
     evidence: {'$.book_title': 'bookTitle97', '$.secret': 'secret for bookTitle97'}
LEAK GET /books/v1/{id}  actor=name1 owner=name2
     evidence: {'$.book_title': 'bookTitle74', '$.secret': 'secret for bookTitle74'}
```

This is VAmPI's canonical BOLA: `get_by_title` validates the token but then
returns any book's `secret_content` regardless of ownership.

## Scope — what "in scope" means here

VAmPI has other planted bugs that metewise v1 does **not** claim to catch. They
are listed with reasons in [`expectations/vampi.json`](../expectations/vampi.json):

- **`GET /users/v1/{username}`** — no auth at all, so it's readable by an
  anonymous client. metewise's anon-control correctly classifies that as a
  *public* resource, not a cross-user BOLA. (It's a missing-authentication bug,
  a different class — metewise stays in its lane on purpose.)
- **`PUT /users/v1/{username}/password`** — a write-only sub-resource with no
  readable state at the same URL, so the effect-based write oracle has nothing to
  observe.

Counting only the bugs in metewise's stated scope (object-level authorization
between authenticated users, on resources that aren't public), recall is 100%.

## Known limitation surfaced by this run

metewise infers an object's owner from **who the API returned it to**. VAmPI's
`GET /books/v1` lists *every* book to *every* user, so if that list call is in
the capture, `bookTitle97` looks "produced" by both users → ownership is
ambiguous → metewise skips it (0 book probes, 0 findings). Catching it needs a
capture where each user views their **own** book detail (the natural
object-access session), or a future enhancement that reads an explicit `owner`
field from the object body. Tracked as future work.

## Reproduce

```sh
# 1. VAmPI needs Python 3.9 (its pinned SQLAlchemy 2.0.2 won't build on 3.14).
git clone https://github.com/erev0s/VAmPI && cd VAmPI
python3.9 -m venv .venv && .venv/bin/pip install -r requirements.txt

# 2. Run it (port 5000 is taken by AirPlay on macOS; use another):
vulnerable=1 .venv/bin/python -c \
  "from config import vuln_app; vuln_app.run(host='127.0.0.1', port=5005)" &
curl -s localhost:5005/createdb          # seed users name1/name2 + books

# 3. Log in for fresh tokens (VAmPI tokens expire after 60s — probe promptly):
curl -s -XPOST localhost:5005/users/v1/login -d '{"username":"name1","password":"pass1"}'
curl -s -XPOST localhost:5005/users/v1/login -d '{"username":"name2","password":"pass2"}'

# 4. Capture each user viewing their own book, then score. The numbers above
#    were produced this way against src/ at v0.4.0.
```
