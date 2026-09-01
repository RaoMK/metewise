# Running the crAPI benchmark

[crAPI](https://github.com/OWASP/crAPI) (OWASP's "Completely Ridiculous API") is
a realistic multi-service vulnerable app with several genuine BOLAs. It ships its
own Docker compose stack, so we don't vendor one here — use theirs.

## Steps

```sh
# 1. Bring crAPI up (from a checkout of OWASP/crAPI)
curl -o docker-compose.yml \
  https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml
docker compose pull && docker compose up -d
# crAPI's web UI comes up on http://localhost:8888

# 2. Register two users in the UI, log each in, and capture a short session per
#    user as a HAR (browser devtools -> Network -> Save all as HAR).
#    crAPI uses a Bearer JWT — grab it from any request's Authorization header,
#    or script the login and use a metewise login recipe (see the main README).

# 3. Fill in benchmark/expectations/crapi.json with the real endpoint templates
#    (the placeholders there are unverified guesses), then score:
python3 benchmark/run_target.py \
    --har captures/crapi.alice.har captures/crapi.bob.har \
    --principals captures/crapi.principals.json \
    --expectations benchmark/expectations/crapi.json \
    --no-destructive

# 4. Tear down
docker compose down
```

## Candidate BOLAs to expect (verify against your capture)

- **`GET /identity/api/v2/vehicle/{vehicleId}/location`** — view another user's
  vehicle location.
- **Shop orders / mechanic reports** — accessing another user's order or report
  by id.

Confirm the exact paths from your own capture before trusting any numbers, and
record the verified result in `benchmark/results/crapi.md` — never publish a
number the harness didn't produce.
