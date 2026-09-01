# Benchmark results — OWASP Juice Shop

metewise scored against a **live** [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)
v20.2.0, on 2026-09-01. Juice Shop is a single Node process, so this ran
**natively with `npm start` — no Docker required**.

## Result

| metric | value |
|---|---|
| precision | **100%** |
| recall | **100%** |
| f1 | **100%** |
| true positives | 1 |
| false positives | 0 |
| false negatives | 0 |

metewise flagged `GET /rest/basket/{id}` as a confirmed cross-user leak **in
both directions**, with the victim's basket contents as evidence:

```
LEAK GET /rest/basket/{id}  actor=bob owner=alice
     evidence: $.data.Products[0].description = 'The all-time classic.'   (Apple Juice)
LEAK GET /rest/basket/{id}  actor=alice owner=bob
     evidence: $.data.Products[0].description = 'Monkeys love it the most.' (Banana Juice)
```

This is Juice Shop's canonical "View Basket" IDOR: `retrieveBasket` looks up a
basket by id with only an *is-logged-in* check and no ownership check
([routes/basket.ts](https://github.com/juice-shop/juice-shop/blob/master/routes/basket.ts)).
An anonymous request is correctly reported as **denied** (the endpoint requires
auth), and the public `GET /api/Products/{id}` is correctly **not flagged** (it's
served to anonymous clients too).

## What this run improved in metewise

Juice Shop basket ids are small integers (`/rest/basket/6`). metewise previously
required integer identifiers to be ≥3 digits (to avoid treating counts/flags as
ids), which would have missed this. The fix: a **bare-integer path segment**
(e.g. `/basket/6`, `/users/42`) is now treated as an object id regardless of
length, while integer *query* values keep the length floor (they're usually
pagination/filter noise). Shipped in v0.8.0.

## Reproduce

```sh
git clone https://github.com/juice-shop/juice-shop && cd juice-shop
npm install
NODE_ENV=unsafe npm start          # http://localhost:3000

# Register two users (POST /api/Users), log each in (POST /rest/user/login) --
# the login response's `authentication.bid` is that user's basket id. Add an item
# to each basket (POST /api/BasketItems) so the leak has identifying content, then
# capture each user viewing GET /rest/basket/{their bid} and score with the
# metewise library (see benchmark/harness.py). The numbers above were produced
# this way against src/ at v0.8.0.
```
