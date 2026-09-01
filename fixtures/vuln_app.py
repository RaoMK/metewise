"""A deliberately-mixed fixture API for testing metewise's oracle.

Three invoice endpoints exercising the cases the oracle must get right:

  GET /invoices/{id}        VULNERABLE: no ownership check -> real BOLA
  GET /safe-invoices/{id}   DEFENDED with a soft-403: returns 200 + an error
                            body, the classic false-positive trap
  GET /shared/{id}          legitimately public: same shape for everyone,
                            must NOT be flagged

Auth is a toy: header "X-User: <name>" identifies the principal. Two users in
two tenants, each owning one invoice.

Run standalone:  python fixtures/vuln_app.py 8099
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# name -> tenant
USERS = {"alice": "acme", "bob": "globex"}

INVOICES = {
    "3f1a9c22-0000-4000-8000-000000000001": {
        "id": "3f1a9c22-0000-4000-8000-000000000001",
        "owner": "alice", "tenant": "acme",
        "total": 4820.00, "customer_email": "cfo@acme.example",
    },
    "7b2e5d44-0000-4000-8000-000000000002": {
        "id": "7b2e5d44-0000-4000-8000-000000000002",
        "owner": "bob", "tenant": "globex",
        "total": 1290.50, "customer_email": "ap@globex.example",
    },
}

SHARED = {
    "pubdoc-terms-v3": {"id": "pubdoc-terms-v3", "title": "Terms of Service", "version": 3},
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep test output quiet
        pass

    def _json(self, status: int, body: object) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        user = self.headers.get("X-User")
        path = self.path.split("?")[0].strip("/").split("/")

        if len(path) == 2 and path[0] == "invoices":
            # VULNERABLE: requires a logged-in user, but never checks that the
            # user owns the invoice. Classic BOLA between authenticated users.
            if user is None or user not in USERS:
                return self._json(401, {"error": "unauthenticated"})
            inv = INVOICES.get(path[1])
            if inv is None:
                return self._json(404, {"error": "not found"})
            return self._json(200, inv)

        if len(path) == 2 and path[0] == "safe-invoices":
            inv = INVOICES.get(path[1])
            if inv is None:
                return self._json(404, {"error": "not found"})
            if user is None or inv["owner"] != user:
                # SOFT-403: refuses, but with a 200 status. The trap.
                return self._json(200, {"error": "forbidden", "code": "OWNER_MISMATCH"})
            return self._json(200, inv)

        if len(path) == 2 and path[0] == "shared":
            doc = SHARED.get(path[1])
            if doc is None:
                return self._json(404, {"error": "not found"})
            return self._json(200, doc)  # same for everyone, by design

        return self._json(404, {"error": "not found"})


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"fixture app on http://127.0.0.1:{port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
