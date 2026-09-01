"""A deliberately-mixed fixture API for testing metewise's oracle.

Read endpoints:

  GET    /invoices/{id}        VULNERABLE: no ownership check -> real BOLA
  GET    /safe-invoices/{id}   DEFENDED with a soft-403: 200 + an error body,
                               the classic false-positive trap
  GET    /shared/{id}          legitimately public: same for everyone

Write endpoints (for write-side BOLA testing):

  POST   /invoices             create; used by metewise to *seed* throwaway
                               objects so destructive probes never touch real data
  PUT    /invoices/{id}        VULNERABLE: updates without an ownership check
  DELETE /invoices/{id}        VULNERABLE: deletes without an ownership check
  PUT    /safe-invoices/{id}   DEFENDED: 403 unless caller owns it
  DELETE /safe-invoices/{id}   DEFENDED: 403 unless caller owns it
  POST   /invoices/{id}/pay    SIDE-EFFECTING: metewise must NEVER probe this

Auth is a toy: header "X-User: <name>" identifies the principal.

Run standalone:  python fixtures/vuln_app.py 8099
"""

from __future__ import annotations

import json
import re
import sys
import uuid
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

    # -- helpers ----------------------------------------------------------
    def _json(self, status: int, body: object) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode() or "{}")
        except json.JSONDecodeError:
            return {}

    def _parts(self) -> list[str]:
        return self.path.split("?")[0].strip("/").split("/")

    def _user(self) -> str | None:
        """Identify the caller by X-User, or by a `Bearer tok-<name>` token
        (so login recipes can be exercised end to end)."""
        u = self.headers.get("X-User")
        if u:
            return u
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer tok-"):
            name = auth[len("Bearer tok-"):]
            if name in USERS:
                return name
        return None

    # -- reads ------------------------------------------------------------
    def do_GET(self) -> None:
        user = self._user()
        path = self._parts()

        if len(path) == 2 and path[0] == "invoices":
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
                return self._json(200, {"error": "forbidden", "code": "OWNER_MISMATCH"})
            return self._json(200, inv)

        if len(path) == 2 and path[0] == "shared":
            doc = SHARED.get(path[1])
            if doc is None:
                return self._json(404, {"error": "not found"})
            return self._json(200, doc)

        return self._json(404, {"error": "not found"})

    # -- create (seed source) --------------------------------------------
    def do_POST(self) -> None:
        user = self._user()
        path = self._parts()

        # LOGIN: exchange credentials for a token, to exercise login recipes.
        if len(path) == 1 and path[0] == "login":
            body = self._read_body()
            name = body.get("username")
            if name in USERS and body.get("password") == f"pw-{name}":
                return self._json(200, {"auth_token": f"tok-{name}"})
            return self._json(401, {"error": "bad credentials"})

        # GraphQL: a single endpoint. `invoice` is VULNERABLE (no ownership
        # check); `safeInvoice` is DEFENDED (null to non-owners). GraphQL reports
        # failures as HTTP 200 + an `errors` array -- the soft-error trap.
        if len(path) == 1 and path[0] == "graphql":
            body = self._read_body()
            q = body.get("query", "")
            gvars = body.get("variables") or {}
            if user is None:
                return self._json(200, {"data": None,
                                        "errors": [{"message": "unauthenticated"}]})
            inv_id = gvars.get("id")
            if inv_id is None:
                m = re.search(r'id:\s*"([^"]+)"', q)
                inv_id = m.group(1) if m else None

            # -- mutations (write-side) --
            if "createInvoice" in q:
                nid = str(uuid.uuid4())
                INVOICES[nid] = {
                    "id": nid, "owner": user, "tenant": USERS[user],
                    "total": gvars.get("total", 0.0),
                    "customer_email": gvars.get("customer_email", f"{user}@example"),
                }
                return self._json(200, {"data": {"createInvoice": INVOICES[nid]}})
            if "updateInvoice" in q:  # VULNERABLE: no ownership check
                inv = INVOICES.get(inv_id)
                if inv is None:
                    return self._json(200, {"data": {"updateInvoice": None}})
                for k in ("customer_email", "total"):
                    if k in gvars:
                        inv[k] = gvars[k]
                return self._json(200, {"data": {"updateInvoice": inv}})
            if "deleteInvoice" in q:  # VULNERABLE: no ownership check
                if inv_id in INVOICES:
                    del INVOICES[inv_id]
                    return self._json(200, {"data": {"deleteInvoice": {"id": inv_id}}})
                return self._json(200, {"data": {"deleteInvoice": None}})

            # -- queries (read-side) --
            if "safeInvoice" in q:
                inv = INVOICES.get(inv_id)
                if inv and inv["owner"] == user:
                    return self._json(200, {"data": {"safeInvoice": inv}})
                return self._json(200, {"data": {"safeInvoice": None}})
            if "invoice" in q:
                return self._json(200, {"data": {"invoice": INVOICES.get(inv_id)}})
            return self._json(200, {"data": None,
                                    "errors": [{"message": "unknown field"}]})

        # SIDE-EFFECTING endpoint: exists so we can prove metewise refuses to
        # probe it. If this ever runs during a scan, something is wrong.
        if len(path) == 3 and path[0] == "invoices" and path[2] == "pay":
            return self._json(200, {"charged": True, "id": path[1]})

        if len(path) == 1 and path[0] == "invoices":
            if user is None or user not in USERS:
                return self._json(401, {"error": "unauthenticated"})
            body = self._read_body()
            new_id = str(uuid.uuid4())
            inv = {
                "id": new_id, "owner": user, "tenant": USERS[user],
                "total": body.get("total", 0.0),
                "customer_email": body.get("customer_email", f"{user}@example"),
            }
            INVOICES[new_id] = inv
            return self._json(201, inv)

        return self._json(404, {"error": "not found"})

    # -- update -----------------------------------------------------------
    def do_PUT(self) -> None:
        user = self._user()
        path = self._parts()

        if len(path) == 2 and path[0] == "invoices":
            # VULNERABLE: updates without checking ownership.
            if user is None or user not in USERS:
                return self._json(401, {"error": "unauthenticated"})
            inv = INVOICES.get(path[1])
            if inv is None:
                return self._json(404, {"error": "not found"})
            inv.update({k: v for k, v in self._read_body().items()
                        if k not in ("id", "owner", "tenant")})
            return self._json(200, inv)

        if len(path) == 2 and path[0] == "safe-invoices":
            inv = INVOICES.get(path[1])
            if inv is None:
                return self._json(404, {"error": "not found"})
            if user is None or inv["owner"] != user:
                return self._json(403, {"error": "forbidden"})
            inv.update({k: v for k, v in self._read_body().items()
                        if k not in ("id", "owner", "tenant")})
            return self._json(200, inv)

        return self._json(404, {"error": "not found"})

    # -- delete -----------------------------------------------------------
    def do_DELETE(self) -> None:
        user = self._user()
        path = self._parts()

        if len(path) == 2 and path[0] == "invoices":
            # VULNERABLE: deletes without checking ownership.
            if user is None or user not in USERS:
                return self._json(401, {"error": "unauthenticated"})
            if path[1] not in INVOICES:
                return self._json(404, {"error": "not found"})
            del INVOICES[path[1]]
            return self._empty(204)

        if len(path) == 2 and path[0] == "safe-invoices":
            inv = INVOICES.get(path[1])
            if inv is None:
                return self._json(404, {"error": "not found"})
            if user is None or inv["owner"] != user:
                return self._json(403, {"error": "forbidden"})
            del INVOICES[path[1]]
            return self._empty(204)

        return self._json(404, {"error": "not found"})


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"fixture app on http://127.0.0.1:{port}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
