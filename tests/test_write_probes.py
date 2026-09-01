"""Write-side BOLA: metewise should catch an attacker MODIFYING (PUT) and
DELETING another user's object, restore/clean up after itself, refuse the
defended endpoints, and never touch a side-effecting endpoint.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from metewise import http  # noqa: E402
from metewise.discover import collect_create_recipes, plan_write_probes  # noqa: E402
from metewise.model import Principal, Tier, Verdict  # noqa: E402
from metewise.writeprobe import probe_write  # noqa: E402

ALICE_INV = "3f1a9c22-0000-4000-8000-000000000001"
BOB_INV = "7b2e5d44-0000-4000-8000-000000000002"


def _load_fixture():
    spec = importlib.util.spec_from_file_location(
        "vuln_app", ROOT / "fixtures" / "vuln_app.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ex(method, url, principal, status, req_body=None, resp_body=None):
    from metewise.model import Exchange
    return Exchange(method=method, url=url, principal=principal, status=status,
                    req_body=req_body, resp_body=resp_body)


class WriteProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        mod = _load_fixture()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.mod = mod
        cls.principals = {
            "alice": Principal("alice", tenant="acme", headers={"X-User": "alice"}),
            "bob": Principal("bob", tenant="globex", headers={"X-User": "bob"}),
        }
        b = cls.base
        # A capture: each user reads their own invoice; alice creates one (so a
        # create recipe is learned); PUT/DELETE/pay templates are established.
        cls.exchanges = [
            _ex("GET", f"{b}/invoices/{ALICE_INV}", "alice", 200,
                resp_body={"id": ALICE_INV, "owner": "alice", "tenant": "acme",
                           "total": 4820.0, "customer_email": "cfo@acme.example"}),
            _ex("GET", f"{b}/invoices/{BOB_INV}", "bob", 200,
                resp_body={"id": BOB_INV, "owner": "bob", "tenant": "globex",
                           "total": 1290.5, "customer_email": "ap@globex.example"}),
            _ex("POST", f"{b}/invoices", "alice", 201,
                req_body={"total": 10.0, "customer_email": "seed@acme.example"},
                resp_body={"id": "seed-xxxx", "owner": "alice", "total": 10.0}),
            _ex("PUT", f"{b}/invoices/{ALICE_INV}", "alice", 200,
                req_body={"total": 4820.0}, resp_body={"id": ALICE_INV}),
            _ex("DELETE", f"{b}/invoices/{ALICE_INV}", "alice", 204),
            # side-effecting endpoint that must never be probed
            _ex("PUT", f"{b}/invoices/{ALICE_INV}/pay", "alice", 200,
                resp_body={"charged": True}),
            # defended endpoints
            _ex("PUT", f"{b}/safe-invoices/{ALICE_INV}", "alice", 200,
                resp_body={"id": ALICE_INV}),
            _ex("DELETE", f"{b}/safe-invoices/{ALICE_INV}", "alice", 204),
        ]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_create_recipe_learned(self):
        recipes = collect_create_recipes(self.exchanges)
        self.assertIn("/invoices", recipes)
        self.assertEqual(recipes["/invoices"].method, "POST")

    def test_forbidden_endpoint_never_planned(self):
        plans = plan_write_probes(self.exchanges, self.principals,
                                  allow_destructive=True)
        self.assertFalse(any("pay" in p.template for p in plans),
                         "side-effecting /pay endpoint must never be probed")

    def test_destructive_off_by_default(self):
        plans = plan_write_probes(self.exchanges, self.principals,
                                  allow_destructive=False)
        self.assertFalse(any(p.tier is Tier.DESTRUCTIVE for p in plans),
                         "DELETE must not be planned without allow_destructive")

    def test_mutate_leak_is_caught_and_restored(self):
        plans = plan_write_probes(self.exchanges, self.principals,
                                  allow_destructive=False)
        muts = [p for p in plans if p.tier is Tier.MUTATE
                and p.template.endswith("/invoices/{id}")
                and p.ref.value == ALICE_INV and p.actor.name == "bob"]
        self.assertTrue(muts, "expected a PUT probe by bob on alice's invoice")
        adj = probe_write(muts[0])
        self.assertEqual(adj.verdict, Verdict.LEAK, adj.reason)
        self.assertEqual(adj.confidence, "confirmed", adj.reason)
        # And the object must be back to its original value afterwards.
        _, _, body = http.request(
            "GET", f"{self.base}/invoices/{ALICE_INV}", {"X-User": "alice"})
        self.assertEqual(body["customer_email"], "cfo@acme.example",
                         "metewise must restore the field it mutated")

    def test_defended_mutate_is_denied(self):
        plans = plan_write_probes(self.exchanges, self.principals,
                                  allow_destructive=False)
        safe = [p for p in plans if p.template.endswith("/safe-invoices/{id}")
                and p.actor.name == "bob"]
        self.assertTrue(safe)
        for p in safe:
            adj = probe_write(p)
            self.assertNotEqual(adj.verdict, Verdict.LEAK, adj.reason)

    def test_destructive_leak_on_seeded_throwaway(self):
        plans = plan_write_probes(self.exchanges, self.principals,
                                  allow_destructive=True)
        dels = [p for p in plans if p.tier is Tier.DESTRUCTIVE
                and p.template.endswith("/invoices/{id}") and p.actor.name == "bob"]
        self.assertTrue(dels, "expected a DELETE probe by bob")
        adj = probe_write(dels[0])
        self.assertEqual(adj.verdict, Verdict.LEAK, adj.reason)
        self.assertIn("deleted_object", adj.leaked_fields)
        # Real invoices must be untouched -- the probe used a seeded throwaway.
        st, _, _ = http.request(
            "GET", f"{self.base}/invoices/{ALICE_INV}", {"X-User": "alice"})
        self.assertEqual(st, 200, "destructive probe must not touch real objects")


if __name__ == "__main__":
    unittest.main(verbosity=2)
