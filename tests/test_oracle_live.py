"""End-to-end: run the oracle against the live fixture app and assert it
gets all three cases right -- the real bug, the soft-403 trap, and the
legitimately public resource.

Dependency-free: uses stdlib unittest and threads the fixture server.
Run:  python -m unittest discover -s tests   (from the metewise/ dir)
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

from metewise.engine import probe_object, to_finding  # noqa: E402
from metewise.model import ObjectRef, Principal, Verdict  # noqa: E402


def _load_fixture():
    spec = importlib.util.spec_from_file_location(
        "vuln_app", ROOT / "fixtures" / "vuln_app.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class OracleLiveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        mod = _load_fixture()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.alice = Principal("alice", tenant="acme", headers={"X-User": "alice"})
        cls.bob = Principal("bob", tenant="globex", headers={"X-User": "bob"})
        cls.alice_invoice = ObjectRef(
            "3f1a9c22-0000-4000-8000-000000000001", "uuid", "alice", "acme"
        )
        cls.shared_doc = ObjectRef("pubdoc-terms-v3", "slug", "alice", "acme")

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_real_bola_is_confirmed_with_evidence(self):
        adj = probe_object(
            self.base, "/invoices/{id}", self.alice_invoice,
            actor=self.bob, owner=self.alice,
        )
        self.assertEqual(adj.verdict, Verdict.LEAK, adj.reason)
        self.assertEqual(adj.confidence, "confirmed", adj.reason)
        # The evidence must name the victim's actual leaked values.
        self.assertIn("$.customer_email", adj.leaked_fields)
        self.assertEqual(adj.leaked_fields["$.customer_email"], "cfo@acme.example")
        # And it should be labelled the cross-tenant axis.
        f = to_finding(adj, self.alice, self.bob)
        self.assertEqual(f.axis, "cross-tenant")

    def test_soft_403_is_a_denial_not_a_leak(self):
        # /safe-invoices returns 200 + {"error": "forbidden"} to a non-owner.
        adj = probe_object(
            self.base, "/safe-invoices/{id}", self.alice_invoice,
            actor=self.bob, owner=self.alice,
        )
        self.assertEqual(adj.verdict, Verdict.DENIED, adj.reason)

    def test_public_resource_is_not_flagged(self):
        adj = probe_object(
            self.base, "/shared/{id}", self.shared_doc,
            actor=self.bob, owner=self.alice,
        )
        self.assertEqual(adj.verdict, Verdict.DENIED, adj.reason)
        self.assertIn("public", adj.reason.lower())

    def test_expired_owner_token_yields_invalid_not_clean(self):
        dead_owner = Principal("alice", tenant="acme", headers={"X-User": "ghost"})
        adj = probe_object(
            self.base, "/invoices/{id}", self.alice_invoice,
            actor=self.bob, owner=dead_owner,
        )
        self.assertEqual(adj.verdict, Verdict.INVALID, adj.reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
