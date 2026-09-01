"""Login recipes: metewise should acquire an auth token from credentials, use
it to probe, and re-authenticate mid-run when a token has expired (so a dead
token yields a real finding, not a false 'all clear').
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

from metewise import auth  # noqa: E402
from metewise.engine import probe_object  # noqa: E402
from metewise.model import ObjectRef, Principal, Verdict  # noqa: E402

ALICE_INV = "3f1a9c22-0000-4000-8000-000000000001"


def _load_fixture():
    spec = importlib.util.spec_from_file_location(
        "vuln_app", ROOT / "fixtures" / "vuln_app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class AuthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        mod = _load_fixture()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def _login(self, name):
        return {
            "url": f"{self.base}/login", "method": "POST",
            "body": {"username": name, "password": f"pw-{name}"},
            "token_path": "$.auth_token",
            "header": "Authorization", "format": "Bearer {token}",
        }

    def test_acquire_headers(self):
        h = auth.acquire_headers(self._login("alice"))
        self.assertEqual(h, {"Authorization": "Bearer tok-alice"})

    def test_bad_credentials_raise(self):
        bad = self._login("alice")
        bad["body"]["password"] = "wrong"
        with self.assertRaises(auth.LoginError):
            auth.acquire_headers(bad)

    def test_probe_with_login_acquired_headers(self):
        alice = Principal("alice", tenant="acme",
                          headers=auth.acquire_headers(self._login("alice")))
        bob = Principal("bob", tenant="globex",
                        headers=auth.acquire_headers(self._login("bob")))
        ref = ObjectRef(ALICE_INV, "uuid", "alice", "acme")
        adj = probe_object(self.base, "/invoices/{id}", ref, actor=bob, owner=alice)
        self.assertEqual(adj.verdict, Verdict.LEAK, adj.reason)

    def test_reauth_recovers_from_expired_owner_token(self):
        # Owner starts with a dead token but carries a login recipe. Without
        # re-auth this would read as INVALID (a false 'all clear'); with it,
        # metewise refreshes and still catches the leak.
        alice = Principal("alice", tenant="acme",
                          headers={"Authorization": "Bearer tok-EXPIRED"},
                          login=self._login("alice"))
        bob = Principal("bob", tenant="globex",
                        headers=auth.acquire_headers(self._login("bob")))
        ref = ObjectRef(ALICE_INV, "uuid", "alice", "acme")
        adj = probe_object(self.base, "/invoices/{id}", ref, actor=bob, owner=alice)
        self.assertEqual(adj.verdict, Verdict.LEAK, adj.reason)

    def test_reauth_absent_still_invalid(self):
        # A dead token with NO recipe must still be reported INVALID, not clean.
        alice = Principal("alice", tenant="acme",
                          headers={"Authorization": "Bearer tok-EXPIRED"})
        bob = Principal("bob", tenant="globex",
                        headers=auth.acquire_headers(self._login("bob")))
        ref = ObjectRef(ALICE_INV, "uuid", "alice", "acme")
        adj = probe_object(self.base, "/invoices/{id}", ref, actor=bob, owner=alice)
        self.assertEqual(adj.verdict, Verdict.INVALID, adj.reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
