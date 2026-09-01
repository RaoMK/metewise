"""End-to-end ingest: capture a HAR from the fixture, then let metewise
discover the object references and their owners on its own -- no hand-written
scenario -- and confirm it finds the real BOLA while ignoring the traps.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from metewise import http  # noqa: E402
from metewise.discover import collect_identifiers, plan_probes, templatize  # noqa: E402
from metewise.engine import probe_object  # noqa: E402
from metewise.har import parse  # noqa: E402
from metewise.model import Principal, Verdict  # noqa: E402

ALICE_INV = "3f1a9c22-0000-4000-8000-000000000001"
BOB_INV = "7b2e5d44-0000-4000-8000-000000000002"


def _load_fixture():
    spec = importlib.util.spec_from_file_location(
        "vuln_app", ROOT / "fixtures" / "vuln_app.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _har_entry(base, method, path, headers):
    """Make a real request and record it as a HAR entry."""
    url = base + path
    status, resp_headers, body = http.request(method, url, headers)
    return {
        "request": {
            "method": method, "url": url,
            "headers": [{"name": k, "value": v} for k, v in headers.items()],
        },
        "response": {
            "status": status,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": json.dumps(body)},
        },
    }


class HarDiscoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        mod = _load_fixture()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
        cls.port = cls.srv.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

        cls.principals = {
            "alice": Principal("alice", tenant="acme", headers={"X-User": "alice"}),
            "bob": Principal("bob", tenant="globex", headers={"X-User": "bob"}),
        }
        a = {"X-User": "alice"}
        b = {"X-User": "bob"}
        # A short captured session: each user touches their own objects.
        entries = [
            _har_entry(cls.base, "GET", f"/invoices/{ALICE_INV}", a),
            _har_entry(cls.base, "GET", f"/safe-invoices/{ALICE_INV}", a),
            _har_entry(cls.base, "GET", "/shared/pubdoc-terms-v3", a),
            _har_entry(cls.base, "GET", f"/invoices/{BOB_INV}", b),
        ]
        cls.har = {"log": {"entries": entries}}
        cls.exchanges = parse(cls.har, cls.principals)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_attribution(self):
        by_url = {e.url.rsplit("/", 1)[-1]: e.principal for e in self.exchanges}
        self.assertEqual(by_url[ALICE_INV], "alice")
        self.assertEqual(by_url[BOB_INV], "bob")

    def test_identifiers_get_owners(self):
        ids = collect_identifiers(self.exchanges)
        self.assertIn(ALICE_INV, ids)
        self.assertEqual(ids[ALICE_INV]["producers"], {"alice"})
        self.assertEqual(ids[BOB_INV]["producers"], {"bob"})

    def test_templating_isolates_the_id(self):
        ids = collect_identifiers(self.exchanges)
        tmpls = templatize(f"{self.base}/invoices/{ALICE_INV}", ids)
        self.assertEqual(len(tmpls), 1)
        template, value, kind = tmpls[0]
        self.assertTrue(template.endswith("/invoices/{id}"))
        self.assertEqual(value, ALICE_INV)
        self.assertEqual(kind, "uuid")

    def test_plans_cross_principals_only(self):
        plans = plan_probes(self.exchanges, self.principals)
        # alice's invoice must be probed by bob (and anon), never by alice.
        inv_plans = [
            p for p in plans
            if p.template.endswith("/invoices/{id}") and p.ref.value == ALICE_INV
        ]
        actors = {p.actor.name for p in inv_plans}
        self.assertIn("bob", actors)
        self.assertNotIn("alice", actors)

    def test_end_to_end_finds_bola_and_ignores_traps(self):
        plans = plan_probes(self.exchanges, self.principals)
        verdicts = {}  # template -> set of verdicts seen
        for p in plans:
            adj = probe_object(
                p.base_url, p.template, p.ref, actor=p.actor,
                owner=p.owner, method=p.method,
            )
            verdicts.setdefault(p.template.split("://")[-1].split("/", 1)[-1], set()).add(
                (adj.verdict, adj.confidence)
            )

        def for_endpoint(name):
            return {k: v for k, v in verdicts.items() if name in k}

        inv = for_endpoint("invoices/{id}")
        # /invoices leaks; /safe-invoices does not (both contain "invoices").
        real = {k: v for k, v in inv.items() if not k.startswith("safe")}
        safe = {k: v for k, v in inv.items() if k.startswith("safe")}

        self.assertTrue(
            any((Verdict.LEAK, "confirmed") in v for v in real.values()),
            f"expected a confirmed leak on /invoices, got {real}",
        )
        for v in safe.values():
            self.assertNotIn(Verdict.LEAK, {vd for vd, _ in v},
                             "soft-403 endpoint must not leak")
        for k, v in for_endpoint("shared/{id}").items():
            self.assertNotIn(Verdict.LEAK, {vd for vd, _ in v},
                             "public resource must not leak")


if __name__ == "__main__":
    unittest.main(verbosity=2)
