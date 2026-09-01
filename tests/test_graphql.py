"""GraphQL BOLA: metewise should catch a vulnerable `invoice(id)` query
(object id in variables *and* inline), leave the defended `safeInvoice` alone,
and never mistake a GraphQL soft-error (HTTP 200 + errors) for a leak.
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

from metewise.graphql import plan_graphql_probes, probe_graphql  # noqa: E402
from metewise.model import Exchange, Principal, Verdict  # noqa: E402

ALICE_INV = "3f1a9c22-0000-4000-8000-000000000001"
BOB_INV = "7b2e5d44-0000-4000-8000-000000000002"

Q_INVOICE = "query($id:ID!){ invoice(id:$id){ id total customer_email owner } }"
Q_SAFE = "query($id:ID!){ safeInvoice(id:$id){ id total owner } }"


def _load_fixture():
    spec = importlib.util.spec_from_file_location(
        "vuln_app", ROOT / "fixtures" / "vuln_app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class GraphQLTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        mod = _load_fixture()
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.gql = f"{cls.base}/graphql"
        cls.principals = {
            "alice": Principal("alice", tenant="acme", headers={"X-User": "alice"}),
            "bob": Principal("bob", tenant="globex", headers={"X-User": "bob"}),
        }

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def _post_ex(self, query, variables, principal):
        # Record a GraphQL call as an Exchange (as har.py would parse it).
        from metewise import http
        st, _, body = http.request(
            "POST", self.gql, self.principals[principal].headers,
            {"query": query, "variables": variables})
        return Exchange(method="POST", url=self.gql, principal=principal,
                        status=st, req_body={"query": query, "variables": variables},
                        resp_body=body)

    def test_variables_bola_caught(self):
        ex = [
            self._post_ex(Q_INVOICE, {"id": ALICE_INV}, "alice"),
            self._post_ex(Q_INVOICE, {"id": BOB_INV}, "bob"),
        ]
        plans = plan_graphql_probes(ex, self.principals)
        leaks = [(p, probe_graphql(p)) for p in plans]
        confirmed = [(p, a) for p, a in leaks if a.verdict is Verdict.LEAK]
        self.assertTrue(confirmed, f"expected a GraphQL leak; got {[a.verdict for _,a in leaks]}")
        # Evidence should carry the victim's real fields.
        _, adj = confirmed[0]
        self.assertEqual(adj.confidence, "confirmed", adj.reason)

    def test_inline_literal_bola_caught(self):
        q = f'{{ invoice(id: "{ALICE_INV}") {{ id total owner }} }}'
        ex = [self._post_ex(q, {}, "alice"),
              # give bob an owned object too so ownership is unambiguous
              self._post_ex(f'{{ invoice(id: "{BOB_INV}") {{ id owner }} }}', {}, "bob")]
        plans = plan_graphql_probes(ex, self.principals)
        self.assertTrue(plans, "inline id should be discovered")
        verdicts = {probe_graphql(p).verdict for p in plans}
        self.assertIn(Verdict.LEAK, verdicts)

    def test_defended_safeInvoice_not_flagged(self):
        ex = [
            self._post_ex(Q_SAFE, {"id": ALICE_INV}, "alice"),
            self._post_ex(Q_SAFE, {"id": BOB_INV}, "bob"),
        ]
        plans = plan_graphql_probes(ex, self.principals)
        for p in plans:
            self.assertNotEqual(probe_graphql(p).verdict, Verdict.LEAK,
                                probe_graphql(p).reason)

    def test_mutation_is_skipped(self):
        mut = 'mutation($id:ID!){ deleteInvoice(id:$id){ id } }'
        ex = [self._post_ex(Q_INVOICE, {"id": ALICE_INV}, "alice")]
        # add a mutation exchange; it must not be planned
        ex.append(Exchange(method="POST", url=self.gql, principal="alice", status=200,
                           req_body={"query": mut, "variables": {"id": ALICE_INV}},
                           resp_body={"data": {"deleteInvoice": {"id": ALICE_INV}}}))
        plans = plan_graphql_probes(ex, self.principals)
        self.assertTrue(all("deleteInvoice" not in p.op.field for p in plans))


if __name__ == "__main__":
    unittest.main(verbosity=2)
