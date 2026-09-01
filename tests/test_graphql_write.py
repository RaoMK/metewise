"""GraphQL write-side BOLA: metewise should catch an attacker MODIFYING
(update mutation) and DELETING (delete mutation) another user's object via
GraphQL, verify the effect through a paired read query, restore/clean up, and
leave defended paths alone.
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
from metewise.graphql import plan_graphql_write_probes, probe_graphql_write  # noqa: E402
from metewise.model import Exchange, Principal, Tier, Verdict  # noqa: E402

AID = "3f1a9c22-0000-4000-8000-000000000001"
BID = "7b2e5d44-0000-4000-8000-000000000002"

Q_READ = "query($id:ID!){ invoice(id:$id){ id customer_email total owner } }"
M_UPDATE = ("mutation($id:ID!,$customer_email:String!)"
            "{ updateInvoice(id:$id, customer_email:$customer_email){ id customer_email } }")
M_DELETE = "mutation($id:ID!){ deleteInvoice(id:$id){ id } }"
M_CREATE = ("mutation($customer_email:String!,$total:Float!)"
            "{ createInvoice(customer_email:$customer_email, total:$total){ id owner } }")


def _load_fixture():
    spec = importlib.util.spec_from_file_location(
        "vuln_app", ROOT / "fixtures" / "vuln_app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class GraphQLWriteTest(unittest.TestCase):
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

    def _ex(self, query, variables, who):
        st, _, body = http.request(self._method(query), self.gql,
                                   self.principals[who].headers,
                                   {"query": query, "variables": variables})
        return Exchange(method="POST", url=self.gql, principal=who, status=st,
                        req_body={"query": query, "variables": variables},
                        resp_body=body)

    @staticmethod
    def _method(q):
        return "POST"

    def _note(self, query, variables, who, resp):
        # Record a mutation's *existence* without executing it (so capturing the
        # delete template doesn't actually delete a real object).
        return Exchange(method="POST", url=self.gql, principal=who, status=200,
                        req_body={"query": query, "variables": variables},
                        resp_body=resp)

    def _capture(self):
        # Each user reads + touches their own invoice; alice shows a create op.
        return [
            self._ex(Q_READ, {"id": AID}, "alice"),
            self._ex(Q_READ, {"id": BID}, "bob"),
            self._ex(M_UPDATE, {"id": AID, "customer_email": "cfo@acme.example"}, "alice"),
            self._note(M_DELETE, {"id": AID}, "alice",
                       {"data": {"deleteInvoice": {"id": AID}}}),   # template only
            self._ex(M_CREATE, {"customer_email": "seed@acme.example", "total": 5.0}, "alice"),
        ]

    def test_update_mutation_leak_caught_and_restored(self):
        plans = plan_graphql_write_probes(self._capture(), self.principals,
                                          allow_destructive=False)
        ups = [p for p in plans if p.tier is Tier.MUTATE
               and p.mut.id_value == AID and p.actor.name == "bob"]
        self.assertTrue(ups, "expected an update-mutation probe by bob on alice's invoice")
        adj = probe_graphql_write(ups[0])
        self.assertEqual(adj.verdict, Verdict.LEAK, adj.reason)
        self.assertEqual(adj.confidence, "confirmed", adj.reason)
        # Restored afterwards.
        _, _, body = http.request("POST", self.gql, {"X-User": "alice"},
                                  {"query": Q_READ, "variables": {"id": AID}})
        self.assertEqual(body["data"]["invoice"]["customer_email"], "cfo@acme.example")

    def test_delete_mutation_off_without_flag(self):
        plans = plan_graphql_write_probes(self._capture(), self.principals,
                                          allow_destructive=False)
        self.assertFalse(any(p.tier is Tier.DESTRUCTIVE for p in plans))

    def test_delete_mutation_leak_on_seeded_throwaway(self):
        plans = plan_graphql_write_probes(self._capture(), self.principals,
                                          allow_destructive=True)
        dels = [p for p in plans if p.tier is Tier.DESTRUCTIVE and p.actor.name == "bob"]
        self.assertTrue(dels, "expected a delete-mutation probe by bob")
        adj = probe_graphql_write(dels[0])
        self.assertEqual(adj.verdict, Verdict.LEAK, adj.reason)
        self.assertIn("deleted_object", adj.leaked_fields)
        # Real invoice untouched (probe used a seeded throwaway).
        _, _, body = http.request("POST", self.gql, {"X-User": "alice"},
                                  {"query": Q_READ, "variables": {"id": AID}})
        self.assertIsNotNone(body["data"]["invoice"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
