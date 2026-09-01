"""The benchmark harness must (a) compute precision/recall correctly and
(b) score a perfect 100/100 against the local fixture -- which doubles as a
regression guard on metewise's real accuracy.
"""

from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "benchmark"))

from score import Expectations, key, score  # noqa: E402


class ScorerTest(unittest.TestCase):
    def _exp(self):
        return Expectations(
            name="t",
            should_find={key("GET", "/a/{id}"), key("PUT", "/a/{id}")},
            must_not_flag={key("GET", "/safe/{id}")},
        )

    def test_perfect(self):
        found = {key("GET", "/a/{id}"), key("PUT", "/a/{id}")}
        s = score(found, self._exp())
        self.assertEqual(s.precision, 1.0)
        self.assertEqual(s.recall, 1.0)
        self.assertTrue(s.perfect)

    def test_false_negative_hurts_recall(self):
        found = {key("GET", "/a/{id}")}  # missed the PUT
        s = score(found, self._exp())
        self.assertEqual(s.recall, 0.5)
        self.assertEqual(s.precision, 1.0)
        self.assertIn(key("PUT", "/a/{id}"), s.false_negatives)

    def test_false_positive_hurts_precision(self):
        found = {key("GET", "/a/{id}"), key("PUT", "/a/{id}"), key("GET", "/safe/{id}")}
        s = score(found, self._exp())
        self.assertEqual(s.recall, 1.0)
        self.assertAlmostEqual(s.precision, 2 / 3)
        self.assertIn(key("GET", "/safe/{id}"), s.false_positives)


class FixtureBenchmarkTest(unittest.TestCase):
    def test_fixture_scores_perfect(self):
        import run_fixture
        s, _ = run_fixture.run()
        self.assertTrue(
            s.perfect,
            f"metewise regressed on the fixture benchmark:\n"
            f"  missed: {s.false_negatives}\n  wrongly flagged: {s.false_positives}",
        )
        self.assertEqual(s.recall, 1.0)
        self.assertEqual(s.precision, 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
