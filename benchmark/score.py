"""Score metewise's findings against a target's known ground truth.

An *expectation* file names, for one target, the endpoints that SHOULD be
flagged (real planted vulnerabilities) and the endpoints that must NOT be
(correctly-defended or public). Given the set of endpoints metewise actually
flagged, this computes precision, recall, and F1, and lists every false
positive and false negative by name.

Identity of a finding, for scoring, is the pair (METHOD, template) -- e.g.
("GET", "/invoices/{id}"). That's stable across changing IDs, which is the whole
point of metewise's fingerprints.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


def key(method: str, template: str) -> tuple[str, str]:
    # Normalise the query string off the template; endpoints are compared by
    # method + path shape.
    return (method.upper(), template.split("?")[0])


@dataclass
class Expectations:
    name: str
    should_find: set[tuple[str, str]]
    must_not_flag: set[tuple[str, str]]

    @classmethod
    def load(cls, path: str) -> "Expectations":
        with open(path) as fh:
            d = json.load(fh)
        return cls(
            name=d["name"],
            should_find={key(e["method"], e["template"]) for e in d.get("should_find", [])},
            must_not_flag={key(e["method"], e["template"]) for e in d.get("must_not_flag", [])},
        )


@dataclass
class Score:
    name: str
    true_positives: set = field(default_factory=set)
    false_negatives: set = field(default_factory=set)
    false_positives: set = field(default_factory=set)

    @property
    def precision(self) -> float:
        tp, fp = len(self.true_positives), len(self.false_positives)
        return tp / (tp + fp) if (tp + fp) else 1.0

    @property
    def recall(self) -> float:
        tp, fn = len(self.true_positives), len(self.false_negatives)
        return tp / (tp + fn) if (tp + fn) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def perfect(self) -> bool:
        return not self.false_negatives and not self.false_positives


def score(found: set[tuple[str, str]], exp: Expectations) -> Score:
    """found = the (method, template) pairs metewise flagged as leaks."""
    s = Score(name=exp.name)
    s.true_positives = found & exp.should_find
    s.false_negatives = exp.should_find - found
    # Anything flagged that isn't a known planted vuln is a false positive.
    s.false_positives = found - exp.should_find
    return s


def report(s: Score) -> str:
    lines = [
        f"target: {s.name}",
        f"  precision : {s.precision:6.1%}   ({len(s.true_positives)} true / "
        f"{len(s.false_positives)} false positive)",
        f"  recall    : {s.recall:6.1%}   ({len(s.true_positives)} found / "
        f"{len(s.false_negatives)} missed)",
        f"  f1        : {s.f1:6.1%}",
    ]
    if s.false_negatives:
        lines.append("  MISSED (false negatives):")
        for m, t in sorted(s.false_negatives):
            lines.append(f"    - {m} {t}")
    if s.false_positives:
        lines.append("  WRONGLY FLAGGED (false positives):")
        for m, t in sorted(s.false_positives):
            lines.append(f"    - {m} {t}")
    if s.perfect:
        lines.append("  perfect: every planted bug caught, nothing else flagged")
    return "\n".join(lines)
