"""Scoring for the evaluation harness.

Implements the metrics from EVALUATION_METHODOLOGY.md section 3:
one-vs-rest TP/TN/FP/FN per (tool, variant, CWE) cell, per-cell
precision/recall/F1, macro-F1 across the 7 CWE classes, and the
robustness drop derived metric.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from src.eval.cwe_map import TARGET_CWES


@dataclass
class PredictionRecord:
    """One detector's verdict on one sample — the unit the harness
    persists (as JSONL) and aggregates from."""

    tool: str
    variant: str
    sample_id: str
    ground_truth: str            # a CWE-* class, or "safe"
    predicted: list[str] = field(default_factory=list)
    raw_output: object = None
    latency_ms: int = 0
    tool_version: str = ""

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, d: dict) -> "PredictionRecord":
        return cls(
            tool=d["tool"],
            variant=d["variant"],
            sample_id=d["sample_id"],
            ground_truth=d["ground_truth"],
            predicted=list(d.get("predicted", [])),
            raw_output=d.get("raw_output"),
            latency_ms=d.get("latency_ms", 0),
            tool_version=d.get("tool_version", ""),
        )


@dataclass
class CellScore:
    """TP/TN/FP/FN and derived metrics for one (tool, variant, CWE) cell."""

    cwe: str
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def support(self) -> int:
        """Number of samples whose ground truth is this CWE."""
        return self.tp + self.fn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def present(self) -> bool:
        """True if this CWE appears at all — as a label or a prediction.
        Absent classes are excluded from the macro average."""
        return (self.tp + self.fn + self.fp) > 0


def confusion(records: list[PredictionRecord], cwe: str) -> CellScore:
    """One-vs-rest confusion counts for a single CWE class."""
    cell = CellScore(cwe=cwe)
    for r in records:
        is_label = r.ground_truth == cwe
        is_pred = cwe in r.predicted
        if is_label and is_pred:
            cell.tp += 1
        elif is_label and not is_pred:
            cell.fn += 1
        elif not is_label and is_pred:
            cell.fp += 1
        else:
            cell.tn += 1
    return cell


@dataclass
class VariantScore:
    """Aggregated score for one (tool, variant) over all 7 CWE cells."""

    tool: str
    variant: str
    per_cwe: dict[str, CellScore]
    n_samples: int

    @property
    def macro_f1(self) -> float:
        """Mean F1 across CWE classes that are present. Equal weight per
        class regardless of sample count (EVALUATION_METHODOLOGY 3.3)."""
        f1s = [c.f1 for c in self.per_cwe.values() if c.present]
        return sum(f1s) / len(f1s) if f1s else 0.0


def score_variant(records: list[PredictionRecord]) -> VariantScore:
    """Aggregate a list of records (assumed one tool, one variant)."""
    tool = records[0].tool if records else ""
    variant = records[0].variant if records else ""
    per_cwe = {cwe: confusion(records, cwe) for cwe in TARGET_CWES}
    return VariantScore(
        tool=tool, variant=variant, per_cwe=per_cwe, n_samples=len(records),
    )


def macro_f1(records: list[PredictionRecord]) -> float:
    """Convenience: macro-F1 for a record list."""
    return score_variant(records).macro_f1


def robustness_drop(
    clean: list[PredictionRecord],
    mutator: list[PredictionRecord],
) -> float:
    """``macro_F1(clean) - macro_F1(mutator)`` for one tool.

    The clean macro-F1 is recomputed over only the sample ids present
    in the mutator variant, so the drop is apples-to-apples and not
    skewed by the ``safe`` hard negatives (which exist only in clean).
    """
    shared = {r.sample_id for r in mutator}
    clean_sub = [r for r in clean if r.sample_id in shared]
    return macro_f1(clean_sub) - macro_f1(mutator)
