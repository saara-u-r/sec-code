"""Scoring for the evaluation harness.

Implements the metrics from docs/reference/EVALUATION_METHODOLOGY.md sections 3.1–3.4
(macro-F1 baseline) and 3.6 (the three-measure profile that replaces
the macro-F1 headline for the next evaluation round).

Currently implemented from §3.6:
  • Detection MCC (binary vuln-vs-safe)
  • Severity-Weighted Recall (CVSS-weighted binary recall on positives)
  • Hierarchical CWE Macro-Accuracy (Wu-Palmer over the hand-coded
    CWE subtree in :mod:`src.eval.cwe_map`)
  • Weighted Cohen's kappa with Wu-Palmer-derived disagreement weights

Still to add: PR-AUC.
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path

from src.eval.cwe_map import TARGET_CWES, wu_palmer_similarity


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
class BinaryConfusion:
    """Binary vuln-vs-safe collapse of a record list, used by MCC.

    A record is "predicted vulnerable" if its ``predicted`` set is
    non-empty, regardless of which CWE was named. Ground truth is
    "vulnerable" if ``ground_truth != "safe"``.
    """

    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.tn + self.fp + self.fn

    @property
    def has_both_classes(self) -> bool:
        """True when both positive and negative samples are present, so
        MCC is well-defined. Mutator variants in this benchmark carry no
        safe negatives by design — see ``src/eval/samples.py`` — so MCC
        is undefined on them."""
        return (self.tp + self.fn) > 0 and (self.tn + self.fp) > 0

    @property
    def mcc(self) -> float | None:
        """Matthews Correlation Coefficient (Chicco & Jurman, BMC
        Genomics 2020). Returns ``None`` when the formula is undefined
        — when either class is entirely absent or every prediction lies
        in one row of the confusion matrix."""
        if not self.has_both_classes:
            return None
        tp, tn, fp, fn = self.tp, self.tn, self.fp, self.fn
        num = tp * tn - fp * fn
        denom_sq = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
        if denom_sq == 0:
            return None
        return num / math.sqrt(denom_sq)


def binary_confusion(records: list[PredictionRecord]) -> BinaryConfusion:
    """Collapse one-vs-rest predictions onto the binary vuln-vs-safe
    decision used by §3.6 Detection MCC."""
    conf = BinaryConfusion()
    for r in records:
        is_label = r.ground_truth != "safe"
        is_pred = len(r.predicted) > 0
        if is_label and is_pred:
            conf.tp += 1
        elif is_label and not is_pred:
            conf.fn += 1
        elif not is_label and is_pred:
            conf.fp += 1
        else:
            conf.tn += 1
    return conf


@dataclass
class SeverityWeightedRecall:
    """SWR (§3.6): CVSS-weighted recall on positives that carry a CVSS
    score. Samples without a CVSS are excluded from the pool rather
    than assigned a fallback (per the methodology)."""

    detected_cvss_sum: float = 0.0
    total_cvss_sum: float = 0.0
    pool_size: int = 0     # positives counted in the denominator
    excluded: int = 0      # positives skipped for lack of a CVSS score

    @property
    def swr(self) -> float:
        if self.total_cvss_sum <= 0:
            return 0.0
        return self.detected_cvss_sum / self.total_cvss_sum


def severity_weighted_recall(
    records: list[PredictionRecord],
    cvss_scores: dict[str, float],
) -> SeverityWeightedRecall:
    """SWR over a record list with a sample_id → CVSS lookup.

    A positive is "detected" if the tool predicted any CWE (binary
    decision, matching MCC). Samples whose ``cvss_scores`` lookup is
    missing or non-positive are excluded.
    """
    out = SeverityWeightedRecall()
    for r in records:
        if r.ground_truth == "safe":
            continue
        cvss = cvss_scores.get(r.sample_id)
        if cvss is None or cvss <= 0:
            out.excluded += 1
            continue
        out.total_cvss_sum += cvss
        out.pool_size += 1
        if r.predicted:
            out.detected_cvss_sum += cvss
    return out


# ---------------------------------------------------------------------------
# Hierarchical CWE Macro-Accuracy (§3.6)
# ---------------------------------------------------------------------------

def _best_sim(predicted: list[str], truth: str) -> float:
    """Wu-Palmer similarity between ``truth`` and the predicted CWE
    that maximises it. Returns 0.0 if ``predicted`` is empty (the
    detector said "safe" on a vulnerable sample) or contains no CWE
    in the hand-coded subtree.

    Multi-prediction tools (Bandit, Semgrep) can fire several rules
    on one sample; the methodology asks for a single similarity per
    sample, so we take the maximum over the detector's predictions —
    the most charitable read of "how close did the tool get?"
    """
    best = 0.0
    for p in predicted:
        try:
            s = wu_palmer_similarity(p, truth)
        except KeyError:
            continue
        if s > best:
            best = s
    return best


@dataclass
class HCMA:
    """HCMA (§3.6): per-class mean Wu-Palmer similarity between the
    detector's best prediction and the ground-truth CWE, macro-averaged
    across present true classes. Computed over vulnerable samples only.

    A "present" class is one with at least one sample in the records;
    classes with zero samples are excluded from the macro-average, in
    line with how :class:`CellScore.present` works for macro-F1.
    """

    per_class_mean: dict[str, float] = field(default_factory=dict)
    per_class_n: dict[str, int] = field(default_factory=dict)

    @property
    def hcma(self) -> float:
        present = [v for k, v in self.per_class_mean.items()
                   if self.per_class_n.get(k, 0) > 0]
        return sum(present) / len(present) if present else 0.0

    @property
    def n_samples(self) -> int:
        return sum(self.per_class_n.values())


def hierarchical_cwe_macro_accuracy(
    records: list[PredictionRecord],
) -> HCMA:
    """Compute HCMA over a record list.

    For every vulnerable sample (``ground_truth != "safe"``), pick the
    predicted CWE that maximises Wu-Palmer similarity to the truth and
    record that similarity. Average within each true class, then return
    the macro-average across classes that have at least one sample.
    """
    by_class_sum: dict[str, float] = {}
    by_class_n: dict[str, int] = {}
    for r in records:
        if r.ground_truth == "safe":
            continue
        try:
            wu_palmer_similarity(r.ground_truth, r.ground_truth)
        except KeyError:
            # Ground truth is not in the hand-coded subtree; skip
            # rather than poison the per-class average.
            continue
        s = _best_sim(r.predicted, r.ground_truth)
        by_class_sum[r.ground_truth] = by_class_sum.get(r.ground_truth, 0.0) + s
        by_class_n[r.ground_truth] = by_class_n.get(r.ground_truth, 0) + 1
    per_class_mean = {
        cwe: by_class_sum[cwe] / by_class_n[cwe] for cwe in by_class_sum
    }
    return HCMA(per_class_mean=per_class_mean, per_class_n=by_class_n)


# ---------------------------------------------------------------------------
# Weighted Cohen's kappa (§3.6 optional headline)
# ---------------------------------------------------------------------------

#: Label space for the kappa calculation: the seven target CWEs plus
#: ``safe`` as a single rated category. The verdict reduction is
#: ``predicted[0]`` if non-empty, else ``"safe"``. ``predicted`` is
#: kept sorted by the harness (see ``run_eval.py``), so this is
#: deterministic across runs.
_KAPPA_LABELS: tuple[str, ...] = TARGET_CWES + ("safe",)


def _verdict(predicted: list[str]) -> str:
    """Reduce a (possibly multi-CWE) prediction to a single rated label
    in :data:`_KAPPA_LABELS`. Returns the first predicted CWE if any,
    else ``"safe"``. The ``predicted`` list is alphabetically sorted by
    the harness, so this is deterministic."""
    for p in predicted:
        if p in _KAPPA_LABELS:
            return p
    return "safe"


def _kappa_weight(a: str, b: str) -> float:
    """Disagreement weight between two labels in ``_KAPPA_LABELS``.

    * 0 on the diagonal (same label → no penalty).
    * 1 when one side is ``"safe"`` and the other a CWE (full penalty;
      missing a vulnerability or false-alarming on a safe sample are
      categorical errors with no partial credit).
    * ``1 - wu_palmer_similarity(a, b)`` between two CWEs.
    """
    if a == b:
        return 0.0
    if a == "safe" or b == "safe":
        return 1.0
    return 1.0 - wu_palmer_similarity(a, b)


@dataclass
class WeightedKappa:
    """Weighted Cohen's kappa (Cohen 1968) over the 8-label space, with
    Wu-Palmer-derived disagreement weights. Also reports the raw
    observed agreement so the kappa-paradox caveat from the methodology
    doc remains visible alongside the headline number."""

    kappa: float
    observed_agreement: float
    n_samples: int


def weighted_cohen_kappa(records: list[PredictionRecord]) -> WeightedKappa | None:
    """Compute weighted κ over a record list.

    Returns ``None`` when the record list is empty or every record
    collapses to a single label (κ formula is undefined under perfect
    label degeneracy because both observed and expected disagreement
    are zero).
    """
    if not records:
        return None

    labels = _KAPPA_LABELS
    idx = {lab: i for i, lab in enumerate(labels)}
    n = len(records)

    # Observed confusion matrix O[i][j] = # samples with truth=i, pred=j
    O = [[0 for _ in labels] for _ in labels]
    n_agree = 0
    for r in records:
        truth = r.ground_truth if r.ground_truth in idx else "safe"
        pred = _verdict(r.predicted)
        O[idx[truth]][idx[pred]] += 1
        if truth == pred:
            n_agree += 1

    # Marginals
    row_totals = [sum(O[i]) for i in range(len(labels))]
    col_totals = [sum(O[i][j] for i in range(len(labels))) for j in range(len(labels))]

    # Expected matrix under independence: E[i][j] = row_i * col_j / n
    # The kappa formula uses E in the denominator. If n == 0 we already
    # returned None.
    weighted_observed = 0.0
    weighted_expected = 0.0
    for i, a in enumerate(labels):
        for j, b in enumerate(labels):
            w = _kappa_weight(a, b)
            if w == 0.0:
                continue
            weighted_observed += w * O[i][j]
            weighted_expected += w * (row_totals[i] * col_totals[j]) / n

    if weighted_expected == 0.0:
        # All disagreement-weight mass is on the diagonal (zero) or the
        # marginals are concentrated on a single label. Kappa is
        # undefined; return None so the report shows it as "—".
        return None

    kappa = 1.0 - (weighted_observed / weighted_expected)
    return WeightedKappa(
        kappa=kappa,
        observed_agreement=n_agree / n,
        n_samples=n,
    )


def load_cvss_scores(raw_dir: str | Path = "data/raw") -> dict[str, float]:
    """Build the ``sample_id -> cvss_score`` lookup used by SWR. Reads
    every ``*.meta.json`` once; samples lacking a positive ``cvss_score``
    field are simply absent from the result."""
    out: dict[str, float] = {}
    for meta_path in Path(raw_dir).glob("*.meta.json"):
        try:
            m = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        sample_id = m.get("id")
        score = m.get("cvss_score")
        if sample_id and isinstance(score, (int, float)) and score > 0:
            out[sample_id] = float(score)
    return out


@dataclass
class VariantScore:
    """Aggregated score for one (tool, variant) over all 7 CWE cells."""

    tool: str
    variant: str
    per_cwe: dict[str, CellScore]
    n_samples: int
    binary: BinaryConfusion = field(default_factory=BinaryConfusion)
    swr: SeverityWeightedRecall = field(default_factory=SeverityWeightedRecall)
    hcma_obj: HCMA = field(default_factory=HCMA)
    kappa_obj: WeightedKappa | None = None

    @property
    def macro_f1(self) -> float:
        """Mean F1 across CWE classes that are present. Equal weight per
        class regardless of sample count (EVALUATION_METHODOLOGY 3.3)."""
        f1s = [c.f1 for c in self.per_cwe.values() if c.present]
        return sum(f1s) / len(f1s) if f1s else 0.0

    @property
    def detection_mcc(self) -> float | None:
        return self.binary.mcc

    @property
    def severity_weighted_recall(self) -> float:
        return self.swr.swr

    @property
    def hcma(self) -> float:
        return self.hcma_obj.hcma

    @property
    def weighted_kappa(self) -> float | None:
        return self.kappa_obj.kappa if self.kappa_obj is not None else None

    @property
    def observed_agreement(self) -> float | None:
        return self.kappa_obj.observed_agreement if self.kappa_obj is not None else None


def score_variant(
    records: list[PredictionRecord],
    cvss_scores: dict[str, float] | None = None,
) -> VariantScore:
    """Aggregate a list of records (assumed one tool, one variant).

    ``cvss_scores`` is optional; when None, SWR is zero with an empty
    pool. Pass the result of :func:`load_cvss_scores` to populate it.
    """
    tool = records[0].tool if records else ""
    variant = records[0].variant if records else ""
    per_cwe = {cwe: confusion(records, cwe) for cwe in TARGET_CWES}
    binary = binary_confusion(records)
    swr = (
        severity_weighted_recall(records, cvss_scores)
        if cvss_scores is not None
        else SeverityWeightedRecall()
    )
    hcma_obj = hierarchical_cwe_macro_accuracy(records)
    kappa_obj = weighted_cohen_kappa(records)
    return VariantScore(
        tool=tool, variant=variant, per_cwe=per_cwe, n_samples=len(records),
        binary=binary, swr=swr, hcma_obj=hcma_obj, kappa_obj=kappa_obj,
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
