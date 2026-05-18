"""
labeler/class_weights.py — Phase 2b class weight computation.

Builds three loss-weight schedules from per-CWE training counts:

  1. ``uniform``           — all classes get 1.0 (baseline)
  2. ``effective_number``  — Cui et al. 2019 (CVPR), the standard
                             long-tail re-weighting
  3. ``ldam_margins``      — Cao et al. 2019 (NeurIPS); these are
                             *margins* added to the softmax logits,
                             not multiplicative loss weights

Plus a Deferred Re-Weighting (DRW) schedule per design doc §4.3.

References
----------
* Cui et al. 2019 — "Class-Balanced Loss Based on Effective Number of Samples"
* Cao et al. 2019 — "Learning Imbalanced Datasets with Label-Distribution-Aware
  Margin Loss"
* Lin et al. 2017 — Focal Loss (γ default 2.0; layered atop these weights)
"""

from __future__ import annotations

from typing import Iterable


# ---------------------------------------------------------------------------
# Effective Number of Samples (Cui et al. 2019)
# ---------------------------------------------------------------------------

def effective_number_weights(
    counts: dict[str, int],
    beta: float = 0.999,
    normalize: bool = True,
) -> dict[str, float]:
    """
    Compute weights ``w_c = (1 - beta) / (1 - beta^n_c)`` per class.

    Cui et al. recommend β ∈ [0.99, 0.9999]. β=0.999 is standard for
    datasets up to ~10K samples per class — it produces a smooth
    down-weighting curve where adding the 1000th sample contributes
    less than the 10th.

    If `normalize`, scale weights so their sum equals the number of
    classes (PyTorch's ``nn.CrossEntropyLoss`` convention).
    """
    if not counts:
        raise ValueError("counts is empty")
    if not (0.0 < beta < 1.0):
        raise ValueError(f"beta must be in (0, 1), got {beta}")

    raw = {}
    for c, n in counts.items():
        if n <= 0:
            raw[c] = 0.0
            continue
        en = (1.0 - beta) / (1.0 - beta ** n)
        raw[c] = en

    if normalize:
        total = sum(raw.values())
        if total == 0:
            return raw
        scale = len(raw) / total
        return {c: w * scale for c, w in raw.items()}
    return raw


# ---------------------------------------------------------------------------
# LDAM margins (Cao et al. 2019)
# ---------------------------------------------------------------------------

def ldam_margins(
    counts: dict[str, int],
    max_margin: float = 0.5,
    exponent: float = 0.25,
) -> dict[str, float]:
    """
    Compute LDAM margins ``m_c = C / n_c^exponent`` where ``C`` is chosen
    so the largest (rare-class) margin equals ``max_margin``. A larger
    margin pushes the decision boundary further from rare classes,
    giving them more wiggle room before being misclassified.

    Default ``exponent=0.25`` (i.e. ``n_c^(1/4)``) and ``max_margin=0.5``
    are the values used in the original LDAM paper for CIFAR-LT and
    iNaturalist 2018.
    """
    if not counts:
        raise ValueError("counts is empty")

    raw_margins = {c: 1.0 / (max(n, 1) ** exponent) for c, n in counts.items()}
    biggest = max(raw_margins.values())
    if biggest == 0:
        return raw_margins
    scale = max_margin / biggest
    return {c: m * scale for c, m in raw_margins.items()}


# ---------------------------------------------------------------------------
# Top-level builder
# ---------------------------------------------------------------------------

def build_weight_schedules(
    counts: dict[str, int],
    label_order: Iterable[str] | None = None,
    beta: float = 0.999,
    ldam_max_margin: float = 0.5,
    drw_total_epochs: int = 10,
    drw_phase_a_fraction: float = 0.8,
    phase_b_weights_name: str = "effective_number",
) -> dict:
    """
    Build the full class-weights config blob (matching design doc §4.3).

    `label_order`, if given, controls the order of the per-class weight
    keys in the emitted JSON — useful when the model expects a specific
    ordering. If None, sorted by class name.
    """
    classes = list(label_order) if label_order is not None else sorted(counts.keys())
    counts_ordered = {c: counts.get(c, 0) for c in classes}

    uniform = {c: 1.0 for c in classes}
    eff_num = effective_number_weights(counts_ordered, beta=beta)
    margins = ldam_margins(counts_ordered, max_margin=ldam_max_margin)

    phase_a_epochs = int(round(drw_total_epochs * drw_phase_a_fraction))
    phase_b_epochs = drw_total_epochs - phase_a_epochs

    return {
        "_schema_version": 1,
        "label_order":     classes,
        "raw_counts":      counts_ordered,
        "uniform":         uniform,
        "effective_number": eff_num,
        "ldam_margins":    margins,
        "drw_schedule": {
            "total_epochs":         drw_total_epochs,
            "phase_a_epochs":       phase_a_epochs,
            "phase_b_epochs":       phase_b_epochs,
            "phase_b_weights":      phase_b_weights_name,
            "_comment":             (
                f"Phase A ({phase_a_epochs} epochs): uniform weights, "
                f"backbone learns from natural distribution. "
                f"Phase B ({phase_b_epochs} epochs): switch to "
                f"{phase_b_weights_name}, classifier head re-calibrates."
            ),
        },
        "config": {
            "beta":             beta,
            "ldam_max_margin":  ldam_max_margin,
            "ldam_exponent":    0.25,
        },
    }
