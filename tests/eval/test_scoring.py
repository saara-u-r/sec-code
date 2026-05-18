"""Tests for src.eval.scoring — confusion counts, per-cell metrics,
macro-F1, and the robustness drop."""

import math

from src.eval.scoring import (
    CellScore,
    PredictionRecord,
    confusion,
    macro_f1,
    robustness_drop,
    score_variant,
)


def _rec(sample_id, gt, predicted, *, tool="bandit", variant="clean"):
    return PredictionRecord(
        tool=tool, variant=variant, sample_id=sample_id,
        ground_truth=gt, predicted=list(predicted),
    )


# --------------------------------------------------------------------------
# CellScore math
# --------------------------------------------------------------------------

def test_cellscore_metrics():
    c = CellScore(cwe="CWE-89", tp=8, tn=10, fp=2, fn=4)
    assert c.support == 12
    assert c.precision == 8 / 10
    assert c.recall == 8 / 12
    assert math.isclose(c.f1, 2 * 0.8 * (8 / 12) / (0.8 + 8 / 12))
    assert c.present


def test_cellscore_zero_division_is_safe():
    empty = CellScore(cwe="CWE-22")
    assert empty.precision == 0.0
    assert empty.recall == 0.0
    assert empty.f1 == 0.0
    assert not empty.present


def test_cellscore_present_on_prediction_only():
    # No ground-truth samples of this CWE, but a false positive exists.
    c = CellScore(cwe="CWE-918", fp=3, tn=5)
    assert c.support == 0
    assert c.present


# --------------------------------------------------------------------------
# confusion — one-vs-rest binarization
# --------------------------------------------------------------------------

def test_confusion_one_vs_rest():
    records = [
        _rec("a", "CWE-89", ["CWE-89"]),            # TP for 89
        _rec("b", "CWE-89", ["CWE-79"]),            # FN for 89, FP for 79
        _rec("c", "CWE-79", ["CWE-89"]),            # FP for 89, FN for 79
        _rec("d", "safe", []),                       # TN for everything
        _rec("e", "safe", ["CWE-89"]),              # FP for 89
    ]
    c89 = confusion(records, "CWE-89")
    assert (c89.tp, c89.fp, c89.fn, c89.tn) == (1, 2, 1, 1)

    c79 = confusion(records, "CWE-79")
    assert (c79.tp, c79.fp, c79.fn, c79.tn) == (0, 1, 1, 3)


def test_confusion_multi_cwe_prediction():
    # A single sample predicted as two CWEs hits two cells.
    records = [_rec("a", "CWE-89", ["CWE-89", "CWE-94"])]
    assert confusion(records, "CWE-89").tp == 1
    assert confusion(records, "CWE-94").fp == 1


# --------------------------------------------------------------------------
# macro-F1
# --------------------------------------------------------------------------

def test_macro_f1_averages_present_classes_only():
    # Perfect on CWE-89, zero on CWE-79; other 5 classes absent.
    records = [
        _rec("a", "CWE-89", ["CWE-89"]),
        _rec("b", "CWE-89", ["CWE-89"]),
        _rec("c", "CWE-79", []),
    ]
    # CWE-89 F1 = 1.0, CWE-79 F1 = 0.0 -> macro over the 2 present = 0.5
    assert math.isclose(macro_f1(records), 0.5)


def test_macro_f1_perfect_detector():
    records = [
        _rec("a", "CWE-89", ["CWE-89"]),
        _rec("b", "CWE-79", ["CWE-79"]),
        _rec("c", "safe", []),
    ]
    assert math.isclose(macro_f1(records), 1.0)


def test_score_variant_carries_tool_and_variant():
    records = [_rec("a", "CWE-89", ["CWE-89"], variant="string_split")]
    vs = score_variant(records)
    assert vs.tool == "bandit"
    assert vs.variant == "string_split"
    assert vs.n_samples == 1
    assert set(vs.per_cwe) == set(__import__(
        "src.eval.cwe_map", fromlist=["TARGET_CWES"]).TARGET_CWES)


# --------------------------------------------------------------------------
# robustness drop
# --------------------------------------------------------------------------

def test_robustness_drop_positive_when_mutator_hurts():
    clean = [
        _rec("a", "CWE-89", ["CWE-89"], variant="clean"),
        _rec("b", "CWE-79", ["CWE-79"], variant="clean"),
    ]
    mutator = [
        _rec("a", "CWE-89", ["CWE-89"], variant="string_split"),
        _rec("b", "CWE-79", [], variant="string_split"),   # now missed
    ]
    drop = robustness_drop(clean, mutator)
    # clean macro-F1 = 1.0, mutator macro-F1 = 0.5 -> drop = 0.5
    assert math.isclose(drop, 0.5)


def test_robustness_drop_restricts_clean_to_shared_ids():
    # The clean run carries an extra "safe" sample that the mutator
    # variant does not — it must not skew the drop.
    clean = [
        _rec("a", "CWE-89", ["CWE-89"], variant="clean"),
        _rec("safe1", "safe", ["CWE-89"], variant="clean"),  # FP, clean-only
    ]
    mutator = [_rec("a", "CWE-89", ["CWE-89"], variant="variable_rename")]
    # Restricted to {a}: clean macro-F1 = 1.0, mutator = 1.0 -> drop 0.0
    assert math.isclose(robustness_drop(clean, mutator), 0.0)


def test_robustness_drop_negative_when_mutator_helps():
    clean = [_rec("a", "CWE-89", [], variant="clean")]
    mutator = [_rec("a", "CWE-89", ["CWE-89"], variant="dead_code_injection")]
    assert robustness_drop(clean, mutator) < 0


# --------------------------------------------------------------------------
# PredictionRecord serialization
# --------------------------------------------------------------------------

def test_prediction_record_json_roundtrip():
    r = PredictionRecord(
        tool="bandit", variant="clean", sample_id="x",
        ground_truth="CWE-89", predicted=["CWE-89"],
        raw_output={"findings": []}, latency_ms=12, tool_version="1.9.4",
    )
    back = PredictionRecord.from_json(r.to_json())
    assert back == r
