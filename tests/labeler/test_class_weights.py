"""
test_class_weights.py — tests for class-weight schedule computation.
"""

from __future__ import annotations

import math

import pytest

from src.labeler.class_weights import (
    build_weight_schedules,
    effective_number_weights,
    ldam_margins,
)


# ---------------------------------------------------------------------------
# effective_number_weights
# ---------------------------------------------------------------------------

def test_effective_number_balanced_classes_equal_weights():
    """With identical counts, all classes get equal weights."""
    counts = {"A": 100, "B": 100, "C": 100}
    w = effective_number_weights(counts, beta=0.999)
    assert math.isclose(w["A"], w["B"], rel_tol=1e-9)
    assert math.isclose(w["A"], w["C"], rel_tol=1e-9)


def test_effective_number_rare_class_gets_higher_weight():
    """Rare class must get a strictly higher weight than common class."""
    counts = {"common": 1000, "rare": 35}
    w = effective_number_weights(counts, beta=0.999)
    assert w["rare"] > w["common"]


def test_effective_number_normalize_sums_to_n_classes():
    counts = {"A": 100, "B": 50, "C": 10}
    w = effective_number_weights(counts, beta=0.999, normalize=True)
    total = sum(w.values())
    assert math.isclose(total, 3.0, rel_tol=1e-6)


def test_effective_number_zero_count_class_zero_weight():
    counts = {"A": 100, "missing": 0}
    w = effective_number_weights(counts, beta=0.999)
    assert w["missing"] == 0.0


def test_effective_number_rejects_invalid_beta():
    counts = {"A": 10}
    with pytest.raises(ValueError):
        effective_number_weights(counts, beta=0.0)
    with pytest.raises(ValueError):
        effective_number_weights(counts, beta=1.0)
    with pytest.raises(ValueError):
        effective_number_weights(counts, beta=-0.5)


def test_effective_number_rejects_empty():
    with pytest.raises(ValueError):
        effective_number_weights({}, beta=0.999)


# ---------------------------------------------------------------------------
# ldam_margins
# ---------------------------------------------------------------------------

def test_ldam_margins_rare_class_gets_largest_margin():
    counts = {"common": 1000, "rare": 35}
    m = ldam_margins(counts, max_margin=0.5)
    assert m["rare"] > m["common"]
    # The rarest class margin should equal max_margin
    assert math.isclose(m["rare"], 0.5, rel_tol=1e-6)


def test_ldam_margins_uses_quartic_root():
    counts = {"A": 16, "B": 1}
    m = ldam_margins(counts, max_margin=0.5, exponent=0.25)
    # 16^0.25 = 2, so raw margins are 1/2 and 1/1; ratio 0.5 vs 1.0
    # After scaling so max=0.5: A=0.25, B=0.5
    assert math.isclose(m["A"], 0.25, rel_tol=1e-6)
    assert math.isclose(m["B"], 0.5, rel_tol=1e-6)


def test_ldam_margins_balanced_classes_equal_margins():
    counts = {"A": 100, "B": 100, "C": 100}
    m = ldam_margins(counts, max_margin=0.5)
    assert math.isclose(m["A"], m["B"], rel_tol=1e-6)
    assert math.isclose(m["A"], m["C"], rel_tol=1e-6)


def test_ldam_margins_zero_count_handled():
    """A zero-count class must not crash the margin computation."""
    counts = {"A": 100, "missing": 0}
    m = ldam_margins(counts)
    # missing class has the largest margin (1/1^0.25 = 1.0), so it gets max
    assert math.isclose(m["missing"], 0.5, rel_tol=1e-6)


# ---------------------------------------------------------------------------
# build_weight_schedules — top-level orchestration
# ---------------------------------------------------------------------------

def test_build_emits_all_three_schedules():
    counts = {"A": 100, "B": 50, "C": 10}
    out = build_weight_schedules(counts)
    assert "uniform" in out
    assert "effective_number" in out
    assert "ldam_margins" in out
    assert "drw_schedule" in out
    # All schedules should have the same set of classes
    for k in ("uniform", "effective_number", "ldam_margins"):
        assert set(out[k].keys()) == {"A", "B", "C"}


def test_build_uniform_is_all_ones():
    counts = {"CWE-89": 1000, "CWE-502": 35}
    out = build_weight_schedules(counts)
    assert all(v == 1.0 for v in out["uniform"].values())


def test_build_drw_schedule_split_correctly():
    counts = {"A": 100}
    out = build_weight_schedules(counts, drw_total_epochs=10, drw_phase_a_fraction=0.8)
    assert out["drw_schedule"]["phase_a_epochs"] == 8
    assert out["drw_schedule"]["phase_b_epochs"] == 2
    assert (
        out["drw_schedule"]["phase_a_epochs"]
        + out["drw_schedule"]["phase_b_epochs"]
        == 10
    )


def test_build_label_order_respected():
    counts = {"X": 5, "Y": 50, "Z": 500}
    label_order = ["Z", "Y", "X"]
    out = build_weight_schedules(counts, label_order=label_order)
    assert out["label_order"] == ["Z", "Y", "X"]
    assert list(out["uniform"].keys()) == ["Z", "Y", "X"]


def test_build_with_real_world_distribution():
    """Sanity check using our actual train counts."""
    counts = {
        "CWE-89":  332,
        "CWE-79":  309,
        "CWE-22":  181,
        "CWE-918": 127,
        "CWE-78":  56,
        "CWE-94":  48,
        "CWE-502": 34,
        "safe":    303,
    }
    out = build_weight_schedules(counts)

    # CWE-502 is rarest (34) so should have the highest LDAM margin
    assert out["ldam_margins"]["CWE-502"] > out["ldam_margins"]["CWE-89"]
    # And the highest effective-number weight (after normalization)
    assert (
        out["effective_number"]["CWE-502"]
        > out["effective_number"]["CWE-89"]
    )
