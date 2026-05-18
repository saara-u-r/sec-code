"""
test_cvss_targets.py — tests for CVSS target preparation.
"""

from __future__ import annotations

import math

import pytest

from src.labeler.cvss_targets import (
    CONFIDENCE_LOSS_WEIGHT,
    SEVERITY_BAND_MIDPOINT,
    SUBVECTOR_CODES,
    build_target_for_sample,
    build_targets,
    compose_base_score,
    parse_subvectors,
)


# ---------------------------------------------------------------------------
# parse_subvectors
# ---------------------------------------------------------------------------

def test_parse_subvectors_full_vector():
    sub = parse_subvectors("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert sub == {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    }


def test_parse_subvectors_v30_supported():
    sub = parse_subvectors("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")
    assert sub is not None
    assert sub["C"] == "L"


def test_parse_subvectors_missing_component_returns_none():
    """If a sub-vector is missing entirely, parsing returns None."""
    assert parse_subvectors("CVSS:3.1/AV:N/AC:L") is None


def test_parse_subvectors_invalid_value_returns_none():
    """Unknown sub-vector value (e.g., AV:X) → None."""
    assert parse_subvectors("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None


def test_parse_subvectors_no_prefix_returns_none():
    assert parse_subvectors("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None


def test_parse_subvectors_empty_returns_none():
    assert parse_subvectors("") is None
    assert parse_subvectors(None) is None


def test_subvector_codes_match_cvss_spec():
    """Ensure our code spaces match the CVSS 3.1 spec."""
    assert SUBVECTOR_CODES["AV"] == ["N", "A", "L", "P"]
    assert SUBVECTOR_CODES["AC"] == ["L", "H"]
    assert SUBVECTOR_CODES["PR"] == ["N", "L", "H"]
    assert SUBVECTOR_CODES["UI"] == ["N", "R"]
    assert SUBVECTOR_CODES["S"]  == ["U", "C"]


# ---------------------------------------------------------------------------
# compose_base_score
# ---------------------------------------------------------------------------

def test_compose_base_score_critical_example():
    """CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H ⇒ 9.8 (Critical)."""
    sub = parse_subvectors("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    score = compose_base_score(sub)
    assert math.isclose(score, 9.8, abs_tol=0.05)


def test_compose_base_score_known_high_example():
    """CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N ⇒ ~5.0–5.9 (Medium)."""
    sub = parse_subvectors("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N")
    score = compose_base_score(sub)
    # Approximate — different rounding rules in different implementations
    assert 4.5 <= score <= 6.0


def test_compose_base_score_zero_impact_returns_zero():
    """All-None impact CVSS scores 0.0."""
    sub = parse_subvectors("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    score = compose_base_score(sub)
    assert score == 0.0


def test_compose_base_score_scope_changed():
    """Scope changed uses the larger 1.08 multiplier."""
    sub = parse_subvectors("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    score = compose_base_score(sub)
    # Should be 10.0 (capped)
    assert math.isclose(score, 10.0, abs_tol=0.05)


def test_compose_base_score_missing_returns_none():
    assert compose_base_score(None) is None
    assert compose_base_score({}) is None
    assert compose_base_score({"AV": "N"}) is None  # incomplete


# ---------------------------------------------------------------------------
# build_target_for_sample
# ---------------------------------------------------------------------------

def test_build_target_full_vector_high_confidence():
    sample = {
        "cvss_vector":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score":       9.8,
        "label_confidence": "high",
    }
    t = build_target_for_sample(sample)
    assert t["cvss_score"] == 9.8
    assert t["sub_vectors"] is not None
    assert t["sub_vectors"]["C"] == "H"
    assert t["score_source"] == "advisory"
    assert t["label_confidence"] == "high"
    assert t["loss_weight"] == CONFIDENCE_LOSS_WEIGHT["high"]


def test_build_target_severity_only_falls_back_to_band_midpoint():
    sample = {
        "cvss_vector":      None,
        "cvss_score":       None,
        "cvss_severity":    "HIGH",
        "label_confidence": "high",
    }
    t = build_target_for_sample(sample)
    assert t["cvss_score"] == SEVERITY_BAND_MIDPOINT["HIGH"]
    assert t["sub_vectors"] is None
    assert t["score_source"] == "band_midpoint"
    # Severity-only should downgrade confidence to medium
    assert t["label_confidence"] == "medium"
    assert t["loss_weight"] == CONFIDENCE_LOSS_WEIGHT["medium"]


def test_build_target_no_cvss_at_all_zero_loss_weight():
    sample = {
        "cvss_vector":      None,
        "cvss_score":       None,
        "cvss_severity":    None,
        "label_confidence": "medium",
    }
    t = build_target_for_sample(sample)
    assert t["cvss_score"] is None
    assert t["sub_vectors"] is None
    assert t["score_source"] == "missing"
    assert t["loss_weight"] == 0.0


def test_build_target_score_only_no_vector():
    """Sample with score but no vector — keep the score, no sub-vectors."""
    sample = {
        "cvss_vector":      None,
        "cvss_score":       7.2,
        "label_confidence": "high",
    }
    t = build_target_for_sample(sample)
    assert t["cvss_score"] == 7.2
    assert t["sub_vectors"] is None
    assert t["score_source"] == "advisory_score_only"
    assert t["loss_weight"] == CONFIDENCE_LOSS_WEIGHT["high"]


def test_build_target_recovers_score_from_vector_when_missing():
    """If we have a vector but no score, compose the score from the vector."""
    sample = {
        "cvss_vector":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score":       None,
        "label_confidence": "high",
    }
    t = build_target_for_sample(sample)
    assert t["cvss_score"] is not None
    assert math.isclose(t["cvss_score"], 9.8, abs_tol=0.05)
    assert t["score_source"] == "computed_from_vector"


# ---------------------------------------------------------------------------
# build_targets (bulk)
# ---------------------------------------------------------------------------

def test_build_targets_keys_by_content_hash():
    samples = [
        {"id": "s1", "content_hash": "hash_a", "cvss_score": 7.5, "cvss_vector": None},
        {"id": "s2", "content_hash": "hash_b", "cvss_score": None, "cvss_vector": None},
    ]
    out = build_targets(samples)
    assert "hash_a" in out["targets"]
    assert "hash_b" in out["targets"]
    assert out["_summary"]["total"] == 2


def test_build_targets_falls_back_to_id_when_no_hash():
    samples = [{"id": "s1", "cvss_score": 5.0, "cvss_vector": None}]
    out = build_targets(samples)
    assert "s1" in out["targets"]


def test_build_targets_skips_keyless_samples():
    samples = [{"cvss_score": 5.0}]  # no id, no content_hash
    out = build_targets(samples)
    assert out["_summary"]["total"] == 0


def test_build_targets_summary_counts_correctly():
    samples = [
        {"id": "a", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "cvss_score": 9.8, "label_confidence": "high"},
        {"id": "b", "cvss_score": 5.0, "cvss_vector": None, "label_confidence": "high"},
        {"id": "c", "cvss_score": None, "cvss_vector": None, "label_confidence": "medium"},
    ]
    out = build_targets(samples)
    assert out["_summary"]["total"] == 3
    assert out["_summary"]["score_coverage"] == 2  # a and b
    assert out["_summary"]["subvector_coverage"] == 1  # only a


def test_loss_weights_sane():
    """Confidence weight ordering: high > medium > low ≥ 0."""
    assert CONFIDENCE_LOSS_WEIGHT["high"] > CONFIDENCE_LOSS_WEIGHT["medium"]
    assert CONFIDENCE_LOSS_WEIGHT["medium"] > CONFIDENCE_LOSS_WEIGHT["low"]
    assert CONFIDENCE_LOSS_WEIGHT["low"] >= 0.0
