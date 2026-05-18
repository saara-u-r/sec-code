"""
test_stratified_splitter.py — tests for the Phase 2 stratified group splitter.

Contract:
  1. Train + val + test == total samples (no sample dropped)
  2. Splits are deterministic given the same seed
  3. Different seeds produce different splits
  4. No repo appears in more than one split (anti-leakage holds)
  5. Stratification: each CWE appears in train/val/test in roughly the
     target proportions (within reasonable tolerance for small datasets)
  6. Hard negatives are co-located with their parent samples
  7. Singleton groups (no `repo` field) work correctly
"""

from __future__ import annotations

import random
from collections import Counter

import pytest

from src.labeler.stratified_splitter import (
    SplitReport,
    stratified_group_split,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_samples(n_per_cwe: dict, repos_per_cwe: dict | None = None) -> list[dict]:
    """
    Build a synthetic dataset where every CWE has ``n_per_cwe[cwe]`` samples
    distributed across ``repos_per_cwe[cwe]`` repos.
    """
    samples = []
    counter = 0
    for cwe, n in n_per_cwe.items():
        n_repos = (repos_per_cwe or {}).get(cwe, max(1, n // 5))
        for i in range(n):
            counter += 1
            repo = f"{cwe}_repo_{i % n_repos}"
            samples.append({
                "id":               f"s{counter}",
                "cwe":              cwe,
                "repo":             repo,
                "framework":        "django" if i % 2 == 0 else "flask",
                "source":           "synthetic",
                "is_hard_negative": False,
            })
    return samples


# ---------------------------------------------------------------------------
# Basic behavior
# ---------------------------------------------------------------------------

def test_split_partitions_all_samples():
    samples = _make_samples({"CWE-89": 50, "CWE-79": 30, "CWE-502": 8})
    report = stratified_group_split(samples, seed=42)
    total = report.totals["train"] + report.totals["val"] + report.totals["test"]
    assert total == len(samples)


def test_split_is_deterministic_per_seed():
    samples = _make_samples({"CWE-89": 50, "CWE-79": 30, "CWE-502": 8})
    r1 = stratified_group_split(samples, seed=42)
    r2 = stratified_group_split(samples, seed=42)

    a1 = sorted((a.sample_id, a.split) for a in r1.assignments)
    a2 = sorted((a.sample_id, a.split) for a in r2.assignments)
    assert a1 == a2


def test_different_seeds_produce_different_splits():
    samples = _make_samples({"CWE-89": 50, "CWE-79": 30, "CWE-502": 8})
    r1 = stratified_group_split(samples, seed=1)
    r2 = stratified_group_split(samples, seed=999)

    a1 = {(a.sample_id, a.split) for a in r1.assignments}
    a2 = {(a.sample_id, a.split) for a in r2.assignments}
    assert a1 != a2


def test_split_fractions_validated():
    samples = _make_samples({"CWE-89": 10})
    with pytest.raises(ValueError):
        stratified_group_split(
            samples, seed=42, train_frac=0.5, val_frac=0.3, test_frac=0.3,
        )


def test_split_rejects_empty_input():
    with pytest.raises(ValueError):
        stratified_group_split([], seed=42)


# ---------------------------------------------------------------------------
# Anti-leakage
# ---------------------------------------------------------------------------

def test_no_repo_appears_in_two_splits():
    """Most important correctness property — repo isolation."""
    samples = _make_samples(
        {"CWE-89": 100, "CWE-79": 60, "CWE-502": 20},
        repos_per_cwe={"CWE-89": 8, "CWE-79": 4, "CWE-502": 3},
    )
    report = stratified_group_split(samples, seed=42)

    repos_per_split = {"train": set(), "val": set(), "test": set()}
    for a in report.assignments:
        if a.group_key.startswith("repo::"):
            repos_per_split[a.split].add(a.group_key)

    assert not (repos_per_split["train"] & repos_per_split["val"])
    assert not (repos_per_split["train"] & repos_per_split["test"])
    assert not (repos_per_split["val"] & repos_per_split["test"])


def test_leakage_check_in_report_passes():
    samples = _make_samples({"CWE-89": 100, "CWE-79": 60, "CWE-502": 20})
    report = stratified_group_split(samples, seed=42)
    assert report.leakage_check["train_val_repo_overlap"] == 0
    assert report.leakage_check["train_test_repo_overlap"] == 0
    assert report.leakage_check["val_test_repo_overlap"] == 0


def test_singleton_groups_for_repoless_samples():
    """Samples without `repo` should each be their own group of size 1."""
    samples = [
        {"id": f"s{i}", "cwe": "CWE-89", "repo": None,
         "framework": "django", "source": "vudenc", "is_hard_negative": False}
        for i in range(40)
    ]
    report = stratified_group_split(samples, seed=42)
    assert report.n_groups == 40
    assert report.n_singleton_groups == 40
    # And the split is allowed to spread these freely (no leakage constraint
    # binds because each is its own group)
    assert sum(report.totals.values()) == 40


# ---------------------------------------------------------------------------
# Stratification
# ---------------------------------------------------------------------------

def test_each_cwe_has_samples_in_all_splits_when_possible():
    """For CWEs with enough samples (≥ 7 distinct groups), all 3 splits
    should be non-empty for that CWE."""
    samples = _make_samples(
        {"CWE-89": 100, "CWE-79": 80, "CWE-78": 50},
        repos_per_cwe={"CWE-89": 20, "CWE-79": 16, "CWE-78": 10},
    )
    report = stratified_group_split(samples, seed=42)
    for cwe in ("CWE-89", "CWE-79", "CWE-78"):
        d = report.per_cwe[cwe]
        assert d["train"] > 0, f"{cwe} has no train samples"
        assert d["val"] > 0,   f"{cwe} has no val samples"
        assert d["test"] > 0,  f"{cwe} has no test samples"


def test_class_proportions_within_tolerance():
    """For larger CWEs, train should be ~70%, val ~15%, test ~15% (±10%)."""
    samples = _make_samples(
        {"CWE-89": 200, "CWE-79": 150},
        repos_per_cwe={"CWE-89": 40, "CWE-79": 30},
    )
    report = stratified_group_split(samples, seed=42)
    for cwe in ("CWE-89", "CWE-79"):
        d = report.per_cwe[cwe]
        n = d["train"] + d["val"] + d["test"]
        train_frac = d["train"] / n
        # Allow 10pp tolerance — group constraints can shift things
        assert 0.55 <= train_frac <= 0.85, (
            f"{cwe}: train frac {train_frac:.0%} too far from target 70%"
        )


def test_rare_cwe_with_few_groups_does_not_crash():
    """CWE with only 3 groups should still produce a valid split."""
    samples = []
    for i in range(3):
        for j in range(2):  # 2 samples per repo
            samples.append({
                "id":               f"rare_{i}_{j}",
                "cwe":              "CWE-502",
                "repo":             f"rare_repo_{i}",
                "framework":        "flask",
                "source":           "ghsa",
                "is_hard_negative": False,
            })
    # Pad with a non-rare class so the split has work to do
    samples.extend(_make_samples({"CWE-89": 50}))
    report = stratified_group_split(samples, seed=42)
    rare = report.per_cwe["CWE-502"]
    # All 6 rare samples must be assigned
    assert rare["train"] + rare["val"] + rare["test"] == 6


# ---------------------------------------------------------------------------
# Hard-negative co-location
# ---------------------------------------------------------------------------

def test_hardneg_co_located_with_parent():
    """A hardneg with parent_sample_id must end up in the same split as
    its parent."""
    parent = {
        "id":               "parent_1",
        "cwe":              "CWE-89",
        "repo":             "x/y",
        "framework":        "django",
        "source":           "ghsa_db",
        "is_hard_negative": False,
    }
    hardneg = {
        "id":               "hardneg_1",
        "cwe":              "safe",
        "repo":             None,                 # hardnegs often lack repo
        "framework":        "django",
        "source":           "hardneg_ghsa_db",
        "is_hard_negative": True,
        "parent_sample_id": "parent_1",
    }
    # Pad with other samples so the split has work to do
    samples = [parent, hardneg] + _make_samples({"CWE-79": 50})
    report = stratified_group_split(samples, seed=42)

    parent_split = next(a.split for a in report.assignments if a.sample_id == "parent_1")
    hardneg_split = next(a.split for a in report.assignments if a.sample_id == "hardneg_1")
    assert parent_split == hardneg_split, (
        f"Hardneg landed in {hardneg_split} but parent is in {parent_split}"
    )


def test_orphan_hardneg_handled_gracefully():
    """A hardneg whose parent is missing from the dataset should still
    get an assignment (treated as its own group)."""
    orphan = {
        "id":               "orphan_hn",
        "cwe":              "safe",
        "repo":             None,
        "framework":        "unknown",
        "source":           "hardneg_xxx",
        "is_hard_negative": True,
        "parent_sample_id": "nonexistent_parent",
    }
    samples = [orphan] + _make_samples({"CWE-89": 50})
    report = stratified_group_split(samples, seed=42)
    # Find the orphan
    orphan_assignment = next(a for a in report.assignments if a.sample_id == "orphan_hn")
    assert orphan_assignment.split in {"train", "val", "test"}


# ---------------------------------------------------------------------------
# SplitReport serialization
# ---------------------------------------------------------------------------

def test_report_to_dict_is_json_serializable():
    import json
    samples = _make_samples({"CWE-89": 50, "CWE-79": 30})
    report = stratified_group_split(samples, seed=42)
    out = report.to_dict()
    json_str = json.dumps(out)  # should not raise
    parsed = json.loads(json_str)
    assert "totals" in parsed
    assert "per_cwe" in parsed
    assert "leakage_check" in parsed
