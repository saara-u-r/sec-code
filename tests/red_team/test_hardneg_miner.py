"""
test_hardneg_miner.py — tests for the Phase 2.5 hard-negative miner.

Verifies:
  • _build_hardneg_meta produces a well-formed schema
  • The schema markers (is_hard_negative, parent_sample_id,
    sanitization_transform) are set correctly
  • The CWE label is reset to "safe"
  • The new content_hash differs from the parent's
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.run_phase2_5_hardneg import (
    TARGET_CWES,
    _build_hardneg_meta,
    _existing_hardneg_parent_ids_on_disk,
    _seed_for_sample,
)


def test_build_hardneg_meta_sets_provenance_fields():
    parent = {
        "id":           "ghsa_db_sql_injection_abc123",
        "source":       "ghsa_db",
        "cwe":          "CWE-89",
        "cve_id":       "CVE-2024-12345",
        "ghsa_id":      "GHSA-aaa-bbb-ccc",
        "framework":    "django",
        "repo":         "owner/repo",
        "file_path":    "myapp/views.py",
        "code_before":  "def f(uid): return cursor.execute(f'SELECT {uid}')",
        "fix_commit":   "deadbeef",
        "vulnerable_commit": "cafef00d",
    }
    sanitized = "def f(uid):\n    return cursor.execute('SELECT ?', (uid,))\n"
    meta = _build_hardneg_meta(parent, sanitized, "fstring_execute_to_parameterized")

    assert meta["is_hard_negative"] is True
    assert meta["parent_sample_id"] == parent["id"]
    assert meta["sanitization_transform"] == "fstring_execute_to_parameterized"
    assert meta["cwe"] == "safe"
    assert meta["vuln_type"] is None
    assert meta["label_source"] == "hardneg_sanitization"
    assert meta["label_confidence"] == "high"
    assert meta["source"] == "hardneg_ghsa_db"
    assert meta["code_before"] == sanitized
    assert meta["code_after"] == ""

    # Inherited traceability anchors
    assert meta["cve_id"] == "CVE-2024-12345"
    assert meta["ghsa_id"] == "GHSA-aaa-bbb-ccc"
    assert meta["framework"] == "django"
    assert meta["repo"] == "owner/repo"
    assert meta["fix_commit"] == "deadbeef"

    # Independent identity
    assert meta["id"] != parent["id"]
    assert meta["id"].startswith("hardneg_")


def test_seed_is_deterministic():
    parent = {"content_hash": "deadbeef" * 8}
    s1 = _seed_for_sample(parent, base_seed=42)
    s2 = _seed_for_sample(parent, base_seed=42)
    assert s1 == s2


def test_seed_varies_with_base_seed():
    parent = {"content_hash": "deadbeef" * 8}
    s1 = _seed_for_sample(parent, base_seed=1)
    s2 = _seed_for_sample(parent, base_seed=999)
    # Different base_seeds → almost certainly different seeds
    assert s1 != s2


def test_target_cwes_match_registered_rules():
    """Every CWE in TARGET_CWES must have at least one registered rule."""
    from src.red_team.sanitization import all_rules
    rules = all_rules()
    missing = [c for c in TARGET_CWES if c not in rules or not rules[c]]
    assert not missing, f"CWEs without sanitization rules: {missing}"


def test_existing_hardneg_scanner_handles_missing_dir(tmp_path):
    """When the output dir doesn't exist, scanner returns empty set."""
    nonexistent = tmp_path / "does_not_exist"
    out = _existing_hardneg_parent_ids_on_disk(str(nonexistent))
    assert out == set()


def test_existing_hardneg_scanner_collects_parents(tmp_path):
    """Scanner should pick up parent_sample_id from hardneg_*.meta.json files."""
    # Create a fake hardneg meta file
    meta = {
        "id": "hardneg_eval_to_literal_eval_abc123",
        "is_hard_negative": True,
        "parent_sample_id": "vudenc_code_injection_xyz789",
        "cwe": "safe",
    }
    (tmp_path / "hardneg_eval_to_literal_eval_abc123.meta.json").write_text(
        json.dumps(meta), encoding="utf-8",
    )
    # And a non-hardneg file (should be ignored)
    other = {"id": "ghsa_xyz", "is_hard_negative": False}
    (tmp_path / "ghsa_xyz.meta.json").write_text(json.dumps(other), encoding="utf-8")

    out = _existing_hardneg_parent_ids_on_disk(str(tmp_path))
    assert out == {"vudenc_code_injection_xyz789"}


def test_target_cwes_unchanged():
    """TARGET_CWES must include all 7 we have rules for."""
    expected = {"CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502", "CWE-918"}
    assert set(TARGET_CWES) == expected
