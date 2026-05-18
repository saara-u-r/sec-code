"""Tests for src.eval.cwe_map — CWE normalization and Bandit rule mapping."""

import pytest

from src.eval.cwe_map import (
    TARGET_CWES,
    bandit_rule_to_cwe,
    normalize_cwe,
)


def test_target_cwes_are_seven():
    assert len(TARGET_CWES) == 7
    assert set(TARGET_CWES) == {
        "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502", "CWE-918",
    }


@pytest.mark.parametrize("raw,expected", [
    (89, "CWE-89"),
    (502, "CWE-502"),
    (918, "CWE-918"),
    (22, "CWE-22"),
])
def test_normalize_cwe_identity(raw, expected):
    assert normalize_cwe(raw) == expected


@pytest.mark.parametrize("child,parent", [
    (80, "CWE-79"),   # script-tag neutralization -> XSS
    (83, "CWE-79"),
    (77, "CWE-78"),   # generic command injection -> OS command injection
    (95, "CWE-94"),   # eval injection -> code injection
    (96, "CWE-94"),
    (23, "CWE-22"),   # relative path traversal -> path traversal
    (564, "CWE-89"),  # hibernate SQLi -> SQL injection
])
def test_normalize_cwe_folds_children(child, parent):
    assert normalize_cwe(child) == parent


@pytest.mark.parametrize("outside", [327, 20, 703, 400, 611, 798, 1, 0])
def test_normalize_cwe_rejects_outside_classes(outside):
    assert normalize_cwe(outside) is None


@pytest.mark.parametrize("text,expected", [
    ("CWE-502", "CWE-502"),
    ("cwe-89", "CWE-89"),
    ("502", "CWE-502"),
    ("CWE-502: Deserialization of Untrusted Data", "CWE-502"),
    ("CWE-80: Improper Neutralization", "CWE-79"),
])
def test_normalize_cwe_parses_strings(text, expected):
    assert normalize_cwe(text) == expected


@pytest.mark.parametrize("junk", [None, "", "safe", "not-a-cwe", "CWE-"])
def test_normalize_cwe_handles_junk(junk):
    assert normalize_cwe(junk) is None


@pytest.mark.parametrize("rule,expected", [
    ("B608", "CWE-89"),
    ("B703", "CWE-79"),
    ("B308", "CWE-79"),
    ("B602", "CWE-78"),
    ("B307", "CWE-94"),   # eval — Bandit mis-tags this CWE-78
    ("B102", "CWE-94"),
    ("B301", "CWE-502"),
    ("B506", "CWE-502"),  # yaml.load — Bandit mis-tags this CWE-20
    ("B310", "CWE-918"),
])
def test_bandit_rule_to_cwe_known_rules(rule, expected):
    assert bandit_rule_to_cwe(rule) == expected


def test_bandit_rule_to_cwe_is_case_insensitive():
    assert bandit_rule_to_cwe("b608") == "CWE-89"


@pytest.mark.parametrize("soft", ["B404", "B403", "B101", "B113", "B999"])
def test_bandit_rule_to_cwe_soft_rules_map_to_nothing(soft):
    assert bandit_rule_to_cwe(soft) is None


def test_bandit_rule_targets_are_all_in_scope():
    from src.eval.cwe_map import BANDIT_RULE_TO_CWE
    assert set(BANDIT_RULE_TO_CWE.values()) <= set(TARGET_CWES)
