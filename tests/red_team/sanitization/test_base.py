"""
test_base.py — tests for the sanitization infrastructure.
"""

from __future__ import annotations

import ast
import random

from src.red_team.sanitization.base import (
    SanitizationResult,
    add_from_import,
    add_import,
    all_rules,
    call_attribute_chain,
    find_calls,
    has_from_import,
    has_import,
    rules_for,
    sanitize,
)


# ---------------------------------------------------------------------------
# call_attribute_chain
# ---------------------------------------------------------------------------

def test_chain_simple_name():
    call = ast.parse("eval(x)").body[0].value
    assert call_attribute_chain(call) == "eval"


def test_chain_attribute():
    call = ast.parse("yaml.load(x)").body[0].value
    assert call_attribute_chain(call) == "yaml.load"


def test_chain_three_levels():
    call = ast.parse("a.b.c(x)").body[0].value
    assert call_attribute_chain(call) == "a.b.c"


def test_chain_indirect_returns_none():
    call = ast.parse("f(x)(y)").body[0].value
    assert call_attribute_chain(call) is None


# ---------------------------------------------------------------------------
# Import detection
# ---------------------------------------------------------------------------

def test_has_import_simple():
    tree = ast.parse("import os\nprint(1)")
    assert has_import(tree, "os")
    assert not has_import(tree, "json")


def test_has_from_import():
    tree = ast.parse("from html import escape")
    assert has_from_import(tree, "html", "escape")
    assert not has_from_import(tree, "html", "unescape")


def test_add_import_appends_when_missing():
    tree = ast.parse("def f(): pass")
    add_import(tree, "json")
    assert has_import(tree, "json")


def test_add_import_idempotent():
    tree = ast.parse("import json\ndef f(): pass")
    add_import(tree, "json")
    n_imports = sum(1 for n in tree.body if isinstance(n, ast.Import))
    assert n_imports == 1


def test_add_from_import_appends_when_missing():
    tree = ast.parse("def f(): pass")
    add_from_import(tree, "html", "escape")
    assert has_from_import(tree, "html", "escape")


def test_add_import_after_module_docstring():
    """Imports must come after the module-level docstring, not before."""
    tree = ast.parse('"""Module docstring."""\ndef f(): pass\n')
    add_import(tree, "json")
    # body[0] = docstring, body[1] = the new import
    assert (
        isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
    )
    assert isinstance(tree.body[1], ast.Import)
    assert tree.body[1].names[0].name == "json"


def test_add_import_after_future_import():
    """``from __future__ import ...`` must remain first."""
    tree = ast.parse("from __future__ import annotations\ndef f(): pass\n")
    add_import(tree, "json")
    # body[0] = __future__ import, body[1] = the new json import
    assert isinstance(tree.body[0], ast.ImportFrom)
    assert tree.body[0].module == "__future__"
    assert isinstance(tree.body[1], ast.Import)
    assert tree.body[1].names[0].name == "json"


# ---------------------------------------------------------------------------
# find_calls
# ---------------------------------------------------------------------------

def test_find_calls_exact_match():
    tree = ast.parse("yaml.load(x)\nyaml.safe_load(y)")
    calls = find_calls(tree, "yaml.load")
    assert len(calls) == 1


def test_find_calls_trailing_only():
    tree = ast.parse("pickle.loads(x)\njson.loads(y)\nyaml.load(z)")
    calls = find_calls(tree, "loads")
    # Matches `pickle.loads` and `json.loads` (trailing == "loads")
    # but not `yaml.load` (trailing == "load")
    assert len(calls) == 2


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

def test_result_ok():
    r = SanitizationResult.ok(
        rule="some_rule", cwe="CWE-94", transform="x_to_y", source="ok",
    )
    assert r.success
    assert r.cwe == "CWE-94"
    assert r.transform == "x_to_y"


def test_result_skip_and_fail():
    s = SanitizationResult.skip("r", "CWE-94", "src", "no match")
    assert not s.success
    assert s.reason == "no match"

    f = SanitizationResult.fail("r", "CWE-94", "src", "raised: TypeError")
    assert not f.success
    assert "raised" in f.reason


# ---------------------------------------------------------------------------
# sanitize() entry point
# ---------------------------------------------------------------------------

def test_sanitize_no_rules_for_cwe():
    out, r = sanitize("def f(): pass", "CWE-9999", random.Random(0))
    assert out == "def f(): pass"
    assert not r.success
    assert "no rules registered" in r.reason


def test_sanitize_no_applicable_rule():
    """CWE-94 has rules but the source has no eval/exec → skip."""
    out, r = sanitize("def f(): return 1", "CWE-94", random.Random(0))
    assert out == "def f(): return 1"
    assert not r.success
    assert "no applicable rule" in r.reason


def test_sanitize_invalid_source():
    out, r = sanitize("def (:", "CWE-94", random.Random(0))
    assert out == "def (:"
    assert not r.success
    assert "did not parse" in r.reason


def test_registry_returns_immutable_copy():
    rules = rules_for("CWE-94")
    rules.append("garbage")  # should not poison the registry
    assert "garbage" not in rules_for("CWE-94")


def test_all_rules_lists_every_cwe():
    out = all_rules()
    assert "CWE-94" in out
    assert "CWE-502" in out
    assert "CWE-79" in out
