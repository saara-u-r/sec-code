"""
test_base.py — tests for red_team.base (Mutator infrastructure).
"""

from __future__ import annotations

import ast
import random

import pytest

from src.red_team.base import (
    MutationResult,
    apply_mutators,
    parse_full_module,
    parse_function_source,
    unparse_clean,
    validate_round_trip,
)


# ---------------------------------------------------------------------------
# parse_function_source
# ---------------------------------------------------------------------------

def test_parse_simple_function():
    src = "def f(): return 1"
    tree = parse_function_source(src)
    assert tree is not None
    assert isinstance(tree, ast.FunctionDef)
    assert tree.name == "f"


def test_parse_async_function():
    src = "async def f(): return 1"
    tree = parse_function_source(src)
    assert tree is not None
    assert isinstance(tree, ast.AsyncFunctionDef)
    assert tree.name == "f"


def test_parse_returns_first_function_in_module():
    src = """
def first():
    return 1

def second():
    return 2
"""
    tree = parse_function_source(src)
    assert tree is not None
    assert tree.name == "first"


def test_parse_finds_function_inside_class():
    src = """
class C:
    def method(self):
        return 1
"""
    tree = parse_function_source(src)
    assert tree is not None
    assert tree.name == "method"


def test_parse_returns_none_on_syntax_error():
    src = "def f(:\n    return 1"
    assert parse_function_source(src) is None


def test_parse_returns_none_on_no_function():
    src = "x = 1\ny = 2\nprint(x + y)"
    assert parse_function_source(src) is None


def test_parse_full_module_succeeds_on_valid_code():
    assert parse_full_module("x = 1") is not None


def test_parse_full_module_returns_none_on_invalid():
    assert parse_full_module("def f(:") is None


# ---------------------------------------------------------------------------
# unparse_clean / validate_round_trip
# ---------------------------------------------------------------------------

def test_round_trip_simple():
    src = "def f(x):\n    return x + 1\n"
    tree = parse_function_source(src)
    out = unparse_clean(tree, format_with_black=False)
    assert validate_round_trip(out)


def test_round_trip_with_black():
    src = "def f(x):\n    return x+1\n"  # bad whitespace
    tree = parse_function_source(src)
    out = unparse_clean(tree, format_with_black=True)
    assert validate_round_trip(out)
    # Black should normalize the spacing around `+`
    assert "x + 1" in out


def test_validate_round_trip_rejects_bad_syntax():
    assert not validate_round_trip("def f(:")


# ---------------------------------------------------------------------------
# MutationResult
# ---------------------------------------------------------------------------

def test_result_ok():
    r = MutationResult.ok("m1", "def f(): pass", count=3)
    assert r.success
    assert r.mutator == "m1"
    assert r.metadata == {"count": 3}


def test_result_skip_and_fail():
    s = MutationResult.skip("m1", "def f(): pass", "no targets")
    assert not s.success
    assert s.reason == "no targets"

    f = MutationResult.fail("m1", "def f(): pass", "raised: X")
    assert not f.success
    assert f.reason.startswith("raised")


# ---------------------------------------------------------------------------
# apply_mutators with empty list / no-op mutator
# ---------------------------------------------------------------------------

class _Identity:
    name = "identity"

    def applies_to(self, tree):
        return True

    def mutate(self, tree, rng):
        return tree


def test_apply_mutators_empty_list_returns_unchanged():
    src = "def f(): return 1"
    out, results = apply_mutators(src, mutators=[], rng=random.Random(0))
    # apply_mutators still formats with black, so output may differ slightly
    assert validate_round_trip(out)
    assert results == []


def test_apply_mutators_with_identity_succeeds():
    src = "def f(): return 1"
    out, results = apply_mutators(
        src,
        mutators=[_Identity()],
        rng=random.Random(0),
        max_per_pass=1,
        min_per_pass=1,
    )
    assert validate_round_trip(out)
    assert len(results) == 1
    assert results[0].success


def test_apply_mutators_with_invalid_source_fails_gracefully():
    """
    On unparseable input, the pipeline must return the original source
    unchanged and produce a single failure result. The exact reason
    string can be either "module did not parse" (syntax error) or
    "no function found" (parses but has no function).
    """
    # Syntax error case
    out, results = apply_mutators("def f(:", mutators=[_Identity()], rng=random.Random(0))
    assert out == "def f(:"
    assert len(results) == 1 and not results[0].success
    assert "did not parse" in results[0].reason

    # Parses but has no function — should fail with "no function"
    out, results = apply_mutators("x = 1", mutators=[_Identity()], rng=random.Random(0))
    assert out == "x = 1"
    assert len(results) == 1 and not results[0].success
    assert "no function" in results[0].reason
