"""
test_string_split.py — tests for the StringSplit mutator.

Contract:
  1. Output parses cleanly (round-trips)
  2. Concatenation chain compiles and evaluates to the original string
  3. Docstrings are NOT split (preserves help() output)
  4. Type annotations as string forward refs are NOT split
  5. F-string interpolation expressions are NOT touched
  6. Bytes literals are NOT touched
  7. Strings shorter than MIN_SPLIT_LENGTH are NOT split
  8. Function semantics preserved (call output unchanged)
"""

from __future__ import annotations

import ast
import random

import pytest

from src.red_team.base import (
    apply_mutators,
    parse_function_source,
    unparse_clean,
    validate_round_trip,
)
from src.red_team.mutators.string_split import (
    MIN_SPLIT_LENGTH,
    STRING_SPLITTER,
    _build_concat_chain,
    _split_string_value,
)


# ---------------------------------------------------------------------------
# Pure-function unit tests (no AST involvement)
# ---------------------------------------------------------------------------

def test_split_string_value_concatenates_back():
    rng = random.Random(0)
    s = "SELECT * FROM users WHERE id = ?"
    for _ in range(20):
        parts = _split_string_value(s, rng.randint(1, 3), rng)
        assert "".join(parts) == s, f"split lost data: {parts}"


def test_build_concat_chain_evaluates_correctly():
    chain = _build_concat_chain(["SEL", "ECT * FROM"])
    expr = ast.Expression(body=chain)
    ast.fix_missing_locations(expr)
    code = compile(expr, "<test>", "eval")
    assert eval(code) == "SELECT * FROM"


def test_build_concat_chain_single_part():
    chain = _build_concat_chain(["only"])
    expr = ast.Expression(body=chain)
    ast.fix_missing_locations(expr)
    assert eval(compile(expr, "<test>", "eval")) == "only"


# ---------------------------------------------------------------------------
# Smoke tests on synthetic functions
# ---------------------------------------------------------------------------

def test_applies_to_synthetic_with_strings(synthetic_functions):
    """At least 3 synthetic functions should have a splittable string."""
    n_applicable = 0
    for src in synthetic_functions:
        tree = parse_function_source(src)
        assert tree is not None
        if STRING_SPLITTER.applies_to(tree):
            n_applicable += 1
    # Functions with f-strings containing long literal parts (SQLi, ping cmd,
    # async-get-user, Flask route) — at minimum 3 of these should match.
    assert n_applicable >= 3, (
        f"Only {n_applicable} synthetic functions have splittable strings; "
        f"expected ≥ 3"
    )


def test_split_string_value_short_string_unchanged():
    """Strings shorter than MIN_SPLIT_LENGTH are not split."""
    rng = random.Random(0)
    parts = _split_string_value("hi", 3, rng)
    assert parts == ["hi"]
    parts = _split_string_value("abc", 5, rng)  # len 3 < MIN_SPLIT_LENGTH=6
    assert parts == ["abc"]


def test_mutated_output_round_trips(synthetic_functions):
    rng = random.Random(42)
    for src in synthetic_functions:
        tree = parse_function_source(src)
        if not STRING_SPLITTER.applies_to(tree):
            continue
        mutated = STRING_SPLITTER.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        assert validate_round_trip(out), f"Round-trip failed:\n{out}"


def test_mutator_does_not_modify_original_tree(synthetic_functions):
    rng = random.Random(7)
    for src in synthetic_functions:
        tree = parse_function_source(src)
        if not STRING_SPLITTER.applies_to(tree):
            continue
        original_dump = ast.dump(tree)
        STRING_SPLITTER.mutate(tree, rng)
        assert ast.dump(tree) == original_dump


# ---------------------------------------------------------------------------
# Semantics preservation
# ---------------------------------------------------------------------------

def test_runtime_behavior_preserved_simple_function():
    """Function returning a string must return the same value after mutation."""
    src = """
def make_query(user_id):
    return "SELECT * FROM users WHERE id = " + str(user_id)
"""
    rng = random.Random(123)
    for _ in range(10):
        tree = parse_function_source(src)
        mutated = STRING_SPLITTER.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)

        ns: dict = {}
        exec(out, ns)  # noqa: S102 — testing AST output
        f = ns["make_query"]
        assert f(42) == "SELECT * FROM users WHERE id = 42"
        assert f(0) == "SELECT * FROM users WHERE id = 0"


def test_fstring_runtime_behavior_preserved():
    """F-string mutation must yield the same final string."""
    src = """
def make_query(user_id):
    return f"SELECT * FROM users WHERE id = {user_id}"
"""
    rng = random.Random(7)
    for _ in range(10):
        tree = parse_function_source(src)
        mutated = STRING_SPLITTER.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)

        ns: dict = {}
        exec(out, ns)
        f = ns["make_query"]
        assert f(42) == "SELECT * FROM users WHERE id = 42"


# ---------------------------------------------------------------------------
# Skip-list correctness
# ---------------------------------------------------------------------------

def test_docstring_not_split():
    """Docstrings must remain a single Constant string."""
    src = '''
def documented(x):
    """A long enough docstring to be split if we weren't careful."""
    return x + 1
'''
    rng = random.Random(0)
    tree = parse_function_source(src)
    mutated = STRING_SPLITTER.mutate(tree, rng)
    # First body statement must still be a single Expr(Constant(str))
    first = mutated.body[0]
    assert isinstance(first, ast.Expr)
    assert isinstance(first.value, ast.Constant)
    assert isinstance(first.value.value, str)
    assert "long enough docstring to be split" in first.value.value


def test_type_annotation_string_not_split():
    """Forward-ref type strings (PEP 563-style) must not be split."""
    src = '''
def f(x: "SomeLongTypeName") -> "AnotherLongTypeName":
    return x
'''
    rng = random.Random(0)
    tree = parse_function_source(src)
    mutated = STRING_SPLITTER.mutate(tree, rng)
    # Reach into the args to verify the annotation is still a single Constant
    assert isinstance(tree.args.args[0].annotation, ast.Constant)
    assert isinstance(mutated.args.args[0].annotation, ast.Constant)
    assert mutated.args.args[0].annotation.value == "SomeLongTypeName"
    assert isinstance(mutated.returns, ast.Constant)
    assert mutated.returns.value == "AnotherLongTypeName"


def test_short_string_not_split():
    """Strings below MIN_SPLIT_LENGTH must remain intact."""
    src = '''
def f():
    return "ab"  # 2 chars — must not be split
'''
    rng = random.Random(0)
    tree = parse_function_source(src)
    # applies_to may be False (no splittable strings) — but if we mutate
    # anyway, the short string should be unchanged
    if STRING_SPLITTER.applies_to(tree):
        # there must be other splittable strings; check the short one is safe
        pass
    # Walk and count: after mutation, "ab" must remain a Constant string of len 2
    mutated = STRING_SPLITTER.mutate(tree, rng) if STRING_SPLITTER.applies_to(tree) else tree
    found_short = False
    for n in ast.walk(mutated):
        if isinstance(n, ast.Constant) and n.value == "ab":
            found_short = True
            break
    assert found_short, "Short string 'ab' was lost or split"


def test_fstring_interpolation_value_not_split():
    """The interpolated expression inside an f-string must not be split."""
    src = '''
def f():
    long_var_name = "SELECT * FROM users"
    return f"Query was: {long_var_name}"
'''
    rng = random.Random(0)
    tree = parse_function_source(src)
    mutated = STRING_SPLITTER.mutate(tree, rng)
    # The Name("long_var_name") inside the FormattedValue must be untouched
    found_name_intact = False
    for n in ast.walk(mutated):
        if isinstance(n, ast.FormattedValue):
            assert isinstance(n.value, ast.Name), (
                f"FormattedValue.value should be Name, got {type(n.value).__name__}"
            )
            assert n.value.id == "long_var_name"
            found_name_intact = True
    assert found_name_intact, "No FormattedValue found in mutated f-string"


def test_bytes_literal_not_split():
    """Bytes literals (b'...') must not be transformed."""
    src = '''
def f():
    return b"SELECT * FROM users"
'''
    rng = random.Random(0)
    tree = parse_function_source(src)
    # applies_to should ideally be False here
    assert not STRING_SPLITTER.applies_to(tree)


# ---------------------------------------------------------------------------
# Real-world samples
# ---------------------------------------------------------------------------

def test_round_trip_on_real_world_samples(real_world_samples):
    """≥ 80% pass rate on 50 real samples drawn diversely from MongoDB."""
    rng = random.Random(2024)
    n_total = 0
    n_pass = 0
    failures: list[str] = []

    for src in real_world_samples:
        tree = parse_function_source(src)
        if tree is None:
            continue
        if not STRING_SPLITTER.applies_to(tree):
            # No splittable strings — not a failure, just not applicable
            continue
        n_total += 1
        try:
            mutated = STRING_SPLITTER.mutate(tree, rng)
            out = unparse_clean(mutated, format_with_black=False)
            if validate_round_trip(out):
                n_pass += 1
            else:
                failures.append("invalid round-trip")
        except Exception as e:
            failures.append(f"raised: {type(e).__name__}: {e}")

    assert n_total >= 5, f"Diversity sampler returned only {n_total} applicable samples"
    pass_rate = n_pass / n_total
    assert pass_rate >= 0.80, (
        f"Pass rate {pass_rate:.1%} below 80% ({n_pass}/{n_total}). "
        f"Failures: {failures[:5]}"
    )


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------

def test_pipeline_with_string_split_only(synthetic_functions):
    rng = random.Random(99)
    for src in synthetic_functions:
        out, results = apply_mutators(
            src,
            mutators=[STRING_SPLITTER],
            rng=rng,
            max_per_pass=1,
            min_per_pass=1,
        )
        assert validate_round_trip(out), f"Pipeline output didn't parse:\n{out}"


def test_pipeline_chained_dead_code_and_string_split(synthetic_functions):
    """Composing two mutators must produce valid output."""
    from src.red_team.mutators.dead_code import DEAD_CODE_INJECTOR

    rng = random.Random(99)
    for src in synthetic_functions:
        out, results = apply_mutators(
            src,
            mutators=[DEAD_CODE_INJECTOR, STRING_SPLITTER],
            rng=rng,
            max_per_pass=2,
            min_per_pass=2,
        )
        assert validate_round_trip(out)
        assert len(results) == 2


@pytest.mark.parametrize("seed", [0, 1, 42, 999])
def test_pipeline_deterministic_per_seed(seed):
    src = """
def get_user(user_id):
    return f"SELECT * FROM users WHERE id = {user_id}"
"""
    out1, _ = apply_mutators(
        src, [STRING_SPLITTER], rng=random.Random(seed), max_per_pass=1, min_per_pass=1,
    )
    out2, _ = apply_mutators(
        src, [STRING_SPLITTER], rng=random.Random(seed), max_per_pass=1, min_per_pass=1,
    )
    assert out1 == out2
