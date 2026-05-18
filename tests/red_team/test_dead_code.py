"""
test_dead_code.py — tests for the DeadCodeInjection mutator.

The mutator's contract:
  1. Output parses cleanly (round-trips)
  2. Number of statements increases (something was actually injected)
  3. The original statements are still present in order
  4. Injected statements are side-effect-free / unreachable
  5. Function preserves its arguments and return type
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
from src.red_team.mutators.dead_code import (
    DEAD_CODE_INJECTOR,
    _DEAD_SNIPPETS,
    _has_docstring,
)


# ---------------------------------------------------------------------------
# Smoke tests on synthetic functions
# ---------------------------------------------------------------------------

def test_snippet_library_loaded():
    """Ensure the dead-snippet library was parsed at module import."""
    assert len(_DEAD_SNIPPETS) >= 10, "Dead-snippet library should not be empty"
    for stmts in _DEAD_SNIPPETS:
        assert isinstance(stmts, list)
        assert all(isinstance(s, ast.stmt) for s in stmts)


def test_applies_to_any_function(synthetic_functions):
    for src in synthetic_functions:
        tree = parse_function_source(src)
        assert tree is not None, f"Could not parse synthetic function: {src[:60]}"
        assert DEAD_CODE_INJECTOR.applies_to(tree)


def test_mutate_increases_body_length(synthetic_functions):
    """After mutation, the function body must have more statements."""
    rng = random.Random(42)
    for src in synthetic_functions:
        tree = parse_function_source(src)
        assert tree is not None
        original_len = len(tree.body)
        mutated = DEAD_CODE_INJECTOR.mutate(tree, rng)
        assert len(mutated.body) > original_len, (
            f"Mutation didn't grow body length for: {src[:60]}"
        )


def test_mutated_output_round_trips(synthetic_functions):
    """ast.unparse → ast.parse must succeed for every mutation."""
    rng = random.Random(42)
    for src in synthetic_functions:
        tree = parse_function_source(src)
        assert tree is not None
        mutated = DEAD_CODE_INJECTOR.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        assert validate_round_trip(out), f"Round-trip failed:\n{out}"


def test_mutator_does_not_modify_original_tree(synthetic_functions):
    """The mutator must work on a deep copy and leave the input untouched."""
    rng = random.Random(42)
    for src in synthetic_functions:
        tree = parse_function_source(src)
        assert tree is not None
        original_dump = ast.dump(tree)
        DEAD_CODE_INJECTOR.mutate(tree, rng)
        assert ast.dump(tree) == original_dump, (
            "Mutator modified the input tree (should deep-copy)"
        )


def test_docstring_preserved_at_position_zero():
    """If function starts with a docstring, it must remain at body[0]."""
    src = '''
def f(x):
    """Important docstring."""
    return x + 1
'''
    rng = random.Random(0)
    for _ in range(20):  # try multiple seeds to expose the bug
        tree = parse_function_source(src)
        assert tree is not None
        assert _has_docstring(tree.body)
        mutated = DEAD_CODE_INJECTOR.mutate(tree, rng)
        first = mutated.body[0]
        assert (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ), "Docstring no longer at body[0] after mutation"


def test_function_signature_unchanged(synthetic_functions):
    """Function name and args must survive mutation."""
    rng = random.Random(7)
    for src in synthetic_functions:
        tree = parse_function_source(src)
        assert tree is not None
        original_name = tree.name
        original_args = ast.dump(tree.args)
        mutated = DEAD_CODE_INJECTOR.mutate(tree, rng)
        assert mutated.name == original_name
        assert ast.dump(mutated.args) == original_args


def test_runtime_behavior_preserved_simple_function():
    """
    For a deterministic, side-effect-free function, runtime behavior must
    survive mutation. We exec both versions and compare results.
    """
    src = """
def add(a, b):
    return a + b
"""
    rng = random.Random(123)
    for _ in range(10):
        tree = parse_function_source(src)
        assert tree is not None
        mutated = DEAD_CODE_INJECTOR.mutate(tree, rng)
        mutated_src = unparse_clean(mutated, format_with_black=False)

        ns: dict = {}
        exec(mutated_src, ns)  # noqa: S102 — testing AST-mutator output
        f = ns["add"]
        assert f(2, 3) == 5
        assert f(-1, 1) == 0
        assert f(0, 0) == 0


# ---------------------------------------------------------------------------
# Tests against real-world samples from MongoDB
# ---------------------------------------------------------------------------

def test_round_trip_on_real_world_samples(real_world_samples):
    """
    Round-trip the dead-code mutator on 50 real samples drawn diversely
    from MongoDB. Pass rate must be ≥ 80% to be considered usable.
    """
    rng = random.Random(2024)
    n_total = 0
    n_pass = 0
    failures: list[str] = []

    for src in real_world_samples:
        tree = parse_function_source(src)
        if tree is None:
            # Source had no parseable function definition — skip, not a failure
            continue
        n_total += 1
        try:
            mutated = DEAD_CODE_INJECTOR.mutate(tree, rng)
            out = unparse_clean(mutated, format_with_black=False)
            if validate_round_trip(out):
                n_pass += 1
            else:
                failures.append("invalid round-trip")
        except Exception as e:
            failures.append(f"raised: {type(e).__name__}: {e}")

    assert n_total >= 5, f"Diversity sampler returned only {n_total} parseable samples"
    pass_rate = n_pass / n_total
    assert pass_rate >= 0.80, (
        f"Pass rate {pass_rate:.1%} below 80% threshold "
        f"({n_pass}/{n_total} passed). Sample failures: {failures[:5]}"
    )


# ---------------------------------------------------------------------------
# Integration via the apply_mutators pipeline
# ---------------------------------------------------------------------------

def test_pipeline_with_dead_code_only(synthetic_functions):
    """
    Use the full apply_mutators pipeline with only dead_code registered.
    Output must round-trip and the pipeline should report success.
    """
    rng = random.Random(99)
    for src in synthetic_functions:
        out, results = apply_mutators(
            src,
            mutators=[DEAD_CODE_INJECTOR],
            rng=rng,
            max_per_pass=1,
            min_per_pass=1,
        )
        assert validate_round_trip(out), f"Pipeline output didn't parse:\n{out}"
        assert len(results) == 1
        # Pipeline result for a function-typed sample should succeed
        assert results[0].success, f"Pipeline failed: {results[0].reason}"


@pytest.mark.parametrize("seed", [0, 1, 42, 999, 12345])
def test_pipeline_deterministic_per_seed(seed):
    """Same seed → same output. Different seeds → (usually) different outputs."""
    src = """
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)
"""
    out1, _ = apply_mutators(
        src, [DEAD_CODE_INJECTOR], rng=random.Random(seed), max_per_pass=1, min_per_pass=1,
    )
    out2, _ = apply_mutators(
        src, [DEAD_CODE_INJECTOR], rng=random.Random(seed), max_per_pass=1, min_per_pass=1,
    )
    assert out1 == out2, "Same seed produced different output"
