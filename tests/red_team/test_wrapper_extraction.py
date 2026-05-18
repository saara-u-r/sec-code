"""
test_wrapper_extraction.py — tests for the WrapperExtraction mutator.

Contract:
  1. Output parses cleanly (round-trips)
  2. Function call output is preserved (semantics unchanged) — test by
     exec'ing the mutated source and comparing return values
  3. The wrapper function is inserted at the top of the body (after
     any docstring)
  4. The wrapped call's original arguments and keyword arguments are
     forwarded correctly
  5. Async calls (await ...) are wrapped with `async def` + `return await`
  6. Sink calls (execute, system, eval, ...) are preferred over arbitrary
     calls when both are present
  7. Wrapper names don't collide with existing local names
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
from src.red_team.mutators.wrapper_extraction import (
    SINK_NAMES,
    WRAPPER_EXTRACTOR,
    _call_target_name,
    _collect_call_sites,
    _has_docstring,
    _pick_target_call,
)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_call_target_name_simple():
    """Simple Name call: eval(x) → 'eval'."""
    src = "eval(x)"
    call = ast.parse(src).body[0].value
    assert _call_target_name(call) == "eval"


def test_call_target_name_attribute():
    """Attribute call: cursor.execute(q) → 'execute'."""
    src = "cursor.execute(q)"
    call = ast.parse(src).body[0].value
    assert _call_target_name(call) == "execute"


def test_call_target_name_chain():
    """Chained: obj.foo.bar(x) → 'bar' (trailing attr)."""
    src = "obj.foo.bar(x)"
    call = ast.parse(src).body[0].value
    assert _call_target_name(call) == "bar"


def test_call_target_name_indirect_returns_none():
    """Indirect: f(x)(y) — outer call's target is undefinable."""
    src = "f(x)(y)"
    call = ast.parse(src).body[0].value
    assert _call_target_name(call) is None


def test_sink_names_contain_expected():
    for s in ("execute", "system", "eval", "loads", "open"):
        assert s in SINK_NAMES


# ---------------------------------------------------------------------------
# Call collection
# ---------------------------------------------------------------------------

def test_collect_call_sites_simple():
    src = """
def f(x):
    a = len(x)
    b = max(x)
    return a + b
"""
    tree = parse_function_source(src)
    calls = _collect_call_sites(tree)
    names = sorted(_call_target_name(c) for c in calls)
    assert names == ["len", "max"]


def test_collect_call_sites_skips_nested_function():
    """Calls inside a nested def must NOT be collected."""
    src = """
def outer(x):
    def inner(y):
        return eval(y)   # inside nested def — should be excluded
    return cursor.execute(x)
"""
    tree = parse_function_source(src)
    calls = _collect_call_sites(tree)
    names = sorted(_call_target_name(c) for c in calls)
    assert "execute" in names
    assert "eval" not in names


def test_pick_target_prefers_sink_call():
    """When both sink and non-sink calls are present, sinks are preferred."""
    src = """
def f(x):
    a = len(x)
    return cursor.execute(x)
"""
    tree = parse_function_source(src)
    calls = _collect_call_sites(tree)
    rng = random.Random(0)
    for _ in range(10):
        target = _pick_target_call(calls, rng)
        assert _call_target_name(target) == "execute"


def test_pick_target_falls_back_to_any_call():
    """If no sinks, pick any call."""
    src = """
def f(x):
    return len(x)
"""
    tree = parse_function_source(src)
    calls = _collect_call_sites(tree)
    rng = random.Random(0)
    target = _pick_target_call(calls, rng)
    assert _call_target_name(target) == "len"


# ---------------------------------------------------------------------------
# Mutator behavior
# ---------------------------------------------------------------------------

def test_applies_to_function_with_calls(synthetic_functions):
    n_applicable = sum(
        1 for src in synthetic_functions
        if WRAPPER_EXTRACTOR.applies_to(parse_function_source(src))
    )
    assert n_applicable >= 8, f"Only {n_applicable} synthetics had calls"


def test_applies_to_callless_function():
    """A function with no calls should not be applicable."""
    src = """
def f(x):
    y = x + 1
    return y
"""
    tree = parse_function_source(src)
    assert not WRAPPER_EXTRACTOR.applies_to(tree)


def test_mutated_output_round_trips(synthetic_functions):
    rng = random.Random(42)
    for src in synthetic_functions:
        tree = parse_function_source(src)
        if not WRAPPER_EXTRACTOR.applies_to(tree):
            continue
        mutated = WRAPPER_EXTRACTOR.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        assert validate_round_trip(out), f"Round-trip failed:\n{out}"


def test_mutator_does_not_modify_original_tree(synthetic_functions):
    rng = random.Random(7)
    for src in synthetic_functions:
        tree = parse_function_source(src)
        if not WRAPPER_EXTRACTOR.applies_to(tree):
            continue
        original_dump = ast.dump(tree)
        WRAPPER_EXTRACTOR.mutate(tree, rng)
        assert ast.dump(tree) == original_dump


def test_wrapper_inserted_after_docstring():
    """The wrapper def must come after the docstring, not before it."""
    src = '''
def documented(items):
    """Count things."""
    return len(items)
'''
    rng = random.Random(0)
    for _ in range(10):
        tree = parse_function_source(src)
        mutated = WRAPPER_EXTRACTOR.mutate(tree, rng)
        # body[0] should still be the docstring
        first = mutated.body[0]
        assert isinstance(first, ast.Expr)
        assert isinstance(first.value, ast.Constant)
        assert first.value.value == "Count things."
        # body[1] should be the wrapper FunctionDef
        second = mutated.body[1]
        assert isinstance(second, ast.FunctionDef)
        assert second.name.startswith("_wrapped_")


def test_wrapper_inserted_at_top_when_no_docstring():
    src = """
def f(x):
    return len(x)
"""
    rng = random.Random(0)
    tree = parse_function_source(src)
    mutated = WRAPPER_EXTRACTOR.mutate(tree, rng)
    first = mutated.body[0]
    assert isinstance(first, ast.FunctionDef)
    assert first.name.startswith("_wrapped_")


def test_wrapper_uses_args_kwargs_forwarding():
    """The wrapper must use *_a, **_kw forwarding."""
    src = """
def f(query):
    return cursor.execute(query)
"""
    rng = random.Random(0)
    tree = parse_function_source(src)
    mutated = WRAPPER_EXTRACTOR.mutate(tree, rng)
    wrapper = mutated.body[0]
    assert isinstance(wrapper, ast.FunctionDef)
    assert wrapper.args.vararg is not None and wrapper.args.vararg.arg == "_a"
    assert wrapper.args.kwarg is not None and wrapper.args.kwarg.arg == "_kw"
    # No positional args in the wrapper
    assert wrapper.args.args == []


# ---------------------------------------------------------------------------
# Semantics preservation
# ---------------------------------------------------------------------------

def test_runtime_behavior_preserved_simple():
    src = """
def f(x):
    return len(x)
"""
    rng = random.Random(123)
    for _ in range(10):
        tree = parse_function_source(src)
        mutated = WRAPPER_EXTRACTOR.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        ns: dict = {}
        exec(out, ns)  # noqa: S102
        f = ns["f"]
        assert f([1, 2, 3]) == 3
        assert f("") == 0


def test_runtime_behavior_with_kwargs():
    """Wrapper must forward keyword args correctly."""
    src = """
def f(items, sep):
    return ",".join(items) + sep
"""
    rng = random.Random(7)
    for _ in range(10):
        tree = parse_function_source(src)
        mutated = WRAPPER_EXTRACTOR.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        ns: dict = {}
        exec(out, ns)
        f = ns["f"]
        assert f(["a", "b"], "!") == "a,b!"


def test_runtime_behavior_with_complex_args():
    """Multiple args + nested expressions inside the wrapped call."""
    src = """
def make_query(table, user_id):
    return "SELECT * FROM " + str(table) + " WHERE id = " + str(user_id)
"""
    rng = random.Random(11)
    for _ in range(10):
        tree = parse_function_source(src)
        mutated = WRAPPER_EXTRACTOR.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        ns: dict = {}
        exec(out, ns)
        f = ns["make_query"]
        assert f("users", 42) == "SELECT * FROM users WHERE id = 42"


# ---------------------------------------------------------------------------
# Async support
# ---------------------------------------------------------------------------

def test_async_function_round_trips():
    """Async function with awaited call must round-trip cleanly."""
    src = """
async def f(query):
    rows = await db.execute(query)
    return rows
"""
    rng = random.Random(0)
    for _ in range(5):
        tree = parse_function_source(src)
        if not WRAPPER_EXTRACTOR.applies_to(tree):
            continue
        mutated = WRAPPER_EXTRACTOR.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        assert validate_round_trip(out), f"Round-trip failed:\n{out}"


# ---------------------------------------------------------------------------
# Wrapper name collision avoidance
# ---------------------------------------------------------------------------

def test_wrapper_name_does_not_collide():
    """Wrapper name must not match any existing local name."""
    src = """
def f(x):
    _wrapped_execute_500 = "fake"
    return cursor.execute(x)
"""
    rng = random.Random(0)
    for _ in range(10):
        tree = parse_function_source(src)
        mutated = WRAPPER_EXTRACTOR.mutate(tree, rng)
        # Find the wrapper function name
        wrapper_def = next(
            n for n in mutated.body if isinstance(n, ast.FunctionDef)
        )
        # The pre-existing local must still exist as a Name reference
        existing_local_names = {
            n.id for n in ast.walk(mutated) if isinstance(n, ast.Name)
        }
        # The wrapper name we generated must not match the existing local
        assert wrapper_def.name not in {"_wrapped_execute_500"} | (
            existing_local_names - {wrapper_def.name}
        )


# ---------------------------------------------------------------------------
# Sink-call preference (proves the mutator goes for vulnerability-relevant calls)
# ---------------------------------------------------------------------------

def test_sink_call_preferred_in_real_pattern():
    """For SQLi-shaped code, the wrapped call must be `execute`."""
    src = """
def get_user(user_id):
    args = make_args(user_id)
    query = build_query(user_id)
    return cursor.execute(query)
"""
    rng = random.Random(0)
    for _ in range(10):
        tree = parse_function_source(src)
        mutated = WRAPPER_EXTRACTOR.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        # The wrapper should be for `execute`
        wrapper_def = next(n for n in mutated.body if isinstance(n, ast.FunctionDef))
        assert "execute" in wrapper_def.name, (
            f"Wrapper was for non-sink call: {wrapper_def.name}\n{out}"
        )


# ---------------------------------------------------------------------------
# Real-world samples
# ---------------------------------------------------------------------------

def test_round_trip_on_real_world_samples(real_world_samples):
    """≥ 70% pass rate on 50 real samples."""
    rng = random.Random(2024)
    n_total = 0
    n_pass = 0
    failures: list[str] = []

    for src in real_world_samples:
        tree = parse_function_source(src)
        if tree is None:
            continue
        if not WRAPPER_EXTRACTOR.applies_to(tree):
            continue
        n_total += 1
        try:
            mutated = WRAPPER_EXTRACTOR.mutate(tree, rng)
            out = unparse_clean(mutated, format_with_black=False)
            if validate_round_trip(out):
                n_pass += 1
            else:
                failures.append("invalid round-trip")
        except Exception as e:
            failures.append(f"raised: {type(e).__name__}: {e}")

    assert n_total >= 5, f"Diversity sampler returned only {n_total} applicable samples"
    pass_rate = n_pass / n_total
    assert pass_rate >= 0.70, (
        f"Pass rate {pass_rate:.1%} below 70% ({n_pass}/{n_total}). "
        f"Failures: {failures[:5]}"
    )


# ---------------------------------------------------------------------------
# Pipeline integration — all 4 mutators
# ---------------------------------------------------------------------------

def test_pipeline_with_wrapper_only(synthetic_functions):
    rng = random.Random(99)
    for src in synthetic_functions:
        out, _ = apply_mutators(
            src, [WRAPPER_EXTRACTOR], rng=rng, max_per_pass=1, min_per_pass=1,
        )
        assert validate_round_trip(out), f"Pipeline output didn't parse:\n{out}"


def test_pipeline_with_all_four_mutators(synthetic_functions):
    """All four mutators chained: dead_code + string_split + rename + wrapper."""
    from src.red_team.mutators.dead_code import DEAD_CODE_INJECTOR
    from src.red_team.mutators.string_split import STRING_SPLITTER
    from src.red_team.mutators.variable_rename import VARIABLE_RENAMER

    rng = random.Random(99)
    n_pass = 0
    for src in synthetic_functions:
        out, _ = apply_mutators(
            src,
            mutators=[
                DEAD_CODE_INJECTOR,
                STRING_SPLITTER,
                VARIABLE_RENAMER,
                WRAPPER_EXTRACTOR,
            ],
            rng=rng,
            max_per_pass=4,
            min_per_pass=2,
        )
        if validate_round_trip(out):
            n_pass += 1
    assert n_pass == len(synthetic_functions), (
        f"Only {n_pass}/{len(synthetic_functions)} survived 4-mutator chain"
    )


@pytest.mark.parametrize("seed", [0, 1, 42, 999])
def test_pipeline_deterministic_per_seed(seed):
    src = """
def get_user(user_id):
    return cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))
"""
    out1, _ = apply_mutators(
        src, [WRAPPER_EXTRACTOR], rng=random.Random(seed), max_per_pass=1, min_per_pass=1,
    )
    out2, _ = apply_mutators(
        src, [WRAPPER_EXTRACTOR], rng=random.Random(seed), max_per_pass=1, min_per_pass=1,
    )
    assert out1 == out2
