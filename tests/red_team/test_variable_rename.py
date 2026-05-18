"""
test_variable_rename.py — tests for the VariableRename mutator.

Contract:
  1. Output parses cleanly (round-trips)
  2. Function call output is preserved (semantics unchanged)
  3. Builtins (`len`, `range`, `print`) are NEVER renamed
  4. `self` and `cls` are NEVER renamed
  5. Imported names are NEVER renamed
  6. Attribute names (`obj.foo`) are NEVER renamed
  7. Free variables (referenced but not defined locally) are NEVER renamed
  8. Names declared `global` or `nonlocal` are NEVER renamed
  9. Names inside string literals are NEVER renamed
 10. Nested function arguments are NEVER renamed (separate scope)
 11. The function's own name is NEVER renamed (would break recursion)
 12. At least one local variable IS renamed when applicable
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
from src.red_team.mutators.variable_rename import (
    SYNONYMS,
    VARIABLE_RENAMER,
    _collect_local_names,
    _pick_synonym,
)


# ---------------------------------------------------------------------------
# Pure unit tests
# ---------------------------------------------------------------------------

def test_synonyms_dict_nonempty():
    assert len(SYNONYMS) >= 30
    for k, vs in SYNONYMS.items():
        assert len(vs) >= 1
        assert all(isinstance(v, str) and v.isidentifier() for v in vs)


def test_pick_synonym_known():
    rng = random.Random(0)
    assert _pick_synonym("user", rng) in SYNONYMS["user"]


def test_pick_synonym_unknown_falls_back_to_var():
    rng = random.Random(0)
    out = _pick_synonym("nonexistent_xyz", rng)
    assert out.startswith("var_")
    assert out.isidentifier()


def test_pick_synonym_deterministic_per_seed():
    a = _pick_synonym("user", random.Random(42))
    b = _pick_synonym("user", random.Random(42))
    assert a == b


# ---------------------------------------------------------------------------
# Scope analyzer
# ---------------------------------------------------------------------------

def test_collect_locals_simple():
    src = """
def f(a, b):
    c = a + b
    for d in range(10):
        e = d * 2
    return c
"""
    tree = parse_function_source(src)
    locals_ = _collect_local_names(tree)
    assert "a" in locals_
    assert "b" in locals_
    assert "c" in locals_
    assert "d" in locals_
    assert "e" in locals_
    # `range` is a builtin → excluded
    assert "range" not in locals_


def test_collect_locals_excludes_global_decl():
    src = """
def f():
    global x
    x = 1
    y = 2
    return x + y
"""
    tree = parse_function_source(src)
    locals_ = _collect_local_names(tree)
    assert "x" not in locals_
    assert "y" in locals_


def test_collect_locals_excludes_self():
    src = """
def method(self, x):
    self.x = x
    y = self.x + 1
    return y
"""
    tree = parse_function_source(src)
    locals_ = _collect_local_names(tree)
    assert "self" not in locals_
    assert "x" in locals_
    assert "y" in locals_


def test_collect_locals_with_async_for():
    src = """
async def f(items):
    total = 0
    async for item in items:
        total += item
    return total
"""
    tree = parse_function_source(src)
    locals_ = _collect_local_names(tree)
    assert "items" in locals_
    assert "item" in locals_
    assert "total" in locals_


def test_collect_locals_excludes_nested_function_args():
    """A nested function's own args are not part of the outer scope.

    Nested function names are technically local bindings in the outer
    scope, but renaming them is unsafe (we don't enter the nested body to
    rewrite its definition), so we deliberately exclude them.
    """
    src = """
def outer(x):
    def inner(y):
        return y + 1
    return x + inner(x)
"""
    tree = parse_function_source(src)
    locals_ = _collect_local_names(tree)
    assert "x" in locals_
    assert "y" not in locals_      # y belongs to inner's scope
    # `inner` is locally bound but the renamer can't safely rewrite its def,
    # so it's deliberately excluded from rename candidates.
    assert "inner" not in locals_


def test_collect_locals_with_walrus():
    src = """
def f(items):
    if (n := len(items)) > 0:
        return n
    return -1
"""
    tree = parse_function_source(src)
    locals_ = _collect_local_names(tree)
    assert "n" in locals_
    assert "items" in locals_


def test_collect_locals_with_starred_assignment():
    src = """
def f(values):
    first, *rest = values
    return first, rest
"""
    tree = parse_function_source(src)
    locals_ = _collect_local_names(tree)
    assert "first" in locals_
    assert "rest" in locals_
    assert "values" in locals_


# ---------------------------------------------------------------------------
# Mutator behavior — synthetic
# ---------------------------------------------------------------------------

def test_applies_to_synthetic_with_locals(synthetic_functions):
    """Most synthetic functions have at least one local variable."""
    n_applicable = sum(
        1 for src in synthetic_functions
        if VARIABLE_RENAMER.applies_to(parse_function_source(src))
    )
    # Functions with parameters are always applicable. Most of our synthetics
    # have parameters → expect ≥ 8 of 12.
    assert n_applicable >= 8


def test_mutated_output_round_trips(synthetic_functions):
    rng = random.Random(42)
    for src in synthetic_functions:
        tree = parse_function_source(src)
        if not VARIABLE_RENAMER.applies_to(tree):
            continue
        mutated = VARIABLE_RENAMER.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        assert validate_round_trip(out), f"Round-trip failed:\n{out}"


def test_mutator_does_not_modify_original_tree(synthetic_functions):
    rng = random.Random(7)
    for src in synthetic_functions:
        tree = parse_function_source(src)
        if not VARIABLE_RENAMER.applies_to(tree):
            continue
        original_dump = ast.dump(tree)
        VARIABLE_RENAMER.mutate(tree, rng)
        assert ast.dump(tree) == original_dump


def test_function_name_unchanged():
    """The function's own name must never be renamed."""
    src = """
def my_function(x, y):
    return x + y
"""
    rng = random.Random(0)
    for _ in range(20):
        tree = parse_function_source(src)
        mutated = VARIABLE_RENAMER.mutate(tree, rng)
        assert mutated.name == "my_function"


# ---------------------------------------------------------------------------
# Semantics preservation
# ---------------------------------------------------------------------------

def test_runtime_behavior_simple_arithmetic():
    src = """
def add(a, b):
    return a + b
"""
    rng = random.Random(123)
    for _ in range(10):
        tree = parse_function_source(src)
        mutated = VARIABLE_RENAMER.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        ns: dict = {}
        exec(out, ns)  # noqa: S102 — testing AST output
        f = ns["add"]
        assert f(2, 3) == 5
        assert f(-1, 1) == 0


def test_runtime_behavior_with_loop_and_state():
    src = """
def count_evens(items):
    n = 0
    for x in items:
        if x % 2 == 0:
            n += 1
    return n
"""
    rng = random.Random(5)
    for _ in range(10):
        tree = parse_function_source(src)
        mutated = VARIABLE_RENAMER.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        ns: dict = {}
        exec(out, ns)
        f = ns["count_evens"]
        assert f([1, 2, 3, 4, 5, 6]) == 3
        assert f([]) == 0
        assert f([2, 4, 6]) == 3


def test_runtime_behavior_string_format():
    """Names appearing inside f-string interpolations get renamed too."""
    src = """
def make_query(user_id):
    return f"SELECT * FROM users WHERE id = {user_id}"
"""
    rng = random.Random(11)
    for _ in range(10):
        tree = parse_function_source(src)
        mutated = VARIABLE_RENAMER.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        ns: dict = {}
        exec(out, ns)
        f = ns["make_query"]
        assert f(42) == "SELECT * FROM users WHERE id = 42"


# ---------------------------------------------------------------------------
# Skip-list correctness
# ---------------------------------------------------------------------------

def test_self_not_renamed():
    src = """
def method(self, x):
    self.x = x
    return self.x
"""
    rng = random.Random(0)
    for _ in range(20):
        tree = parse_function_source(src)
        mutated = VARIABLE_RENAMER.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        assert "self" in out, f"`self` was renamed:\n{out}"


def test_builtins_not_renamed():
    src = """
def f(items):
    n = len(items)
    return list(range(n))
"""
    rng = random.Random(0)
    for _ in range(20):
        tree = parse_function_source(src)
        mutated = VARIABLE_RENAMER.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        for builtin in ("len", "range", "list"):
            assert builtin in out, f"Builtin `{builtin}` was renamed:\n{out}"


def test_imported_names_not_renamed():
    src = """
def f():
    import os
    return os.path.join('/tmp', 'x')
"""
    rng = random.Random(0)
    for _ in range(20):
        tree = parse_function_source(src)
        mutated = VARIABLE_RENAMER.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        # `os` is imported inside the function — it counts as a local name
        # (the import statement binds it). Renaming `os` is technically safe
        # if we rename ALL its uses too. The current implementation does NOT
        # collect imports as local names, so `os` should remain.
        assert "os.path.join" in out


def test_attribute_names_not_renamed():
    src = """
def update_user(user, name):
    user.name = name
    user.id = name + '_pk'
    return user.name
"""
    rng = random.Random(0)
    for _ in range(20):
        tree = parse_function_source(src)
        mutated = VARIABLE_RENAMER.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        # The local `user` and `name` may be renamed, but `.name` and `.id`
        # as attribute accesses must remain.
        # We check that we still see attribute access patterns
        assert ".name" in out
        assert ".id" in out


def test_global_decl_names_not_renamed():
    src = """
counter = 0
def increment():
    global counter
    counter += 1
    return counter
"""
    rng = random.Random(0)
    for _ in range(20):
        tree = parse_function_source(src)
        mutated = VARIABLE_RENAMER.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        # `counter` is declared global — must remain
        assert "global counter" in out
        assert "counter += 1" in out
        assert "return counter" in out


def test_string_literals_not_renamed():
    """The string content "user_id" must remain even if the variable is renamed."""
    src = """
def get_user(user_id):
    msg = "Looking up user_id"
    return msg + ': ' + str(user_id)
"""
    rng = random.Random(0)
    for _ in range(20):
        tree = parse_function_source(src)
        mutated = VARIABLE_RENAMER.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        # The literal "user_id" inside the string must remain
        assert "Looking up user_id" in out


def test_nested_function_arguments_unchanged():
    """Nested functions have their own scope. Their args are NOT in our scope."""
    src = """
def outer(x):
    def inner(y):
        return y * 2
    return inner(x)
"""
    rng = random.Random(0)
    for _ in range(20):
        tree = parse_function_source(src)
        mutated = VARIABLE_RENAMER.mutate(tree, rng)
        out = unparse_clean(mutated, format_with_black=False)
        # Find the inner function definition. Its arg name `y` and body
        # reference to `y` should both still be `y`.
        inner_tree = ast.parse(out)
        inner_fn = None
        for node in ast.walk(inner_tree):
            if isinstance(node, ast.FunctionDef) and node.name == "inner":
                inner_fn = node
                break
        assert inner_fn is not None, f"Inner function not found in:\n{out}"
        assert inner_fn.args.args[0].arg == "y", (
            "Nested function's parameter was renamed (would break scope)"
        )


def test_at_least_one_rename_happens():
    """For a function with several locals, the mutator should rename at least one."""
    src = """
def get_user(user_id, name, query):
    result = cursor.execute(query)
    return result
"""
    rng = random.Random(0)
    tree = parse_function_source(src)
    mutated = VARIABLE_RENAMER.mutate(tree, rng)
    out = unparse_clean(mutated, format_with_black=False)
    # At least one of user_id, name, query, result should have been renamed
    n_present = sum(1 for n in ("user_id", "name", "query", "result") if n in out)
    assert n_present < 4, f"No locals were renamed:\n{out}"


def test_rename_fraction_intensity():
    """When fraction_range is fixed at (1.0, 1.0), all locals are renamed."""
    from src.red_team.mutators.variable_rename import VariableRename

    full_renamer = VariableRename(rename_fraction_range=(1.0, 1.0))
    src = """
def f(user_id, name):
    query = name + str(user_id)
    return query
"""
    rng = random.Random(7)
    tree = parse_function_source(src)
    mutated = full_renamer.mutate(tree, rng)
    out = unparse_clean(mutated, format_with_black=False)
    # All four locals (user_id, name, query, plus possibly the param name)
    # should be renamed. None of the originals should appear as identifiers.
    # We check via AST so we don't get false positives from comments.
    new_tree = ast.parse(out)
    name_ids = {n.id for n in ast.walk(new_tree) if isinstance(n, ast.Name)}
    arg_ids = set()
    for node in ast.walk(new_tree):
        if isinstance(node, ast.FunctionDef):
            for a in node.args.args:
                arg_ids.add(a.arg)
    all_idents = name_ids | arg_ids
    for original in ("user_id", "name", "query"):
        assert original not in all_idents, (
            f"Original identifier `{original}` survived a 100% rename:\n{out}"
        )


# ---------------------------------------------------------------------------
# Real-world samples
# ---------------------------------------------------------------------------

def test_round_trip_on_real_world_samples(real_world_samples):
    """≥ 70% pass rate on 50 real samples drawn diversely from MongoDB.

    Threshold is slightly lower than the other mutators because real-world
    Python often has subtle scope edge cases (decorators that reference
    locals, type vars, stub functions with `...` body) that this
    implementation may not handle perfectly. 70% is the floor.
    """
    rng = random.Random(2024)
    n_total = 0
    n_pass = 0
    failures: list[str] = []

    for src in real_world_samples:
        tree = parse_function_source(src)
        if tree is None:
            continue
        if not VARIABLE_RENAMER.applies_to(tree):
            continue
        n_total += 1
        try:
            mutated = VARIABLE_RENAMER.mutate(tree, rng)
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
# Pipeline integration
# ---------------------------------------------------------------------------

def test_pipeline_with_variable_rename_only(synthetic_functions):
    rng = random.Random(99)
    for src in synthetic_functions:
        out, _ = apply_mutators(
            src, [VARIABLE_RENAMER], rng=rng, max_per_pass=1, min_per_pass=1,
        )
        assert validate_round_trip(out), f"Pipeline output didn't parse:\n{out}"


def test_pipeline_chained_all_three_mutators(synthetic_functions):
    """Chain dead_code + string_split + variable_rename."""
    from src.red_team.mutators.dead_code import DEAD_CODE_INJECTOR
    from src.red_team.mutators.string_split import STRING_SPLITTER

    rng = random.Random(99)
    n_pass = 0
    for src in synthetic_functions:
        out, results = apply_mutators(
            src,
            mutators=[DEAD_CODE_INJECTOR, STRING_SPLITTER, VARIABLE_RENAMER],
            rng=rng,
            max_per_pass=3,
            min_per_pass=2,
        )
        if validate_round_trip(out):
            n_pass += 1
    assert n_pass == len(synthetic_functions), (
        f"Only {n_pass}/{len(synthetic_functions)} synthetics survived 3-mutator chain"
    )


@pytest.mark.parametrize("seed", [0, 1, 42, 999])
def test_pipeline_deterministic_per_seed(seed):
    src = """
def get_user(user_id, name):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)
"""
    out1, _ = apply_mutators(
        src, [VARIABLE_RENAMER], rng=random.Random(seed), max_per_pass=1, min_per_pass=1,
    )
    out2, _ = apply_mutators(
        src, [VARIABLE_RENAMER], rng=random.Random(seed), max_per_pass=1, min_per_pass=1,
    )
    assert out1 == out2
