"""
red_team/base.py — Shared infrastructure for AST-based code mutators.

A *mutator* takes a Python function (as text or AST) and produces a
semantics-preserving but lexically-different version, used to test whether
a vulnerability detection model has learned semantics or surface patterns.

This module defines:
  • The `Mutator` Protocol that every concrete mutator implements
  • `MutationResult` — a structured outcome (success / skip / fail)
  • `parse_function_source(source)` — robustly find and parse the function
    in a code string (whether it's a full file or a bare def)
  • `unparse_clean(tree)` — emit AST back to source, optionally run through
    black for formatting consistency
  • `validate_round_trip(source)` — check that source → AST → source
    survives parsing
  • `apply_mutators(source, mutators, rng)` — compose a list of mutators
    end-to-end with rollback on failure
"""

from __future__ import annotations

import ast
import logging
import random
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class MutationResult:
    """The outcome of one mutator's invocation."""

    success: bool
    source: str = ""              # mutated source if success, else original
    mutator: str = ""
    reason: str = ""              # human-readable on failure
    metadata: dict = field(default_factory=dict)

    @classmethod
    def ok(cls, mutator: str, source: str, **metadata) -> "MutationResult":
        return cls(success=True, source=source, mutator=mutator, metadata=metadata)

    @classmethod
    def skip(cls, mutator: str, source: str, reason: str) -> "MutationResult":
        # "skip" means the mutator was not applicable (e.g. no string
        # literals to split). Source is unchanged.
        return cls(success=False, source=source, mutator=mutator, reason=reason)

    @classmethod
    def fail(cls, mutator: str, source: str, reason: str) -> "MutationResult":
        # "fail" means the mutator raised or produced invalid code. Caller
        # should fall back to the unmutated source.
        return cls(success=False, source=source, mutator=mutator, reason=reason)


# ---------------------------------------------------------------------------
# Protocol that every mutator implements
# ---------------------------------------------------------------------------

@runtime_checkable
class Mutator(Protocol):
    """A mutator transforms an `ast.FunctionDef` in-place or returns a new one."""

    name: str

    def applies_to(self, tree: ast.FunctionDef) -> bool:
        """Quick check: does this mutator have anything to do here?"""
        ...

    def mutate(self, tree: ast.FunctionDef, rng: random.Random) -> ast.FunctionDef:
        """Return a mutated copy of `tree`. May raise — caller wraps in try."""
        ...


# ---------------------------------------------------------------------------
# Parse / unparse helpers
# ---------------------------------------------------------------------------

def parse_function_source(source: str) -> ast.FunctionDef | None:
    """
    Parse `source` and return the first FunctionDef found at module level.

    Returns None if the source has no function definition or fails to parse.
    Async functions (AsyncFunctionDef) are also accepted.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        logger.debug(f"parse_function_source: SyntaxError — {e}")
        return None

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node  # type: ignore[return-value]

    # Fall back: search nested (e.g. function inside a class body)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node  # type: ignore[return-value]

    return None


def parse_full_module(source: str) -> ast.Module | None:
    """Parse `source` as a complete module. Returns None on SyntaxError."""
    try:
        return ast.parse(source)
    except SyntaxError as e:
        logger.debug(f"parse_full_module: SyntaxError — {e}")
        return None


def unparse_clean(tree: ast.AST, format_with_black: bool = True) -> str:
    """
    Emit `tree` to source code. If `format_with_black=True`, run the result
    through black so the mutated output looks like clean developer code
    (rather than ast.unparse's default whitespace style).

    Falls back to raw `ast.unparse` if black is unavailable or fails.
    """
    raw = ast.unparse(tree)
    if not format_with_black:
        return raw

    try:
        import black
        return black.format_str(raw, mode=black.Mode())
    except ImportError:
        return raw
    except Exception as e:
        logger.debug(f"black formatting failed, falling back to ast.unparse: {e}")
        return raw


def validate_round_trip(source: str) -> bool:
    """True if `source` parses cleanly. Used as the post-mutation gate."""
    try:
        ast.parse(source)
        return True
    except SyntaxError:
        return False


# ---------------------------------------------------------------------------
# Mutator pipeline (composition with rollback)
# ---------------------------------------------------------------------------

def _find_first_function_in_module(module: ast.Module) -> ast.FunctionDef | None:
    """Return the first FunctionDef / AsyncFunctionDef in the module body."""
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node  # type: ignore[return-value]
    # Search nested (inside class bodies) as a fallback
    for node in ast.walk(module):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node  # type: ignore[return-value]
    return None


def _replace_function_in_module(
    module: ast.Module, old_fn: ast.FunctionDef, new_fn: ast.FunctionDef
) -> ast.Module:
    """Walk the module and replace `old_fn` with `new_fn` (by identity)."""
    class _Replacer(ast.NodeTransformer):
        def visit_FunctionDef(self, node):  # noqa: N802
            self.generic_visit(node)
            return new_fn if node is old_fn else node

        def visit_AsyncFunctionDef(self, node):  # noqa: N802
            self.generic_visit(node)
            return new_fn if node is old_fn else node

    return _Replacer().visit(module)


def apply_mutators(
    source: str,
    mutators: list[Mutator],
    rng: random.Random | None = None,
    max_per_pass: int = 3,
    min_per_pass: int = 1,
    format_output: bool = True,
) -> tuple[str, list[MutationResult]]:
    """
    Apply 1..max_per_pass mutators (randomly chosen and ordered) to `source`.

    Returns:
      (final_source, [MutationResult, ...] — one per attempted mutator)

    Strategy:
      • Parse `source` as a full module (preserves imports, module-level
        statements, classes — everything around the target function)
      • Locate the first function inside the module — that's our mutation
        target
      • Pick a random subset of `mutators` (size in [min_per_pass, max_per_pass])
        and apply each in random order. If a mutator fails or breaks
        round-trip, skip it
      • Re-emit the *whole module* with the mutated function spliced back
        in place of the original
    """
    rng = rng or random.Random()

    module = parse_full_module(source)
    if module is None:
        return source, [MutationResult.fail("pipeline", source, "module did not parse")]

    target_fn = _find_first_function_in_module(module)
    if target_fn is None:
        return source, [MutationResult.fail("pipeline", source, "no function found")]

    n = len(mutators)
    if n == 0:
        return unparse_clean(module, format_with_black=format_output), []
    k = rng.randint(min(min_per_pass, n), min(max_per_pass, n))
    chosen = rng.sample(mutators, k)

    results: list[MutationResult] = []
    current_fn = target_fn

    for m in chosen:
        if not m.applies_to(current_fn):
            results.append(MutationResult.skip(m.name, source, "not applicable"))
            continue

        try:
            mutated_fn = m.mutate(current_fn, rng)
        except Exception as e:
            results.append(MutationResult.fail(m.name, source, f"raised: {e}"))
            continue

        # Validate the mutated *function* round-trips cleanly on its own
        try:
            candidate = ast.unparse(mutated_fn)
            ast.parse(candidate)
        except Exception as e:
            results.append(MutationResult.fail(m.name, source, f"round-trip: {e}"))
            continue

        current_fn = mutated_fn
        results.append(MutationResult.ok(m.name, candidate))

    # Splice the (possibly mutated) function back into the module
    new_module = _replace_function_in_module(module, target_fn, current_fn)
    ast.fix_missing_locations(new_module)
    final = unparse_clean(new_module, format_with_black=format_output)
    return final, results


# ---------------------------------------------------------------------------
# Mutator registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, Mutator] = {}


def register(mutator: Mutator) -> Mutator:
    """Decorator-style registration. Used by mutator modules at import time."""
    if not getattr(mutator, "name", None):
        raise ValueError("Mutator must have a `name` attribute")
    if mutator.name in _REGISTRY:
        raise ValueError(f"Duplicate mutator name: {mutator.name}")
    _REGISTRY[mutator.name] = mutator
    return mutator


def get_mutator(name: str) -> Mutator:
    return _REGISTRY[name]


def all_mutators() -> list[Mutator]:
    return list(_REGISTRY.values())
