"""
red_team/mutators/dead_code.py — Mutator M2: Dead Code Injection.

Inserts statically-unreachable or side-effect-free statements at random
positions in a function body. The injected code must:
  • Never affect program behavior (zero side effects on safe inputs)
  • Never raise an exception
  • Always parse and round-trip through ast.unparse

Why this mutator: tests whether the model relies on token *position* /
attention-sink patterns or on actual data flow. A model that mispredicts
after we shift line numbers around is pattern-matching, not reasoning.
"""

from __future__ import annotations

import ast
import random
from copy import deepcopy
from dataclasses import dataclass

from src.red_team.base import register


# ---------------------------------------------------------------------------
# Library of side-effect-free / unreachable snippets
# ---------------------------------------------------------------------------
#
# Every snippet here must satisfy:
#   1. Parses standalone with ast.parse
#   2. Has zero observable side effects
#   3. Doesn't introduce any name that could clash with user code
#      (we use leading underscore + suffix to keep collision risk near zero)
#
# Snippets are stored as raw source — parsed once at import time.

_DEAD_SNIPPET_SOURCES: list[str] = [
    "_unused_var = 0",
    "_unused_var = None",
    "_unused_var = ''",
    "_unused_var = []",
    "_unused_var = {}",
    "_unused_var = ()",
    "_unused_var = sum([])",
    "_unused_var = len('')",
    "_unused_var = max([0])",
    "_unused_var = min([0])",
    "_ = lambda: None",
    "if False:\n    pass",
    "if False:\n    _x = 1",
    "if 0:\n    pass",
    "if not True:\n    pass",
    "for _i in range(0):\n    pass",
    "while False:\n    break",
    "if False and True:\n    pass",
]

# Parse all snippets once at import time. Each entry is a list of stmts
# (since multi-line snippets like `if False: pass` parse to one stmt
# but we want a uniform interface).
_DEAD_SNIPPETS: list[list[ast.stmt]] = []
for _src in _DEAD_SNIPPET_SOURCES:
    try:
        _DEAD_SNIPPETS.append(ast.parse(_src).body)
    except SyntaxError:
        # Should never happen — but if a snippet is bad, skip it rather
        # than crash module import.
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_docstring(body: list[ast.stmt]) -> bool:
    """True if body[0] is a docstring expression."""
    return (
        len(body) > 0
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    )


def _pick_injection_count(body_len: int, rng: random.Random) -> int:
    """Pick how many dead snippets to inject based on body length."""
    if body_len <= 1:
        return 1
    if body_len <= 5:
        return rng.randint(1, 2)
    if body_len <= 20:
        return rng.randint(2, 3)
    return rng.randint(3, 4)


def _pick_injection_index(
    body_len: int,
    skip_first: bool,
    rng: random.Random,
) -> int:
    """
    Pick an index in [0, body_len] for insertion. If `skip_first`, never
    return 0 (preserves docstring at body[0]).
    """
    lo = 1 if skip_first else 0
    hi = body_len  # insert at end is allowed
    if hi < lo:
        return lo
    return rng.randint(lo, hi)


# ---------------------------------------------------------------------------
# Mutator
# ---------------------------------------------------------------------------

@dataclass
class DeadCodeInjection:
    """Mutator M2: insert dead/unreachable statements at random positions."""

    name: str = "dead_code_injection"

    def applies_to(self, tree: ast.FunctionDef) -> bool:
        # Always applicable — every function body can take an inserted stmt
        # (even a `pass`-only body can have dead code added before pass).
        return isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef))

    def mutate(self, tree: ast.FunctionDef, rng: random.Random) -> ast.FunctionDef:
        if not _DEAD_SNIPPETS:
            # Should be impossible, but guards against import-time corruption
            raise RuntimeError("dead_code: snippet library is empty")

        # Work on a deep copy — never mutate the caller's tree
        new_tree = deepcopy(tree)
        body = new_tree.body
        skip_first = _has_docstring(body)
        n_inject = _pick_injection_count(len(body), rng)

        for _ in range(n_inject):
            snippet_stmts = deepcopy(rng.choice(_DEAD_SNIPPETS))
            idx = _pick_injection_index(len(body), skip_first, rng)
            # Splice in (one or more statements per snippet)
            body[idx:idx] = snippet_stmts

        # Edge case: empty body after dead code is still empty? impossible —
        # dead code adds at least 1 stmt. But ensure the body has something.
        if not body:
            body.append(ast.Pass())

        ast.fix_missing_locations(new_tree)
        return new_tree


# Register the mutator instance with the global registry
DEAD_CODE_INJECTOR = DeadCodeInjection()
register(DEAD_CODE_INJECTOR)
