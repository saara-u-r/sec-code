"""
red_team/mutators/string_split.py — Mutator M3: String Literal Splitting.

Splits string literals into concatenated parts, evading surface-level
pattern matching (e.g. Bandit / Semgrep regexes that look for
``"SELECT "`` or ``"DELETE FROM"``) while preserving runtime semantics.

Why this is the most important mutator: many vulnerability scanners
(including some LLMs) match against literal substrings. After this
mutation, the runtime SQL / shell command / template is byte-identical,
but the source-level token stream is shuffled. A model whose CWE
prediction confidence drops here is provably doing surface-form matching.

Examples
--------
Plain string ::

    query = "SELECT * FROM users"

becomes ::

    query = "SEL" + "ECT * FRO" + "M users"

F-string ::

    q = f"SELECT * FROM users WHERE id = {uid}"

becomes ::

    q = f"SEL" f"ECT * FROM users WHERE id = {uid}"
    # (which Python concatenates back into the same string at compile time)

Implementation notes
--------------------
* We split the *literal* parts of strings only — never split inside
  ``FormattedValue`` interpolation expressions of an f-string.
* Strings shorter than ``MIN_SPLIT_LENGTH`` are skipped.
* Splits inside docstrings are skipped (would mangle help() output).
* Splits inside ``arg.annotation`` / forward-ref-style type hint strings
  are skipped (some tools evaluate these strings).
* Bytes literals (``b"..."``) are skipped — different node type and
  irrelevant to text-based vulnerabilities.
"""

from __future__ import annotations

import ast
import random
from copy import deepcopy
from dataclasses import dataclass

from src.red_team.base import register


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

MIN_SPLIT_LENGTH = 6        # don't split strings shorter than this
MAX_SPLITS_PER_STRING = 3   # cap on splits per individual string
MAX_STRINGS_PER_FUNCTION = 8  # cap on strings touched per mutation pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_str_constant(node: ast.AST) -> bool:
    """True if `node` is a Constant holding a (non-empty, non-bytes) str."""
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and len(node.value) >= MIN_SPLIT_LENGTH
    )


def _split_string_value(s: str, n_splits: int, rng: random.Random) -> list[str]:
    """
    Cut `s` into `n_splits + 1` pieces at random positions.

    Positions avoid index 0 and len(s) (no empty leading/trailing parts).
    Returns the list of pieces in order; concatenating them yields `s`.
    Strings shorter than ``MIN_SPLIT_LENGTH`` are returned unchanged —
    splitting them produces single-character pieces which is ugly and
    not useful for our adversarial-robustness goal.
    """
    if len(s) < MIN_SPLIT_LENGTH or n_splits <= 0:
        return [s]
    n_splits = min(n_splits, len(s) - 1)
    positions = sorted(rng.sample(range(1, len(s)), n_splits))
    parts: list[str] = []
    last = 0
    for p in positions:
        parts.append(s[last:p])
        last = p
    parts.append(s[last:])
    return parts


def _build_concat_chain(parts: list[str]) -> ast.expr:
    """
    Build an ast.BinOp(Add) chain from a list of string parts.

    [\"a\", \"b\", \"c\"] → BinOp(BinOp(Constant(\"a\"), +, Constant(\"b\")), +, Constant(\"c\"))
    """
    if not parts:
        return ast.Constant(value="")
    expr: ast.expr = ast.Constant(value=parts[0])
    for p in parts[1:]:
        expr = ast.BinOp(left=expr, op=ast.Add(), right=ast.Constant(value=p))
    return expr


def _split_joined_str(node: ast.JoinedStr, rng: random.Random) -> ast.expr | None:
    """
    Split the literal `Constant` parts of an f-string into a BinOp chain
    of (plain) Constants and single-element JoinedStrs.

    NOTE: We deliberately convert ``f"SELECT * FROM users WHERE id = {uid}"``
    into ``"SEL" + "ECT * FROM users WHERE id = " + f"{uid}"`` rather than
    keeping it as a single JoinedStr with split Constant children. The
    reason: ``ast.unparse`` silently merges consecutive Constant siblings
    inside a JoinedStr back into one literal at print time, which would
    make the split invisible. Converting to a BinOp chain forces the
    string boundaries to remain visible in the source — exactly what we
    need to defeat surface-level pattern matchers.

    Returns the new BinOp chain, or None if no constant part was long
    enough to split.
    """
    pieces: list[ast.expr] = []
    changed = False
    for v in node.values:
        if isinstance(v, ast.Constant) and isinstance(v.value, str) and len(v.value) >= MIN_SPLIT_LENGTH:
            n_splits = rng.randint(1, MAX_SPLITS_PER_STRING)
            parts = _split_string_value(v.value, n_splits, rng)
            if len(parts) > 1:
                pieces.extend(ast.Constant(value=p) for p in parts)
                changed = True
                continue
            pieces.append(ast.Constant(value=v.value))
        elif isinstance(v, ast.Constant) and isinstance(v.value, str):
            # Short literal — keep as plain str
            pieces.append(ast.Constant(value=v.value))
        elif isinstance(v, ast.FormattedValue):
            # Wrap the FormattedValue in its own JoinedStr so the format
            # spec / conversion is preserved exactly.
            pieces.append(ast.JoinedStr(values=[v]))
        else:
            pieces.append(v)

    if not changed or not pieces:
        return None

    # Combine all pieces with `+` into a BinOp chain
    expr: ast.expr = pieces[0]
    for p in pieces[1:]:
        expr = ast.BinOp(left=expr, op=ast.Add(), right=p)
    return expr


# ---------------------------------------------------------------------------
# Skip-context tracker
# ---------------------------------------------------------------------------
#
# Some string Constant nodes must NOT be split:
#   • The function's first-statement docstring (Expr→Constant str)
#   • Type annotations on arguments (arg.annotation when it's a string)
#   • Type annotations on return values (FunctionDef.returns when string)
#   • Module-level docstrings — N/A here since we work on a function tree

def _collect_skip_nodes(fn: ast.FunctionDef) -> set[int]:
    """
    Return the set of `id(node)` values that must not be touched.

    We use object identity (id) since AST nodes don't hash by structure.
    """
    skip: set[int] = set()

    # Docstring (first stmt that is Expr(Constant(str)))
    if fn.body and isinstance(fn.body[0], ast.Expr) and isinstance(fn.body[0].value, ast.Constant) and isinstance(fn.body[0].value.value, str):
        skip.add(id(fn.body[0].value))

    # arg annotations (string forward refs)
    for arg in (fn.args.args + fn.args.kwonlyargs + fn.args.posonlyargs):
        if arg.annotation is not None:
            for n in ast.walk(arg.annotation):
                if isinstance(n, ast.Constant) and isinstance(n.value, str):
                    skip.add(id(n))

    # return annotation
    if fn.returns is not None:
        for n in ast.walk(fn.returns):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                skip.add(id(n))

    return skip


# ---------------------------------------------------------------------------
# Transformer
# ---------------------------------------------------------------------------

class _StringSplitter(ast.NodeTransformer):
    def __init__(self, rng: random.Random, skip_ids: set[int], cap: int):
        self.rng = rng
        self.skip_ids = skip_ids
        self.cap = cap
        self.touched = 0
        # Skip f-string interpolation expressions — we don't want to mutate
        # `request.args["x"]` if it appears inside a `FormattedValue` of an
        # f-string. The JoinedStr handler manages its own splitting.
        self._inside_formatted_value = 0

    # ----- f-strings ---------------------------------------------------

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        if self.touched >= self.cap:
            return node
        # Don't recurse into the JoinedStr's values via generic_visit —
        # we handle them specially. Skip if the entire f-string node is
        # in the skip set.
        if id(node) in self.skip_ids:
            return node
        replacement = _split_joined_str(node, self.rng)
        if replacement is not None:
            self.touched += 1
            return replacement
        return node

    def visit_FormattedValue(self, node: ast.FormattedValue) -> ast.AST:
        # Don't split string literals that live inside an interpolated
        # expression of an f-string — keep their semantics tight.
        self._inside_formatted_value += 1
        try:
            self.generic_visit(node)
        finally:
            self._inside_formatted_value -= 1
        return node

    # ----- plain strings ----------------------------------------------

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if self.touched >= self.cap:
            return node
        if id(node) in self.skip_ids:
            return node
        if self._inside_formatted_value:
            return node
        if not _is_str_constant(node):
            return node

        n_splits = self.rng.randint(1, MAX_SPLITS_PER_STRING)
        parts = _split_string_value(node.value, n_splits, self.rng)
        if len(parts) <= 1:
            return node

        self.touched += 1
        return _build_concat_chain(parts)


# ---------------------------------------------------------------------------
# Mutator
# ---------------------------------------------------------------------------

@dataclass
class StringSplit:
    """Mutator M3: split string literals into concatenated chunks."""

    name: str = "string_split"

    def applies_to(self, tree: ast.FunctionDef) -> bool:
        if not isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        skip = _collect_skip_nodes(tree)
        for n in ast.walk(tree):
            # plain string of sufficient length, not in skip set
            if isinstance(n, ast.Constant) and id(n) not in skip and _is_str_constant(n):
                return True
            # f-string with a long literal part
            if isinstance(n, ast.JoinedStr) and id(n) not in skip:
                for v in n.values:
                    if isinstance(v, ast.Constant) and isinstance(v.value, str) and len(v.value) >= MIN_SPLIT_LENGTH:
                        return True
        return False

    def mutate(self, tree: ast.FunctionDef, rng: random.Random) -> ast.FunctionDef:
        new_tree = deepcopy(tree)
        skip = _collect_skip_nodes(new_tree)
        splitter = _StringSplitter(rng, skip, MAX_STRINGS_PER_FUNCTION)
        result = splitter.visit(new_tree)
        ast.fix_missing_locations(result)
        return result  # type: ignore[return-value]


STRING_SPLITTER = StringSplit()
register(STRING_SPLITTER)
