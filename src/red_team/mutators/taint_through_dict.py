"""
red_team/mutators/taint_through_dict.py — Mutator M7: route a sink's
first positional argument through an intermediate dict-subscript.

The two earlier sink-targeted mutators (\
``sink_attr_obfuscate`` and ``sink_via_globals``) rewrite the *sink
identifier* itself. This mutator leaves the sink identifier alone and
rewrites the *flow* by which a tainted value reaches the sink. A call::

    cursor.execute("SELECT * FROM users WHERE id = " + user_arg)

becomes::

    cursor.execute(({"_a": "SELECT * FROM users WHERE id = " + user_arg})["_a"])

The dict literal is constructed and immediately subscripted, so the
value reaching the sink is bitwise identical to the original argument.
The transformation is therefore semantics-preserving at every call
site for which it applies. The shortcut it attacks is dataflow
tracking that does not propagate taint through dict reads: a detector
relying on a static lineage from a parameter to a sink call argument
will lose the trail through the dict-construction/subscript pair.

The pattern-matching SAST tools (Bandit, Semgrep without taint mode)
do not perform dataflow and we therefore expect them to be invariant
to this mutator; we include it to (i) exercise a third sink-targeted
axis in the benchmark, (ii) provide a probe that will distinguish
dataflow-aware detectors (CodeQL, Semgrep taint configurations, a
learned detector that has internalised dict-read tracking) from pure
pattern-matching tools when those detectors are added in future work.

Sink coverage
-------------
The mutator targets the union of the SAO and SVG sink sets, i.e.
attribute-style sinks across CWE-78/89/918/502 plus bare-builtin
sinks across CWE-94. Sinks whose first positional argument is a
literal constant are skipped (there is no taint to flow); sinks
called with kwargs only and no positional arguments are also
skipped.

The mutator is held out of training-time augmentation.
"""

from __future__ import annotations

import ast
import random
from copy import deepcopy
from dataclasses import dataclass

from src.red_team.base import register
from src.red_team.mutators.sink_attr_obfuscate import _matches_sink as _matches_sao_sink
from src.red_team.mutators.sink_via_globals import BUILTIN_SINK_NAMES


def _is_sink_call(func: ast.expr) -> bool:
    """True if ``func`` is either an attribute sink (SAO target list)
    or a bare-builtin sink (SVG target list)."""
    if isinstance(func, ast.Attribute):
        return _matches_sao_sink(func)
    if isinstance(func, ast.Name):
        return func.id in BUILTIN_SINK_NAMES
    return False


def _wrap_through_dict(expr: ast.expr) -> ast.Subscript:
    """Build the AST for ``({"_a": <expr>})["_a"]``."""
    return ast.Subscript(
        value=ast.Dict(
            keys=[ast.Constant(value="_a")],
            values=[expr],
        ),
        slice=ast.Constant(value="_a"),
        ctx=ast.Load(),
    )


class _DictTaintTransformer(ast.NodeTransformer):
    def __init__(self) -> None:
        self.touched = 0

    def visit_Call(self, node: ast.Call) -> ast.AST:  # noqa: N802
        # Recurse first so nested calls get rewritten before we
        # examine this one. The wrapped subscript we synthesise
        # contains a Dict and a Constant subscript, neither of which
        # is a Call, so we do not need to worry about loops on the
        # output node.
        self.generic_visit(node)
        if not _is_sink_call(node.func):
            return node
        if not node.args:
            return node
        first = node.args[0]
        # No taint to flow if the first arg is already a literal.
        if isinstance(first, ast.Constant):
            return node
        new_first = _wrap_through_dict(first)
        new_args = [new_first] + list(node.args[1:])
        self.touched += 1
        return ast.Call(
            func=node.func,
            args=new_args,
            keywords=list(node.keywords),
        )


@dataclass
class TaintThroughDict:
    """Mutator M7: route the first positional argument of every sink
    call through a one-entry dict literal.

    Held out of training-time augmentation; used as the test-time
    robustness probe for the dataflow-through-dict axis.
    """

    name: str = "taint_through_dict"

    def applies_to(self, tree: ast.FunctionDef) -> bool:
        if not isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        for n in ast.walk(tree):
            if (
                isinstance(n, ast.Call)
                and _is_sink_call(n.func)
                and n.args
                and not isinstance(n.args[0], ast.Constant)
            ):
                return True
        return False

    def mutate(self, tree: ast.FunctionDef, rng: random.Random) -> ast.FunctionDef:
        del rng
        new_tree = deepcopy(tree)
        transformer = _DictTaintTransformer()
        result = transformer.visit(new_tree)
        ast.fix_missing_locations(result)
        return result  # type: ignore[return-value]


TAINT_THROUGH_DICT = TaintThroughDict()
register(TAINT_THROUGH_DICT)


def apply_to_source(source: str) -> tuple[str, bool]:
    """Rewrite every eligible sink call in ``source`` (anywhere in the
    module). Returns ``(new_source, applied)`` where ``applied`` is True
    iff at least one call was rewritten.

    Falls back to the original source if parsing or unparsing fails.
    """
    try:
        module = ast.parse(source)
    except SyntaxError:
        return source, False

    transformer = _DictTaintTransformer()
    new_module = transformer.visit(module)
    if transformer.touched == 0:
        return source, False

    ast.fix_missing_locations(new_module)
    try:
        out = ast.unparse(new_module)
        ast.parse(out)
    except Exception:
        return source, False

    try:
        import black
        out = black.format_str(out, mode=black.Mode())
    except Exception:
        pass

    return out, True
