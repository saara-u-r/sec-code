"""
red_team/mutators/sink_attr_obfuscate.py — Mutator M5: Sink Attribute Obfuscation.

Rewrites attribute-style sink calls to their ``getattr``-mediated
equivalent. ``os.system(cmd)`` becomes ``getattr(os, "system")(cmd)``;
``cursor.execute(query)`` becomes ``getattr(cursor, "execute")(query)``.
The transformation is semantically identical at runtime (Python resolves
both forms to the same callable) but the sink token (``system``,
``execute``, ``loads``, etc.) no longer appears as a syntactic
identifier in the source. Pattern-based static analyzers that match the
sink token regex-style will miss the rewritten form.

Unlike the four original mutators (dead-code injection, variable
rename, wrapper extraction, string split) — all of which preserve the
sink token verbatim and consequently produced no measurable robustness
drop in the first evaluation pass — this mutator deliberately targets
the sink identifier itself.

Sink coverage
-------------
The mutator rewrites attribute calls whose ``(value, attr)`` matches one
of the entries in ``SINK_TARGETS`` below. The list covers the four
target CWE classes where attribute-style sinks dominate (CWE-78,
CWE-89, CWE-918, CWE-502). It does not cover:

* CWE-94 (code injection) — ``eval`` / ``exec`` / ``compile`` are bare
  builtin calls, not attribute access. A separate mutator
  (``builtin_via_globals``) is the natural fit and is left as follow-up.
* CWE-22 (path traversal) and CWE-79 (XSS) — sinks are framework-
  specific calls or property assignments that don't fit the ``getattr``
  rewrite cleanly.

The mutator is intentionally held out of training-time augmentation:
it is the test-time robustness probe for the second evaluation round.
"""

from __future__ import annotations

import ast
import random
from copy import deepcopy
from dataclasses import dataclass

from src.red_team.base import register


# ---------------------------------------------------------------------------
# Sink target list
# ---------------------------------------------------------------------------
#
# Each entry is (module_name_or_None, attr_name). A module_name of None
# is a wildcard — matches ANY value with that attribute, e.g.
# (None, "execute") matches cursor.execute, connection.execute,
# db.engine.execute, etc. Wildcards are useful for sinks (CWE-89) where
# the receiver is a runtime object rather than an imported module.

SINK_TARGETS: set[tuple[str | None, str]] = {
    # ---- CWE-78  OS command injection -------------------------------------
    ("os", "system"),
    ("os", "popen"),
    ("os", "spawnl"), ("os", "spawnle"), ("os", "spawnlp"), ("os", "spawnlpe"),
    ("os", "spawnv"), ("os", "spawnve"), ("os", "spawnvp"), ("os", "spawnvpe"),
    ("subprocess", "call"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
    ("commands", "getoutput"),
    ("commands", "getstatusoutput"),

    # ---- CWE-89  SQL injection --------------------------------------------
    (None, "execute"),
    (None, "executemany"),
    (None, "executescript"),
    (None, "raw"),

    # ---- CWE-918 SSRF -----------------------------------------------------
    ("requests", "get"),
    ("requests", "post"),
    ("requests", "put"),
    ("requests", "patch"),
    ("requests", "delete"),
    ("requests", "head"),
    ("requests", "options"),
    ("requests", "request"),
    ("urllib", "urlopen"),
    ("urllib2", "urlopen"),
    ("httpx", "get"),
    ("httpx", "post"),
    ("httpx", "put"),
    ("httpx", "patch"),
    ("httpx", "delete"),

    # ---- CWE-502 Insecure deserialization ---------------------------------
    ("pickle", "load"),
    ("pickle", "loads"),
    ("cPickle", "load"),
    ("cPickle", "loads"),
    ("dill", "load"),
    ("dill", "loads"),
    ("yaml", "load"),
    ("yaml", "load_all"),
    ("yaml", "unsafe_load"),
    ("yaml", "unsafe_load_all"),
    ("marshal", "load"),
    ("marshal", "loads"),
    ("shelve", "open"),
}

#: Sink targets indexed by attr for O(1) lookup during AST walk.
_BY_ATTR: dict[str, set[str | None]] = {}
for _val, _attr in SINK_TARGETS:
    _BY_ATTR.setdefault(_attr, set()).add(_val)


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _matches_sink(func: ast.expr) -> bool:
    """True if ``func`` is an ``Attribute`` node whose (value-name, attr)
    is a sink we target."""
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr not in _BY_ATTR:
        return False
    allowed_values = _BY_ATTR[func.attr]
    if None in allowed_values:
        return True
    if isinstance(func.value, ast.Name) and func.value.id in allowed_values:
        return True
    return False


def _to_getattr_call(attr_node: ast.Attribute) -> ast.Call:
    """Build ``getattr(value, "attr")`` from an Attribute node.

    The result is itself an expression — wrap it in another Call to
    apply the original call's args/kwargs.
    """
    return ast.Call(
        func=ast.Name(id="getattr", ctx=ast.Load()),
        args=[attr_node.value, ast.Constant(value=attr_node.attr)],
        keywords=[],
    )


# ---------------------------------------------------------------------------
# Transformer
# ---------------------------------------------------------------------------

class _SinkObfuscator(ast.NodeTransformer):
    def __init__(self) -> None:
        self.touched = 0

    def visit_Call(self, node: ast.Call) -> ast.AST:  # noqa: N802
        # Recurse first so nested calls (args, etc.) get transformed too.
        self.generic_visit(node)
        if _matches_sink(node.func):
            attr: ast.Attribute = node.func  # type: ignore[assignment]
            new_func = _to_getattr_call(attr)
            self.touched += 1
            return ast.Call(
                func=new_func,
                args=list(node.args),
                keywords=list(node.keywords),
            )
        return node


# ---------------------------------------------------------------------------
# Mutator
# ---------------------------------------------------------------------------

@dataclass
class SinkAttrObfuscate:
    """Mutator M5: rewrite sink ``x.attr(...)`` calls as
    ``getattr(x, "attr")(...)``.

    Held out of training-time augmentation; used as the test-time
    robustness probe targeting sink-token-preserving detection.
    """

    name: str = "sink_attr_obfuscate"

    def applies_to(self, tree: ast.FunctionDef) -> bool:
        if not isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and _matches_sink(n.func):
                return True
        return False

    def mutate(self, tree: ast.FunctionDef, rng: random.Random) -> ast.FunctionDef:
        # ``rng`` is unused — the mutator is deterministic given the
        # input. The signature matches the Mutator protocol.
        del rng
        new_tree = deepcopy(tree)
        obfuscator = _SinkObfuscator()
        result = obfuscator.visit(new_tree)
        ast.fix_missing_locations(result)
        return result  # type: ignore[return-value]


SINK_ATTR_OBFUSCATE = SinkAttrObfuscate()
register(SINK_ATTR_OBFUSCATE)


# ---------------------------------------------------------------------------
# Whole-module entry point
# ---------------------------------------------------------------------------
#
# The standard ``apply_mutators`` pipeline restricts each mutator to the
# first function in the module — fine for rename/dead-code/split/wrap
# (all of which need a function boundary anyway) but wrong for this
# mutator, whose target sinks can live anywhere in the file (module-level
# expressions, helper functions, class methods, etc.). The build-variants
# script uses this entry point for sink_attr_obfuscate instead.

def apply_to_source(source: str) -> tuple[str, bool]:
    """Rewrite every sink-attribute call in ``source`` (anywhere in the
    module, not just the first function). Returns ``(new_source, applied)``
    where ``applied`` is True iff at least one sink was rewritten.

    Falls back to the original source if parsing or unparsing fails.
    """
    try:
        module = ast.parse(source)
    except SyntaxError:
        return source, False

    obfuscator = _SinkObfuscator()
    new_module = obfuscator.visit(module)
    if obfuscator.touched == 0:
        return source, False

    ast.fix_missing_locations(new_module)
    try:
        out = ast.unparse(new_module)
        ast.parse(out)  # round-trip sanity
    except Exception:
        return source, False

    # Optional black formatting for consistency with the other mutators'
    # output style.
    try:
        import black
        out = black.format_str(out, mode=black.Mode())
    except Exception:
        pass

    return out, True
