"""
red_team/mutators/sink_via_globals.py — Mutator M6: Bare-builtin sink
indirection via the builtins module's ``__dict__``.

Companion to ``sink_attr_obfuscate``. Where SAO rewrites attribute-style
sinks (``os.system(...)``, ``cursor.execute(...)``), this mutator rewrites
bare *builtin* sink calls — ``eval``, ``exec``, ``compile``, and
``__import__`` — whose function is a plain :class:`ast.Name`, not an
:class:`ast.Attribute`. Together the two cover the CWE-78/89/918/502
attribute path (SAO) and the CWE-94 builtin path (this module).

The rewrite is::

    eval(payload)  ->  __import__('builtins').__dict__['eval'](payload)

The substitution is semantically identical at runtime in CPython:
``__import__('builtins')`` returns the same module object that supplies
the bare name ``eval`` at lookup time, and its ``__dict__`` exposes the
builtin under the same key. The sink token (``eval``, ``exec``, etc.) no
longer appears as a syntactic identifier in the source — only as a
string literal inside a subscript. Pattern-matching SAST tools that
look for ``eval(`` will miss the rewritten form.

Why not ``getattr``?
    Using ``getattr(__import__('builtins'), 'eval')(...)`` would
    semantically work, but ``getattr`` is the rewrite vehicle already
    used by ``sink_attr_obfuscate``. Routing through ``__dict__``
    indexing gives a distinct obfuscation axis: detectors that learn to
    flag ``getattr(_, "eval")`` would still miss ``__dict__["eval"]``.

Why not ``globals()['eval']``?
    Bare builtins are *not* stored in the module's ``globals()`` dict —
    name lookup falls through to the builtins module after globals
    misses. ``globals()['eval']`` raises ``KeyError`` at runtime in any
    module that does not explicitly assign to ``eval``. The
    ``__import__('builtins').__dict__['eval']`` form is the
    runtime-faithful counterpart that lives up to the mutator name.

The mutator is held out of training-time augmentation; it is a
test-time robustness probe like ``sink_attr_obfuscate``.
"""

from __future__ import annotations

import ast
import random
from copy import deepcopy
from dataclasses import dataclass

from src.red_team.base import register


#: Bare builtin names we rewrite. These appear as ``ast.Name(id=...)``
#: in call positions, not as ``ast.Attribute``. CWE-94 (code injection)
#: is the principal target; ``__import__`` is included because dynamic
#: imports are a well-known CWE-94 sink.
BUILTIN_SINK_NAMES: frozenset[str] = frozenset({
    "eval",
    "exec",
    "compile",
    "__import__",
})


def _matches_builtin_sink(func: ast.expr) -> bool:
    """True if ``func`` is a bare-name call to one of our target builtins."""
    return isinstance(func, ast.Name) and func.id in BUILTIN_SINK_NAMES


def _build_indirect_lookup(name: str) -> ast.Subscript:
    """Construct the AST for ``__import__('builtins').__dict__['<name>']``."""
    builtins_call = ast.Call(
        func=ast.Name(id="__import__", ctx=ast.Load()),
        args=[ast.Constant(value="builtins")],
        keywords=[],
    )
    dict_attr = ast.Attribute(
        value=builtins_call, attr="__dict__", ctx=ast.Load(),
    )
    return ast.Subscript(
        value=dict_attr,
        slice=ast.Constant(value=name),
        ctx=ast.Load(),
    )


class _GlobalsSinkObfuscator(ast.NodeTransformer):
    def __init__(self) -> None:
        self.touched = 0

    def visit_Call(self, node: ast.Call) -> ast.AST:  # noqa: N802
        # Recurse into args/kwargs first so nested calls get rewritten.
        # The returned new Call is not re-visited (NodeTransformer
        # default), so we cannot loop on the synthesized
        # ``__import__('builtins')`` we are about to emit.
        self.generic_visit(node)
        if _matches_builtin_sink(node.func):
            assert isinstance(node.func, ast.Name)
            new_func = _build_indirect_lookup(node.func.id)
            self.touched += 1
            return ast.Call(
                func=new_func,
                args=list(node.args),
                keywords=list(node.keywords),
            )
        return node


@dataclass
class SinkViaGlobals:
    """Mutator M6: rewrite bare-builtin sink calls (``eval(x)``,
    ``exec(x)``, ``compile(x, ...)``, ``__import__(x)``) as indirected
    lookups through the builtins module's ``__dict__``.

    Held out of training-time augmentation; used as the test-time
    robustness probe for CWE-94 (the class ``sink_attr_obfuscate`` skips).
    """

    name: str = "sink_via_globals"

    def applies_to(self, tree: ast.FunctionDef) -> bool:
        if not isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and _matches_builtin_sink(n.func):
                return True
        return False

    def mutate(self, tree: ast.FunctionDef, rng: random.Random) -> ast.FunctionDef:
        del rng
        new_tree = deepcopy(tree)
        obfuscator = _GlobalsSinkObfuscator()
        result = obfuscator.visit(new_tree)
        ast.fix_missing_locations(result)
        return result  # type: ignore[return-value]


SINK_VIA_GLOBALS = SinkViaGlobals()
register(SINK_VIA_GLOBALS)


def apply_to_source(source: str) -> tuple[str, bool]:
    """Rewrite every bare-builtin sink call in ``source`` (anywhere in the
    module). Returns ``(new_source, applied)`` where ``applied`` is True
    iff at least one call was rewritten.

    Falls back to the original source if parsing or unparsing fails.
    """
    try:
        module = ast.parse(source)
    except SyntaxError:
        return source, False

    obfuscator = _GlobalsSinkObfuscator()
    new_module = obfuscator.visit(module)
    if obfuscator.touched == 0:
        return source, False

    ast.fix_missing_locations(new_module)
    try:
        out = ast.unparse(new_module)
        ast.parse(out)  # round-trip sanity
    except Exception:
        return source, False

    try:
        import black
        out = black.format_str(out, mode=black.Mode())
    except Exception:
        pass

    return out, True
