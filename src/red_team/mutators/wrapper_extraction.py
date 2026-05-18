"""
red_team/mutators/wrapper_extraction.py — Mutator M4: Wrapper Extraction.

Wraps a "vulnerability-relevant" call inside an inline-defined nested
function, forcing the dataflow to traverse one extra level of indirection.

Why this mutator: pattern-matching models look at vulnerability signals
within a single function's surface form. After this mutation, the
attribute call ``cursor.execute(query)`` becomes ``_execute_inner(query)``
— a call to a user-defined function. A model that only looks at the
outer function's calls (not the bodies of nested functions defined
inline) loses the "execute" signal completely. A model that follows
inter-procedural dataflow (which GraphCodeBERT can do) follows the call
into ``_execute_inner`` and still flags the vulnerability.

Strategy
--------
1. Walk the function body and collect "interesting" Call nodes — calls
   whose target name matches a known vulnerability sink (``execute``,
   ``system``, ``eval``, ``loads``, ``open``, ``get``, ...).
2. Pick one Call uniformly at random.
3. Generate a wrapper function::

       def <wrapper_name>(*_a, **_kw):
           return <original_call>(*_a, **_kw)

   that forwards all arguments to the original call. The wrapper is
   inserted at the start of the function body (after any docstring).
4. Replace the original Call expression with a call to the wrapper,
   preserving the original arguments.

Why ``*args, **kwargs`` forwarding (the "lazy" variant)
-------------------------------------------------------
Generating an explicit signature for the wrapper would require us to
introspect default values, type annotations, and keyword-only specs
of the target — fragile across the long tail of Python idioms.
``*_a, **_kw`` forwarding is provably semantics-preserving for any
call (because it's exactly what Python uses internally for partial
application via ``functools.partial``). The wrapper is correct by
construction.
"""

from __future__ import annotations

import ast
import random
from copy import deepcopy
from dataclasses import dataclass, field

from src.red_team.base import register


# ---------------------------------------------------------------------------
# Sinks: function/method names worth wrapping
# ---------------------------------------------------------------------------

# Names that are vulnerability-relevant. The mutator preferentially picks
# calls to these (the most informative ones for our use case). If none of
# these appear, it falls back to wrapping ANY call.
SINK_NAMES: frozenset[str] = frozenset({
    # CWE-89  — SQL Injection
    "execute", "executemany", "executescript", "raw", "text", "filter",
    # CWE-78  — Command Injection
    "system", "popen", "run", "call", "check_output", "Popen",
    # CWE-22  — Path Traversal
    "open", "send_file", "send_from_directory",
    # CWE-79  — XSS
    "Markup", "mark_safe", "render_template_string",
    # CWE-94  — Code Injection
    "eval", "exec", "compile", "import_module",
    # CWE-918 — SSRF
    "get", "post", "put", "patch", "delete", "head", "request",
    "urlopen", "Request",
    # CWE-502 — Deserialization
    "loads", "load", "full_load", "unsafe_load",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _call_target_name(call: ast.Call) -> str | None:
    """
    Return the *trailing* identifier of a call's func attribute chain.

    For ``cursor.execute(q)`` returns ``"execute"``; for ``os.system(c)``
    returns ``"system"``; for ``eval(x)`` returns ``"eval"``; for
    ``obj.foo.bar(x)`` returns ``"bar"``. Returns None for indirect calls
    where the trailing name can't be determined statically.
    """
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _has_docstring(body: list[ast.stmt]) -> bool:
    return (
        len(body) > 0
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    )


def _is_within_call_func(parent_call: ast.Call, candidate: ast.Call) -> bool:
    """True if `candidate` is exactly the .func attribute of `parent_call`.

    We use this to skip calls that ARE the func of another call (rare but
    happens in higher-order code like ``decorator()(args)``).
    """
    return parent_call.func is candidate


def _collect_call_sites(fn: ast.FunctionDef) -> list[ast.Call]:
    """Walk the function body and collect all Call nodes (skipping nested
    function/class bodies, lambdas, and decorators — same scope discipline
    as the rename mutator)."""
    out: list[ast.Call] = []

    def _walk(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            if node is fn:
                # Walk the body of the target function but not nested defs
                for child in node.body:
                    _walk(child)
            return
        if isinstance(node, ast.Call):
            out.append(node)
        for child in ast.iter_child_nodes(node):
            _walk(child)

    # We bypass `_walk(fn)` and walk fn's body directly (decorators are
    # outside the function's logical scope).
    for child in fn.body:
        _walk(child)
    return out


def _pick_target_call(
    calls: list[ast.Call], rng: random.Random
) -> ast.Call | None:
    """Prefer calls whose trailing name is a known sink; fall back to any."""
    sink_calls = [c for c in calls if _call_target_name(c) in SINK_NAMES]
    if sink_calls:
        return rng.choice(sink_calls)
    if calls:
        return rng.choice(calls)
    return None


def _build_wrapper(
    target_call: ast.Call,
    wrapper_name: str,
    is_async: bool = False,
) -> ast.FunctionDef:
    """
    Construct an inline wrapper that forwards `*_a, **_kw` to the original
    call's func node. The original call's arguments are NOT inlined into
    the wrapper — the wrapper accepts whatever caller passes and forwards.
    """
    # Build the forwarded call: <original_func>(*_a, **_kw)
    forwarded_call = ast.Call(
        func=deepcopy(target_call.func),
        args=[ast.Starred(value=ast.Name(id="_a", ctx=ast.Load()), ctx=ast.Load())],
        keywords=[ast.keyword(arg=None, value=ast.Name(id="_kw", ctx=ast.Load()))],
    )

    if is_async:
        body_stmt = ast.Return(value=ast.Await(value=forwarded_call))
        FnNode = ast.AsyncFunctionDef
    else:
        body_stmt = ast.Return(value=forwarded_call)
        FnNode = ast.FunctionDef

    args = ast.arguments(
        posonlyargs=[],
        args=[],
        vararg=ast.arg(arg="_a", annotation=None),
        kwonlyargs=[],
        kw_defaults=[],
        kwarg=ast.arg(arg="_kw", annotation=None),
        defaults=[],
    )

    return FnNode(
        name=wrapper_name,
        args=args,
        body=[body_stmt],
        decorator_list=[],
        returns=None,
    )


def _replace_call_in_function(
    fn: ast.FunctionDef, old_call: ast.Call, new_call: ast.Call
) -> ast.FunctionDef:
    """Replace `old_call` (by identity) with `new_call` in fn's body."""

    class _Replacer(ast.NodeTransformer):
        def visit_Call(self, node: ast.Call) -> ast.AST:  # noqa: N802
            self.generic_visit(node)
            return new_call if node is old_call else node

    return _Replacer().visit(fn)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Mutator
# ---------------------------------------------------------------------------

@dataclass
class WrapperExtraction:
    """Mutator M4: extract a vulnerable call into a nested wrapper function."""

    name: str = "wrapper_extraction"
    wrapper_prefix: str = "_wrapped_"
    sink_names: frozenset = field(default_factory=lambda: SINK_NAMES)

    def applies_to(self, tree: ast.FunctionDef) -> bool:
        if not isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        # Need at least one Call node inside the function's local scope
        for node in _collect_call_sites(tree):
            return True  # found one — applicable
        return False

    def mutate(self, tree: ast.FunctionDef, rng: random.Random) -> ast.FunctionDef:
        new_tree = deepcopy(tree)
        calls = _collect_call_sites(new_tree)
        target = _pick_target_call(calls, rng)
        if target is None:
            return new_tree

        target_name = _call_target_name(target) or "call"
        # Strip any chars that aren't valid identifier components, then add
        # a small random suffix to avoid collision with existing names.
        clean = "".join(ch for ch in target_name if ch.isalnum() or ch == "_")
        suffix = rng.randint(100, 999)
        wrapper_name = f"{self.wrapper_prefix}{clean}_{suffix}"

        # Avoid name collision with existing locals
        existing_names: set[str] = set()
        for n in ast.walk(new_tree):
            if isinstance(n, ast.Name):
                existing_names.add(n.id)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                existing_names.add(n.name)
            elif isinstance(n, ast.arg):
                existing_names.add(n.arg)
        while wrapper_name in existing_names:
            suffix = rng.randint(100, 999)
            wrapper_name = f"{self.wrapper_prefix}{clean}_{suffix}"

        # Determine if the original call was awaited — if so, the wrapper
        # needs `async def` and `return await ...`.
        is_async_call = self._is_awaited(new_tree, target)

        wrapper_fn = _build_wrapper(target, wrapper_name, is_async=is_async_call)

        # Build the replacement Call: <wrapper_name>(<original args>, <original kwargs>)
        new_call = ast.Call(
            func=ast.Name(id=wrapper_name, ctx=ast.Load()),
            args=[deepcopy(a) for a in target.args],
            keywords=[deepcopy(k) for k in target.keywords],
        )

        # Replace original call in the tree
        new_tree = _replace_call_in_function(new_tree, target, new_call)

        # Insert wrapper at top of function body, after any docstring
        insert_idx = 1 if _has_docstring(new_tree.body) else 0
        new_tree.body.insert(insert_idx, wrapper_fn)

        ast.fix_missing_locations(new_tree)
        return new_tree

    def _is_awaited(self, fn: ast.FunctionDef, target: ast.Call) -> bool:
        """Return True if `target` appears as `await target` somewhere in fn."""
        for node in ast.walk(fn):
            if isinstance(node, ast.Await) and node.value is target:
                return True
        return False


WRAPPER_EXTRACTOR = WrapperExtraction()
register(WRAPPER_EXTRACTOR)
