"""
cwe22_path.py — Sanitization rule for CWE-22 (Path Traversal).

Vulnerable patterns
-------------------
    open(os.path.join(BASE, user_path))
    open(user_path)
    send_file(user_path)
    send_from_directory(BASE, user_path)

The vulnerability: the user can pass ``../../etc/passwd`` and break out
of the intended directory.

Sanitized form
--------------
The canonical fix is to use ``werkzeug.utils.secure_filename`` (the
go-to in Flask apps) or ``pathlib.Path.resolve`` + base-prefix check.
We use **secure_filename** because:
  • It's the most-cited CWE-22 fix in OWASP / Flask docs
  • It produces a clear, recognizable surface change
  • A single, well-defined replacement makes the rule deterministic

Rule implemented
----------------
**WrapWithSecureFilename** — finds the user-controlled path argument
to a sink call and wraps it in ``secure_filename(...)``. Specifically:
  • For ``open(p)`` and ``send_file(p)``: wrap the *first arg* directly.
  • For ``open(os.path.join(BASE, user))`` and similar: walk into the
    join-like construction and wrap the last positional argument
    (which by Flask/Django convention is the user-supplied component).
  • For ``send_from_directory(BASE, user)``: wrap the second arg.
"""

from __future__ import annotations

import ast
import random
from copy import deepcopy
from dataclasses import dataclass

from src.red_team.sanitization.base import (
    add_from_import,
    call_attribute_chain,
    register,
)


# ---------------------------------------------------------------------------
# Helper: wrap an expression in `secure_filename(...)`
# ---------------------------------------------------------------------------

def _wrap_in_secure_filename(expr: ast.expr) -> ast.Call:
    return ast.Call(
        func=ast.Name(id="secure_filename", ctx=ast.Load()),
        args=[deepcopy(expr)],
        keywords=[],
    )


def _is_already_wrapped(expr: ast.expr) -> bool:
    return (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Name)
        and expr.func.id == "secure_filename"
    )


def _is_path_join_call(expr: ast.expr) -> bool:
    if not isinstance(expr, ast.Call):
        return False
    chain = call_attribute_chain(expr)
    if not chain:
        return False
    return chain.split(".")[-1] == "join"  # os.path.join, Path.join, posixpath.join, etc.


@dataclass
class WrapWithSecureFilename:
    cwe: str = "CWE-22"
    name: str = "wrap_with_secure_filename"
    transform: str = "wrap_with_secure_filename"

    _SINK_TRAILING = {"open", "send_file", "send_from_directory"}

    def _targets(self, tree: ast.Module) -> list[ast.Call]:
        out = []
        for c in ast.walk(tree):
            if not isinstance(c, ast.Call):
                continue
            chain = call_attribute_chain(c)
            if not chain:
                continue
            if chain.split(".")[-1] not in self._SINK_TRAILING:
                continue
            if not c.args:
                continue
            out.append(c)
        return out

    def _has_wrappable_arg(self, call: ast.Call) -> bool:
        chain = call_attribute_chain(call) or ""
        trailing = chain.split(".")[-1]

        if trailing == "send_from_directory":
            # send_from_directory(base, user_file) — wrap arg[1]
            return len(call.args) >= 2 and not _is_already_wrapped(call.args[1])

        # open / send_file — first arg is either the path Name/Attr or a join call
        first = call.args[0]
        if _is_already_wrapped(first):
            return False
        if _is_path_join_call(first) and first.args:
            return not _is_already_wrapped(first.args[-1])
        return True

    def applies_to(self, tree: ast.Module) -> bool:
        return any(self._has_wrappable_arg(c) for c in self._targets(tree))

    def sanitize(self, tree: ast.Module, rng: random.Random) -> ast.Module:
        new_tree = deepcopy(tree)
        for call in self._targets(new_tree):
            if not self._has_wrappable_arg(call):
                continue
            chain = call_attribute_chain(call) or ""
            trailing = chain.split(".")[-1]

            if trailing == "send_from_directory":
                call.args[1] = _wrap_in_secure_filename(call.args[1])
                continue

            first = call.args[0]
            if _is_path_join_call(first) and first.args:
                # Wrap the LAST positional arg of the join call —
                # this is conventionally the user-supplied component
                first.args[-1] = _wrap_in_secure_filename(first.args[-1])
            else:
                call.args[0] = _wrap_in_secure_filename(first)

        add_from_import(new_tree, "werkzeug.utils", "secure_filename")
        ast.fix_missing_locations(new_tree)
        return new_tree


register(WrapWithSecureFilename())
