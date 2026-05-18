"""
cwe89_sqli.py — Sanitization rule for CWE-89 (SQL Injection).

Vulnerable patterns
-------------------
    cursor.execute(f"SELECT * FROM x WHERE id = {uid}")
    cursor.execute("SELECT * FROM x WHERE id = " + str(uid))
    cursor.execute("SELECT * FROM x WHERE id = %s" % uid)
    cursor.execute("SELECT * FROM x WHERE id = {}".format(uid))

Sanitized form
--------------
    cursor.execute("SELECT * FROM x WHERE id = ?", (uid,))

We use the **DB-API ``?`` placeholder** (which is sqlite3, oracle's
cx_Oracle in some modes, and pyodbc) — the most language-portable
parameterized syntax in Python's DB-API 2.0. Our goal is *surface
distinguishability* (the model needs to learn that parameterized queries
look different from interpolated ones), so picking one specific marker
is fine — we don't have to perfectly track each driver's preferred
placeholder.

Rules implemented
-----------------
1. **FStringExecuteToParameterized** — converts ``execute(f"... {x} ...")``
   into ``execute("... ? ...", (x,))``. Each ``FormattedValue`` becomes
   one positional parameter.

2. **PercentExecuteToParameterized** — converts
   ``execute("... %s ..." % (a, b))`` into
   ``execute("... %s ...", (a, b))`` — same string, but the args
   tuple is now passed as a *separate* argument to ``execute`` rather
   than being interpolated by ``%`` first. This is exactly the pattern
   most secure DB-API code uses.

We deliberately keep these as the only two cases. ``+``-concatenated
SQL is too varied to handle deterministically (the concatenation can
mix in ``str(...)`` casts, conditionals, etc.); we let the
mutation+rename mutators handle those cases lexically.
"""

from __future__ import annotations

import ast
import random
from copy import deepcopy
from dataclasses import dataclass

from src.red_team.sanitization.base import (
    call_attribute_chain,
    register,
)


_EXECUTE_TRAILING = {"execute", "executemany", "executescript"}


def _is_execute_call(call: ast.Call) -> bool:
    chain = call_attribute_chain(call)
    if not chain:
        return False
    return chain.split(".")[-1] in _EXECUTE_TRAILING


# ---------------------------------------------------------------------------
# Rule 1: f-string → parameterized
# ---------------------------------------------------------------------------

@dataclass
class FStringExecuteToParameterized:
    cwe: str = "CWE-89"
    name: str = "fstring_execute_to_parameterized"
    transform: str = "fstring_execute_to_parameterized"

    def _vulnerable_calls(self, tree: ast.Module) -> list[ast.Call]:
        out = []
        for c in ast.walk(tree):
            if not isinstance(c, ast.Call):
                continue
            if not _is_execute_call(c):
                continue
            if not c.args:
                continue
            if isinstance(c.args[0], ast.JoinedStr):
                # Has at least one FormattedValue → vulnerable
                if any(isinstance(v, ast.FormattedValue) for v in c.args[0].values):
                    out.append(c)
        return out

    def applies_to(self, tree: ast.Module) -> bool:
        return bool(self._vulnerable_calls(tree))

    def sanitize(self, tree: ast.Module, rng: random.Random) -> ast.Module:
        new_tree = deepcopy(tree)
        for call in self._vulnerable_calls(new_tree):
            joined = call.args[0]
            literal_parts: list[str] = []
            params: list[ast.expr] = []

            for v in joined.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    literal_parts.append(v.value)
                elif isinstance(v, ast.FormattedValue):
                    literal_parts.append("?")
                    params.append(deepcopy(v.value))
                else:
                    # Unknown sub-node — leave the call alone
                    return new_tree

            new_query = ast.Constant(value="".join(literal_parts))
            new_args = [new_query]

            # If the original call had additional positional args (some DB
            # APIs accept (sql, params) already), preserve them after our
            # injected tuple. But for typical execute(sql) signatures this
            # branch isn't hit.
            if params:
                new_args.append(
                    ast.Tuple(elts=params, ctx=ast.Load())
                )
            new_args.extend(deepcopy(call.args[1:]))
            call.args = new_args

        ast.fix_missing_locations(new_tree)
        return new_tree


# ---------------------------------------------------------------------------
# Rule 2: % interpolation → parameterized (move the tuple to second arg)
# ---------------------------------------------------------------------------

@dataclass
class PercentExecuteToParameterized:
    cwe: str = "CWE-89"
    name: str = "percent_execute_to_parameterized"
    transform: str = "percent_execute_to_parameterized"

    def _vulnerable_calls(self, tree: ast.Module) -> list[ast.Call]:
        out = []
        for c in ast.walk(tree):
            if not isinstance(c, ast.Call):
                continue
            if not _is_execute_call(c):
                continue
            if not c.args:
                continue
            arg0 = c.args[0]
            if (
                isinstance(arg0, ast.BinOp)
                and isinstance(arg0.op, ast.Mod)
                and isinstance(arg0.left, ast.Constant)
                and isinstance(arg0.left.value, str)
            ):
                out.append(c)
        return out

    def applies_to(self, tree: ast.Module) -> bool:
        return bool(self._vulnerable_calls(tree))

    def sanitize(self, tree: ast.Module, rng: random.Random) -> ast.Module:
        new_tree = deepcopy(tree)
        for call in self._vulnerable_calls(new_tree):
            binop = call.args[0]  # "..." % (a, b, ...)
            sql_string = binop.left  # the Constant(str)
            params_expr = binop.right  # tuple, single value, or %(name)s dict

            # Build new args: [sql_string, params]
            # If params_expr is a single value not yet a tuple, wrap it
            if isinstance(params_expr, ast.Tuple):
                new_params = params_expr
            else:
                new_params = ast.Tuple(elts=[deepcopy(params_expr)], ctx=ast.Load())

            new_args = [deepcopy(sql_string), new_params]
            new_args.extend(deepcopy(call.args[1:]))
            call.args = new_args

        ast.fix_missing_locations(new_tree)
        return new_tree


register(FStringExecuteToParameterized())
register(PercentExecuteToParameterized())
