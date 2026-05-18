"""
cwe94_codei.py — Sanitization rule for CWE-94 (Code Injection).

Vulnerable pattern
------------------
    eval(user_expression)
    exec(user_expression)
    compile(user_expression, ...)

Sanitized form
--------------
    ast.literal_eval(user_expression)

``ast.literal_eval`` is the canonical secure replacement for ``eval``:
it only accepts Python literal *expressions* (numbers, strings, tuples,
lists, dicts, booleans, ``None``) and refuses anything else, including
function calls. This is the OWASP-recommended fix.

The rule:
  • Picks the first occurrence of ``eval(...)`` or ``exec(...)`` as a
    call node
  • Replaces it with ``ast.literal_eval(...)`` (preserving the original
    arguments)
  • Adds ``import ast`` at the top of the module if not already present
"""

from __future__ import annotations

import ast
import random
from copy import deepcopy
from dataclasses import dataclass

from src.red_team.sanitization.base import (
    add_import,
    call_attribute_chain,
    register,
)


@dataclass
class EvalToLiteralEval:
    cwe: str = "CWE-94"
    name: str = "eval_to_literal_eval"
    transform: str = "eval_to_literal_eval"

    def applies_to(self, tree: ast.Module) -> bool:
        return any(
            call_attribute_chain(c) in {"eval", "exec"}
            for c in ast.walk(tree)
            if isinstance(c, ast.Call)
        )

    def sanitize(self, tree: ast.Module, rng: random.Random) -> ast.Module:
        new_tree = deepcopy(tree)
        targets = [
            c for c in ast.walk(new_tree)
            if isinstance(c, ast.Call) and call_attribute_chain(c) in {"eval", "exec"}
        ]
        if not targets:
            return new_tree

        # Replace the first occurrence
        target = targets[0]
        target.func = ast.Attribute(
            value=ast.Name(id="ast", ctx=ast.Load()),
            attr="literal_eval",
            ctx=ast.Load(),
        )

        add_import(new_tree, "ast")
        ast.fix_missing_locations(new_tree)
        return new_tree


register(EvalToLiteralEval())
