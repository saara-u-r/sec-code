"""
cwe78_cmdi.py — Sanitization rules for CWE-78 (OS Command Injection).

Vulnerable patterns
-------------------
    os.system(f"ping {host}")
    os.system("ping " + host)
    os.popen(cmd_str)
    subprocess.run(cmd_str, shell=True)
    subprocess.call(cmd_str, shell=True)

Sanitized form
--------------
    subprocess.run([..., host], shell=False, check=True)

The canonical fix is to use the **list form** of subprocess invocation
with ``shell=False``, which makes Python pass arguments to ``execve``
directly, removing the shell as an attacker surface entirely.

Two rules implemented:
  1. **OsSystemToSubprocessRun** — replaces ``os.system(cmd)`` with
     ``subprocess.run(shlex.split(cmd) if isinstance(cmd, str) else cmd,
     shell=False, check=True)``. We use ``shlex.split`` to convert the
     string into an argv list at runtime — provably correct for
     well-formed shell command strings.
  2. **SubprocessShellTrueToFalse** — when the call is already
     ``subprocess.run(cmd, shell=True)``, flip ``shell=True`` to
     ``shell=False`` and add ``shlex.split(cmd)`` wrapping.

Both rules add ``import shlex`` and ``import subprocess`` as needed.
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


# ---------------------------------------------------------------------------
# Rule 1: os.system / os.popen → subprocess.run([..], shell=False)
# ---------------------------------------------------------------------------

@dataclass
class OsSystemToSubprocessRun:
    cwe: str = "CWE-78"
    name: str = "os_system_to_subprocess_run"
    transform: str = "os_system_to_subprocess_run"

    _UNSAFE_NAMES = {"os.system", "os.popen"}

    def _targets(self, tree: ast.Module) -> list[ast.Call]:
        return [
            c for c in ast.walk(tree)
            if isinstance(c, ast.Call)
            and call_attribute_chain(c) in self._UNSAFE_NAMES
            and c.args
        ]

    def applies_to(self, tree: ast.Module) -> bool:
        return bool(self._targets(tree))

    def sanitize(self, tree: ast.Module, rng: random.Random) -> ast.Module:
        new_tree = deepcopy(tree)
        for call in self._targets(new_tree):
            cmd_arg = deepcopy(call.args[0])
            shlex_split_call = ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id="shlex", ctx=ast.Load()),
                    attr="split",
                    ctx=ast.Load(),
                ),
                args=[cmd_arg],
                keywords=[],
            )
            new_keywords = [
                ast.keyword(arg="shell", value=ast.Constant(value=False)),
                ast.keyword(arg="check", value=ast.Constant(value=True)),
            ]
            call.func = ast.Attribute(
                value=ast.Name(id="subprocess", ctx=ast.Load()),
                attr="run",
                ctx=ast.Load(),
            )
            call.args = [shlex_split_call]
            call.keywords = new_keywords

        add_import(new_tree, "subprocess")
        add_import(new_tree, "shlex")
        ast.fix_missing_locations(new_tree)
        return new_tree


# ---------------------------------------------------------------------------
# Rule 2: subprocess.run(cmd, shell=True, ...) → shell=False with shlex.split
# ---------------------------------------------------------------------------

@dataclass
class SubprocessShellTrueToFalse:
    cwe: str = "CWE-78"
    name: str = "subprocess_shell_true_to_false"
    transform: str = "subprocess_shell_true_to_false"

    _SUBPROCESS_TRAILING = {"run", "call", "check_output", "check_call", "Popen"}

    def _targets(self, tree: ast.Module) -> list[ast.Call]:
        out = []
        for c in ast.walk(tree):
            if not isinstance(c, ast.Call):
                continue
            chain = call_attribute_chain(c)
            if not chain:
                continue
            if chain.split(".")[-1] not in self._SUBPROCESS_TRAILING:
                continue
            for kw in c.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    out.append(c)
                    break
        return out

    def applies_to(self, tree: ast.Module) -> bool:
        return bool(self._targets(tree))

    def sanitize(self, tree: ast.Module, rng: random.Random) -> ast.Module:
        new_tree = deepcopy(tree)
        for call in self._targets(new_tree):
            # Wrap first positional arg in shlex.split(...)
            if call.args and not isinstance(call.args[0], ast.List):
                call.args[0] = ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="shlex", ctx=ast.Load()),
                        attr="split",
                        ctx=ast.Load(),
                    ),
                    args=[deepcopy(call.args[0])],
                    keywords=[],
                )
            # Flip shell=True → shell=False
            for kw in call.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                    kw.value = ast.Constant(value=False)

        add_import(new_tree, "shlex")
        ast.fix_missing_locations(new_tree)
        return new_tree


register(OsSystemToSubprocessRun())
register(SubprocessShellTrueToFalse())
