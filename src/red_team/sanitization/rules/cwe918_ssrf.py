"""
cwe918_ssrf.py — Sanitization rule for CWE-918 (Server-Side Request Forgery).

Vulnerable patterns
-------------------
    requests.get(user_url)
    requests.post(user_url, ...)
    httpx.get(user_url)
    aiohttp.ClientSession().get(user_url)
    urllib.request.urlopen(user_url)

The vulnerability: an attacker passes ``http://169.254.169.254/...`` (AWS
metadata) or ``http://127.0.0.1:internal_admin/`` and the server
faithfully relays the request, leaking internal service data.

Sanitized form
--------------
The canonical fix is **URL allowlist validation** before the call —
parse the URL, verify the host is in an approved set, refuse otherwise.
Different shops do this with different libraries; we pick a
recognizable, single-line transformation that emits a canonical
validation pattern using ``urllib.parse.urlparse``:

Before::

    return requests.get(user_url)

After::

    from urllib.parse import urlparse

    _parsed = urlparse(user_url)
    if _parsed.netloc not in ALLOWED_HOSTS:
        raise ValueError("URL host not in allowlist")
    return requests.get(user_url)

The exact set ``ALLOWED_HOSTS`` is left as a sentinel name — real
deployments configure it. Our goal is *surface differentiation* (the
sanitized version contains a guard pattern that the vulnerable version
lacks), so the sentinel is fine.

Rule implemented
----------------
**InsertAllowlistGuard** — for each HTTP-fetch sink call inside a
function, insert the allowlist-check statements immediately before
the statement that contains the call. Then add the
``from urllib.parse import urlparse`` import.
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


_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "request"}
_URL_FETCH_TRAILING = _HTTP_METHODS | {"urlopen", "Request"}


def _is_http_fetch(call: ast.Call) -> bool:
    chain = call_attribute_chain(call) or ""
    trailing = chain.split(".")[-1]
    if trailing not in _URL_FETCH_TRAILING:
        return False
    return bool(call.args)


def _build_guard_block(url_expr: ast.expr) -> list[ast.stmt]:
    """
    Construct:

        _parsed = urlparse(<url_expr>)
        if _parsed.netloc not in ALLOWED_HOSTS:
            raise ValueError('URL host not in allowlist')
    """
    parse_assign = ast.Assign(
        targets=[ast.Name(id="_parsed", ctx=ast.Store())],
        value=ast.Call(
            func=ast.Name(id="urlparse", ctx=ast.Load()),
            args=[deepcopy(url_expr)],
            keywords=[],
        ),
    )
    guard = ast.If(
        test=ast.Compare(
            left=ast.Attribute(
                value=ast.Name(id="_parsed", ctx=ast.Load()),
                attr="netloc",
                ctx=ast.Load(),
            ),
            ops=[ast.NotIn()],
            comparators=[ast.Name(id="ALLOWED_HOSTS", ctx=ast.Load())],
        ),
        body=[
            ast.Raise(
                exc=ast.Call(
                    func=ast.Name(id="ValueError", ctx=ast.Load()),
                    args=[ast.Constant(value="URL host not in allowlist")],
                    keywords=[],
                ),
                cause=None,
            ),
        ],
        orelse=[],
    )
    return [parse_assign, guard]


def _statement_containing(call: ast.Call, fn_body: list[ast.stmt]) -> int | None:
    """Return the body index of the statement that (transitively) contains `call`."""
    for i, stmt in enumerate(fn_body):
        for node in ast.walk(stmt):
            if node is call:
                return i
    return None


@dataclass
class InsertAllowlistGuard:
    cwe: str = "CWE-918"
    name: str = "insert_url_allowlist_guard"
    transform: str = "insert_url_allowlist_guard"

    def _functions_with_targets(
        self, tree: ast.Module
    ) -> list[tuple[ast.FunctionDef, list[ast.Call]]]:
        out = []
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = [
                c for stmt in fn.body for c in ast.walk(stmt)
                if isinstance(c, ast.Call) and _is_http_fetch(c)
            ]
            if calls:
                out.append((fn, calls))
        return out

    def _function_already_guarded(self, fn: ast.FunctionDef) -> bool:
        """Heuristic: skip if the function already contains an `urlparse` call."""
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                chain = call_attribute_chain(node) or ""
                if chain.split(".")[-1] == "urlparse":
                    return True
        return False

    def applies_to(self, tree: ast.Module) -> bool:
        for fn, _ in self._functions_with_targets(tree):
            if not self._function_already_guarded(fn):
                return True
        return False

    def sanitize(self, tree: ast.Module, rng: random.Random) -> ast.Module:
        new_tree = deepcopy(tree)
        modified = False

        for fn, calls in self._functions_with_targets(new_tree):
            if self._function_already_guarded(fn):
                continue

            # Pick the first applicable call to guard (one guard is enough
            # to make the function look "sanitized")
            target_call = calls[0]
            url_expr = target_call.args[0]

            # Find the body index of the statement containing this call
            stmt_idx = _statement_containing(target_call, fn.body)
            if stmt_idx is None:
                continue

            guard_block = _build_guard_block(url_expr)
            fn.body[stmt_idx:stmt_idx] = guard_block
            modified = True

        if modified:
            add_from_import(new_tree, "urllib.parse", "urlparse")

        ast.fix_missing_locations(new_tree)
        return new_tree


register(InsertAllowlistGuard())
