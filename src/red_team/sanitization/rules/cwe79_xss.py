"""
cwe79_xss.py — Sanitization rules for CWE-79 (Cross-Site Scripting).

Vulnerable patterns + canonical fixes
-------------------------------------
    Markup(user_input)                      →  escape(user_input)
    flask.Markup(user_input)                →  escape(user_input)
    markupsafe.Markup(user_input)           →  markupsafe.escape(user_input)
    mark_safe(user_input)                   →  escape(user_input)
    django.utils.safestring.mark_safe(s)    →  escape(s)
    render_template_string(template, ctx)   →  render_template_string(escape(template), ctx)
                                             (or: refuse — but escape is the
                                              minimum sanitization most apps use)

The general principle: **wrap the unsafe argument with html.escape**
(or ``markupsafe.escape``) so the output is HTML-encoded, neutralizing
any embedded ``<script>`` or attribute-injection payloads.

Two rules:
  1. ``MarkupToEscape`` — replace the call name (``Markup`` / ``mark_safe``)
     with ``escape``, leaving the args alone.
  2. ``WrapRenderTemplateStringWithEscape`` — keeps
     ``render_template_string`` but wraps its first argument in
     ``escape(...)``.
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
# Rule 1: Markup(...) / mark_safe(...) → escape(...)
# ---------------------------------------------------------------------------

@dataclass
class MarkupToEscape:
    cwe: str = "CWE-79"
    name: str = "markup_to_escape"
    transform: str = "markup_to_escape"

    # We intentionally accept both bare-call and dotted-attribute variants:
    #   Markup(x), mark_safe(x), markupsafe.Markup(x), flask.Markup(x), …
    _UNSAFE_TRAILING = {"Markup", "mark_safe"}

    def _is_target(self, call: ast.Call) -> bool:
        chain = call_attribute_chain(call)
        if not chain:
            return False
        return chain.split(".")[-1] in self._UNSAFE_TRAILING

    def applies_to(self, tree: ast.Module) -> bool:
        return any(
            self._is_target(c)
            for c in ast.walk(tree)
            if isinstance(c, ast.Call)
        )

    def sanitize(self, tree: ast.Module, rng: random.Random) -> ast.Module:
        new_tree = deepcopy(tree)
        targets = [
            c for c in ast.walk(new_tree)
            if isinstance(c, ast.Call) and self._is_target(c)
        ]
        if not targets:
            return new_tree

        for call in targets:
            # Replace the call's func with a bare ``escape`` Name node.
            call.func = ast.Name(id="escape", ctx=ast.Load())

        add_from_import(new_tree, "html", "escape")
        ast.fix_missing_locations(new_tree)
        return new_tree


# ---------------------------------------------------------------------------
# Rule 2: render_template_string(template, ctx) →
#         render_template_string(escape(template), ctx)
# ---------------------------------------------------------------------------

@dataclass
class WrapRenderTemplateStringWithEscape:
    cwe: str = "CWE-79"
    name: str = "wrap_render_template_string_with_escape"
    transform: str = "wrap_render_template_string_with_escape"

    def _is_target(self, call: ast.Call) -> bool:
        chain = call_attribute_chain(call)
        return bool(chain) and chain.split(".")[-1] == "render_template_string"

    def applies_to(self, tree: ast.Module) -> bool:
        return any(
            self._is_target(c)
            for c in ast.walk(tree)
            if isinstance(c, ast.Call) and c.args
        )

    def sanitize(self, tree: ast.Module, rng: random.Random) -> ast.Module:
        new_tree = deepcopy(tree)
        targets = [
            c for c in ast.walk(new_tree)
            if isinstance(c, ast.Call) and self._is_target(c) and c.args
        ]
        if not targets:
            return new_tree

        for call in targets:
            original_first = call.args[0]
            # Skip if already wrapped in escape(...)
            if (
                isinstance(original_first, ast.Call)
                and isinstance(original_first.func, ast.Name)
                and original_first.func.id == "escape"
            ):
                continue
            call.args[0] = ast.Call(
                func=ast.Name(id="escape", ctx=ast.Load()),
                args=[original_first],
                keywords=[],
            )

        add_from_import(new_tree, "html", "escape")
        ast.fix_missing_locations(new_tree)
        return new_tree


register(MarkupToEscape())
register(WrapRenderTemplateStringWithEscape())
