"""
red_team/sanitization/base.py — Hard-negative generation infrastructure.

A *sanitization rule* takes a vulnerable Python function and produces
a safe twin: same surface structure, same data flow positions, same
sink names — but the dangerous operation is replaced with its canonical
secure equivalent.

Hard negatives generated this way are the single most important
adversarial test for our model:
  • Vulnerable: ``cursor.execute(f"SELECT * FROM x WHERE id = {uid}")``
  • Hard-neg:   ``cursor.execute("SELECT * FROM x WHERE id = ?", (uid,))``

A pattern-matching model that sees ``cursor.execute`` near user input
and shouts "SQLi!" will FAIL on the hard negative — which is exactly
what we want to catch.

This module defines:
  • The ``SanitizationRule`` Protocol
  • ``SanitizationResult`` — structured outcome
  • Helpers for adding imports, locating call sinks, replacing nodes
  • A registry that maps CWE → list of applicable rules
  • ``sanitize`` — entry point: takes (source, cwe) → (safe_twin, result)
"""

from __future__ import annotations

import ast
import logging
import random
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class SanitizationResult:
    """Structured outcome of one rule's invocation."""

    success: bool
    source: str = ""
    rule: str = ""
    cwe: str = ""
    transform: str = ""        # e.g. "eval_to_literal_eval"
    reason: str = ""           # human-readable on failure
    metadata: dict = field(default_factory=dict)

    @classmethod
    def ok(cls, rule: str, cwe: str, transform: str, source: str, **metadata) -> "SanitizationResult":
        return cls(
            success=True, source=source, rule=rule, cwe=cwe,
            transform=transform, metadata=metadata,
        )

    @classmethod
    def skip(cls, rule: str, cwe: str, source: str, reason: str) -> "SanitizationResult":
        return cls(success=False, source=source, rule=rule, cwe=cwe, reason=reason)

    @classmethod
    def fail(cls, rule: str, cwe: str, source: str, reason: str) -> "SanitizationResult":
        return cls(success=False, source=source, rule=rule, cwe=cwe, reason=reason)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class SanitizationRule(Protocol):
    """A CWE-specific sanitization transform."""

    cwe: str               # e.g. "CWE-94"
    name: str              # e.g. "eval_to_literal_eval"
    transform: str         # human-readable transform name (== name typically)

    def applies_to(self, tree: ast.Module) -> bool:
        """True if this rule has a vulnerable pattern to sanitize in `tree`."""
        ...

    def sanitize(self, tree: ast.Module, rng: random.Random) -> ast.Module:
        """Return a sanitized copy of `tree`. May raise — caller catches."""
        ...


# ---------------------------------------------------------------------------
# AST utility helpers shared by all rules
# ---------------------------------------------------------------------------

def call_attribute_chain(call: ast.Call) -> str | None:
    """
    For a ``Call`` node return its dotted target chain or None.

    Examples:
      eval(x)              → "eval"
      yaml.load(x)         → "yaml.load"
      cursor.execute(q)    → "cursor.execute"
      pickle.loads(b)      → "pickle.loads"
      obj.foo.bar(x)       → "obj.foo.bar"
    """
    parts: list[str] = []
    node: ast.AST | None = call.func
    while node is not None:
        if isinstance(node, ast.Name):
            parts.append(node.id)
            break
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        else:
            return None
    if not parts:
        return None
    return ".".join(reversed(parts))


def has_import(tree: ast.Module, module_name: str, alias: str | None = None) -> bool:
    """
    True if `tree` imports `module_name`. If `alias` is given, the alias
    must match (or the module must be imported under that alias via
    ``import x as alias``).
    """
    target_alias = alias or module_name.split(".")[0]
    for node in tree.body:
        if isinstance(node, ast.Import):
            for n in node.names:
                if n.name == module_name and (n.asname or n.name) == target_alias:
                    return True
                if n.name == module_name and alias is None:
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module == module_name:
                return True
            # Sometimes we want to know if a *submodule* alias matches —
            # e.g. `from os.path import join` → has_import("os.path") is True.
    return False


def has_from_import(tree: ast.Module, module: str, name: str) -> bool:
    """True if `tree` has ``from <module> import <name>``."""
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == module:
            for n in node.names:
                if n.name == name:
                    return True
    return False


def add_import(tree: ast.Module, module: str) -> None:
    """Add ``import <module>`` to the top of `tree` if not already present."""
    if has_import(tree, module):
        return
    new_import = ast.Import(names=[ast.alias(name=module, asname=None)])
    _insert_at_top(tree, new_import)


def add_from_import(tree: ast.Module, module: str, name: str) -> None:
    """Add ``from <module> import <name>`` if not already present."""
    if has_from_import(tree, module, name):
        return
    new_import = ast.ImportFrom(
        module=module, names=[ast.alias(name=name, asname=None)], level=0,
    )
    _insert_at_top(tree, new_import)


def _insert_at_top(tree: ast.Module, stmt: ast.stmt) -> None:
    """
    Insert `stmt` at the top of `tree.body`, but after the module
    docstring (if any) and after any existing leading ``from __future__
    import …`` statements (which Python requires to come first).
    """
    insert_at = 0
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ):
        insert_at = 1
    while (
        insert_at < len(tree.body)
        and isinstance(tree.body[insert_at], ast.ImportFrom)
        and tree.body[insert_at].module == "__future__"
    ):
        insert_at += 1
    tree.body.insert(insert_at, stmt)
    ast.fix_missing_locations(tree)


def find_calls(tree: ast.AST, target_chain: str) -> list[ast.Call]:
    """
    Return all ``Call`` nodes whose attribute chain matches `target_chain`.

    Multiple matching strategies:
      • Exact match: ``target_chain == "yaml.load"`` matches only that.
      • Trailing match (no dot in target): ``target_chain == "loads"``
        matches ``pickle.loads``, ``json.loads``, ``yaml.loads`` etc.
    """
    out: list[ast.Call] = []
    is_trailing_only = "." not in target_chain
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        chain = call_attribute_chain(node)
        if chain is None:
            continue
        if is_trailing_only:
            if chain.split(".")[-1] == target_chain:
                out.append(node)
        else:
            if chain == target_chain:
                out.append(node)
    return out


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, list[SanitizationRule]] = {}


def register(rule: SanitizationRule) -> SanitizationRule:
    """Register a sanitization rule under its CWE."""
    if not getattr(rule, "cwe", None):
        raise ValueError("Rule must have `cwe` attribute")
    if not getattr(rule, "name", None):
        raise ValueError("Rule must have `name` attribute")
    _REGISTRY.setdefault(rule.cwe, []).append(rule)
    return rule


def rules_for(cwe: str) -> list[SanitizationRule]:
    return list(_REGISTRY.get(cwe, []))


def all_rules() -> dict[str, list[SanitizationRule]]:
    return {cwe: list(rules) for cwe, rules in _REGISTRY.items()}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def sanitize(
    source: str,
    cwe: str,
    rng: random.Random | None = None,
    format_output: bool = True,
) -> tuple[str, SanitizationResult]:
    """
    Take a vulnerable function (`source`) and a target CWE; return a
    sanitized hard-negative version.

    Returns
    -------
    (safe_twin_source, SanitizationResult)
        On success, ``safe_twin_source`` differs from input.
        On skip/fail, ``safe_twin_source == source``.
    """
    from src.red_team.base import unparse_clean

    rng = rng or random.Random()

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return source, SanitizationResult.fail(
            "sanitize", cwe, source, f"input did not parse: {e}",
        )

    rules = rules_for(cwe)
    if not rules:
        return source, SanitizationResult.skip(
            "sanitize", cwe, source, f"no rules registered for {cwe}",
        )

    applicable = [r for r in rules if r.applies_to(tree)]
    if not applicable:
        return source, SanitizationResult.skip(
            "sanitize", cwe, source, "no applicable rule found for this code",
        )

    rule = rng.choice(applicable)
    try:
        sanitized = rule.sanitize(tree, rng)
    except Exception as e:
        return source, SanitizationResult.fail(
            rule.name, cwe, source, f"raised: {type(e).__name__}: {e}",
        )

    try:
        out = unparse_clean(sanitized, format_with_black=format_output)
        ast.parse(out)  # round-trip check
    except Exception as e:
        return source, SanitizationResult.fail(
            rule.name, cwe, source, f"round-trip: {e}",
        )

    if out.strip() == source.strip():
        return source, SanitizationResult.skip(
            rule.name, cwe, source, "rule produced identical output",
        )

    return out, SanitizationResult.ok(
        rule=rule.name, cwe=cwe, transform=rule.transform, source=out,
    )
