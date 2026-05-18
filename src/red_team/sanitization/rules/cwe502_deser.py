"""
cwe502_deser.py — Sanitization rules for CWE-502 (Insecure Deserialization).

Vulnerable patterns + canonical fixes
-------------------------------------
    pickle.loads(blob)         →  json.loads(blob.decode() if isinstance(blob, bytes) else blob)
    cPickle.loads(blob)        →  json.loads(...)
    yaml.load(s)               →  yaml.safe_load(s)
    yaml.load(s, Loader=...)   →  yaml.safe_load(s)
    yaml.unsafe_load(s)        →  yaml.safe_load(s)
    marshal.loads(blob)        →  json.loads(...)

Two rules implemented:
  1. ``YamlLoadToSafeLoad`` — yaml.load → yaml.safe_load (preserves API)
  2. ``PickleToJsonLoads`` — pickle/marshal/cPickle.loads → json.loads
     (changes serialization format but is the canonical secure fix —
     see Python docs warnings on pickle, OWASP cheat sheet)

Note: in real codebases, "fixing" pickle properly often means switching
serialization formats entirely. We pick ``json.loads`` because it's the
single most common documented replacement and because the surface
difference (``pickle.loads`` → ``json.loads``) is exactly the kind of
*lexical* change that defeats keyword-grepping detectors.
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
# Rule 1: yaml.load → yaml.safe_load
# ---------------------------------------------------------------------------

@dataclass
class YamlLoadToSafeLoad:
    cwe: str = "CWE-502"
    name: str = "yaml_load_to_safe_load"
    transform: str = "yaml_load_to_safe_load"

    _UNSAFE_NAMES = {"yaml.load", "yaml.unsafe_load", "yaml.full_load"}

    def applies_to(self, tree: ast.Module) -> bool:
        return any(
            call_attribute_chain(c) in self._UNSAFE_NAMES
            for c in ast.walk(tree)
            if isinstance(c, ast.Call)
        )

    def sanitize(self, tree: ast.Module, rng: random.Random) -> ast.Module:
        new_tree = deepcopy(tree)
        targets = [
            c for c in ast.walk(new_tree)
            if isinstance(c, ast.Call)
            and call_attribute_chain(c) in self._UNSAFE_NAMES
        ]
        if not targets:
            return new_tree

        for call in targets:
            # Rewrite cursor.func to a yaml.safe_load attribute
            call.func = ast.Attribute(
                value=ast.Name(id="yaml", ctx=ast.Load()),
                attr="safe_load",
                ctx=ast.Load(),
            )
            # Drop any Loader= keyword (no longer applicable to safe_load)
            call.keywords = [kw for kw in call.keywords if kw.arg != "Loader"]

        ast.fix_missing_locations(new_tree)
        return new_tree


# ---------------------------------------------------------------------------
# Rule 2: pickle/marshal/cPickle.loads → json.loads
# ---------------------------------------------------------------------------

@dataclass
class PickleToJsonLoads:
    cwe: str = "CWE-502"
    name: str = "pickle_to_json_loads"
    transform: str = "pickle_to_json_loads"

    _UNSAFE_NAMES = {
        "pickle.loads", "pickle.load",
        "cPickle.loads", "cPickle.load",
        "marshal.loads", "marshal.load",
        "dill.loads", "dill.load",
    }

    def applies_to(self, tree: ast.Module) -> bool:
        return any(
            call_attribute_chain(c) in self._UNSAFE_NAMES
            for c in ast.walk(tree)
            if isinstance(c, ast.Call)
        )

    def sanitize(self, tree: ast.Module, rng: random.Random) -> ast.Module:
        new_tree = deepcopy(tree)
        targets = [
            c for c in ast.walk(new_tree)
            if isinstance(c, ast.Call)
            and call_attribute_chain(c) in self._UNSAFE_NAMES
        ]
        if not targets:
            return new_tree

        for call in targets:
            chain = call_attribute_chain(call)
            # `.load()` reads from a file object; `.loads()` reads from str/bytes.
            # json has the same naming convention, so a direct attr swap works.
            attr = chain.split(".")[-1] if chain else "loads"
            call.func = ast.Attribute(
                value=ast.Name(id="json", ctx=ast.Load()),
                attr=attr,
                ctx=ast.Load(),
            )

        add_import(new_tree, "json")
        ast.fix_missing_locations(new_tree)
        return new_tree


register(YamlLoadToSafeLoad())
register(PickleToJsonLoads())
