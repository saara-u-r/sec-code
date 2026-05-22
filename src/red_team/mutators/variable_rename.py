"""
red_team/mutators/variable_rename.py — Mutator M1: Variable Rename.

Replaces user-defined local identifiers with semantically-equivalent
synonyms drawn from a curated dictionary. Preserves runtime behavior
because we only touch names that resolve to the function's local scope.

Why this mutator: a model that learned ``user_id appears inside an
execute(f"...") → predict CWE-89`` fails after we rename ``user_id`` to
``account_pk`` because the surface token disappeared. A model that learned
``untrusted-input flows into execute() via f-string interpolation`` is
unaffected by the rename — it's tracking dataflow, not specific names.

Rename rules
------------
Renameable (local to the function we're mutating):
  * Function parameters (positional, keyword-only, *args, **kwargs)
  * Local assignments (``x = ...``, ``x, y = ...``)
  * Augmented and annotated assignments (``x += 1``, ``x: int = 1``)
  * ``for x in ...`` loop variables
  * Comprehension targets (``[x for x in ...]``)
  * ``with ... as x``, ``except ... as x``
  * Walrus targets (``(x := expr)``)

NOT renameable (would change semantics):
  * Free variables (referenced but not defined locally)
  * Names declared ``global x`` or ``nonlocal x``
  * Imported names (``import os``, ``from os import path``)
  * Attribute names (``obj.foo`` — ``foo`` is an attribute, not a name)
  * Built-ins (``len``, ``range``, ``print``, ``eval``, etc.)
  * Names inside string literals (those are data, not code)
  * The function's own name (would break recursion)
  * Names that match arg names of *nested* functions (we only rename
    in the outer function's scope)
"""

from __future__ import annotations

import ast
import builtins
import keyword
import random
from copy import deepcopy
from dataclasses import dataclass

from src.red_team.base import register


# ---------------------------------------------------------------------------
# Synonym dictionary — curated mappings preserving meaning + readability
# ---------------------------------------------------------------------------

SYNONYMS: dict[str, list[str]] = {
    # Common entity nouns
    "user":     ["account", "customer", "member", "person"],
    "users":    ["accounts", "customers", "members"],
    "id":       ["pk", "identifier", "key"],
    "pk":       ["id", "identifier"],
    "uid":      ["user_pk", "account_id", "member_id"],
    "name":     ["label", "title", "ident"],
    "data":     ["payload", "content", "body"],
    "value":    ["val", "datum", "entry"],
    "item":     ["element", "entry", "record"],
    "items":    ["elements", "entries", "records"],
    "result":   ["resp", "outcome", "ret"],
    "results":  ["responses", "outcomes", "outputs"],
    "response": ["reply", "resp", "output"],
    "request":  ["req", "incoming", "petition"],
    "url":      ["link", "uri", "endpoint"],
    "path":     ["fpath", "filepath", "loc"],
    "filepath": ["path", "fpath", "loc"],
    "filename": ["fname", "file_name", "fpath"],
    "file":     ["fobj", "fp", "stream"],
    "query":    ["sql", "stmt", "raw_sql"],
    "sql":      ["query", "stmt", "raw_sql"],
    "stmt":     ["statement", "query", "sql"],
    "cmd":      ["command", "shell_cmd", "instr"],
    "host":     ["server", "node", "addr"],
    "port":     ["socket_port", "tcp_port"],
    "msg":      ["message", "text", "note"],
    "message":  ["msg", "text", "note"],
    "text":     ["content", "body", "msg"],
    "content":  ["body", "payload", "data"],
    "blob":     ["raw", "buffer", "chunk"],
    "key":      ["lookup", "ident", "pk"],
    "token":    ["auth_tok", "secret", "credential"],
    "config":   ["cfg", "settings", "options"],
    "options":  ["opts", "settings", "config"],
    "params":   ["args", "kwargs_in", "p_dict"],
    "args":     ["params", "arguments", "argv"],
    "kwargs":   ["keyword_args", "named_args", "kw_in"],
    "session":  ["sess", "auth_sess", "user_sess"],
    "conn":     ["connection", "db_conn", "handle"],
    "cursor":   ["cur", "db_cursor"],   # only renames LOCAL `cursor`, not module-level
    "row":      ["record", "tuple_in"],
    "rows":     ["records", "result_set"],
    "limit":    ["max_n", "ceil", "cap"],
    "offset":   ["skip", "start_at"],
    "count":    ["n", "total", "amt"],
    "total":    ["sum_total", "grand_total", "agg"],
    "size":     ["n", "length", "extent"],
    "length":   ["size", "n", "len_of"],
    "index":    ["pos", "i_at", "loc"],
    "i":        ["idx", "k", "n_iter"],
    "j":        ["jdx", "l", "m_iter"],
    "k":        ["kdx", "p"],
    "x":        ["x_val", "v", "elem"],
    "y":        ["y_val", "w", "other"],
    "n":        ["count", "total_n", "amt"],
    "obj":      ["instance", "thing", "subject"],
    "fn":       ["func", "callback", "handler"],
    "func":     ["fn", "callback", "handler"],
    "callback": ["cb", "handler", "fn"],
    "handler":  ["fn", "callback", "endpoint_fn"],
    "err":      ["error", "exc", "issue"],
    "error":    ["err", "exc", "issue"],
    "exc":      ["exception", "err", "raised"],
    "ret":      ["result", "outcome", "ret_val"],
    "ok":       ["success", "is_ok", "passed"],
    "success":  ["ok", "is_ok", "passed"],
    # Verb-fronted parameter names
    "get":      ["fetch", "retrieve", "lookup"],
    "set":      ["assign", "store", "put"],
    "add":      ["insert", "register", "append"],
    "remove":   ["delete", "drop", "discard"],
    "delete":   ["remove", "drop", "discard"],
    "create":   ["make", "build", "instantiate"],
    "update":   ["modify", "alter", "patch"],
    "load":     ["read", "fetch", "import_from"],
    "save":     ["write", "persist", "store"],
}


def _pick_synonym(original: str, rng: random.Random) -> str:
    """Pick a synonym for `original` from the dictionary, with snake_case fallback."""
    if original in SYNONYMS:
        return rng.choice(SYNONYMS[original])
    # Try lowercase variants
    lower = original.lower()
    if lower in SYNONYMS and lower != original:
        # Preserve case style of the original (e.g. UserID → AccountId)
        return rng.choice(SYNONYMS[lower])
    # Fallback: deterministic anonymized name. SHA-256 instead of Python's
    # built-in hash() because hash() is randomized per process via
    # PYTHONHASHSEED, which would break byte-identical reruns of
    # build_mutator_variants.py.
    import hashlib
    digest = hashlib.sha256(original.encode("utf-8")).digest()
    return f"var_{int.from_bytes(digest[:4], 'big') % 10000}"


# ---------------------------------------------------------------------------
# Scope analyzer
# ---------------------------------------------------------------------------

# Names we never rename — Python builtins + keywords + special function dunders
_BUILTINS: set[str] = set(dir(builtins))
_KEYWORDS: set[str] = set(keyword.kwlist) | set(keyword.softkwlist)
_NEVER_RENAME: set[str] = _BUILTINS | _KEYWORDS | {
    # Common framework-supplied names that look local but are conventionally
    # "free" inside route handlers and class methods. Renaming these would
    # silently change behavior in many real samples.
    "self", "cls",
    "__name__", "__file__", "__doc__", "__init__", "__class__",
    "Ellipsis", "NotImplemented", "True", "False", "None",
}


def _collect_local_names(fn: ast.FunctionDef) -> set[str]:
    """
    Return the set of identifiers that are *defined locally* inside `fn`
    (and therefore safe to rename). Excludes names declared global/nonlocal,
    imported names, and names belonging to *nested* functions or classes
    (those have their own scope and we don't want to rename across them).
    """
    locals_: set[str] = set()
    declared_nonlocal: set[str] = set()

    # Function parameters
    args = fn.args
    for a in (args.posonlyargs + args.args + args.kwonlyargs):
        locals_.add(a.arg)
    if args.vararg is not None:
        locals_.add(args.vararg.arg)
    if args.kwarg is not None:
        locals_.add(args.kwarg.arg)

    # Walk the body but skip into nested function/class bodies
    for node in _iter_local_scope(fn):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            declared_nonlocal.update(node.names)
            continue

        # Local assignment targets
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                _collect_target_names(tgt, locals_)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            _collect_target_names(node.target, locals_)
        elif isinstance(node, ast.NamedExpr):  # walrus :=
            if isinstance(node.target, ast.Name):
                locals_.add(node.target.id)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            _collect_target_names(node.target, locals_)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    _collect_target_names(item.optional_vars, locals_)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                locals_.add(node.name)
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            for gen in node.generators:
                _collect_target_names(gen.target, locals_)

    locals_ -= declared_nonlocal
    locals_ -= _NEVER_RENAME
    return locals_


def _iter_local_scope(fn: ast.FunctionDef):
    """
    Walk all nodes inside `fn`, but skip the bodies of nested functions
    and classes (they have their own scope). We do still descend into
    expressions (for comprehensions, lambdas in arguments, etc.).
    """
    stack: list[ast.AST] = [fn]
    visited_root = False
    while stack:
        n = stack.pop()
        if not visited_root:
            visited_root = True
            # The function itself: descend into the body, args defaults,
            # decorators stay outside (they execute in the enclosing scope).
            stack.extend(reversed(fn.body))
            continue

        yield n

        # Don't descend into nested function/class bodies
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue

        for child in ast.iter_child_nodes(n):
            stack.append(child)


def _collect_target_names(target: ast.AST, out: set[str]) -> None:
    """Recursively collect names that appear in an assignment target."""
    if isinstance(target, ast.Name):
        out.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            _collect_target_names(elt, out)
    elif isinstance(target, ast.Starred):
        _collect_target_names(target.value, out)
    # Attribute / Subscript targets like `self.x = ...` are not local names —
    # they're attribute writes, skip.


# ---------------------------------------------------------------------------
# Renamer
# ---------------------------------------------------------------------------

class _Renamer(ast.NodeTransformer):
    """Replace `Name`/`arg` nodes whose id is in `mapping` with the new name."""

    def __init__(self, mapping: dict[str, str], fn_name: str):
        self.mapping = mapping
        self.fn_name = fn_name
        # We must NOT recurse into nested FunctionDef/ClassDef/Lambda bodies
        # because their scopes might shadow our names.
        self._skip_nested = 0

    def visit_FunctionDef(self, node):  # noqa: N802
        # Only touch the OUTERMOST function (our target). Don't recurse.
        if node.name == self.fn_name and self._skip_nested == 0:
            self._skip_nested += 1
            try:
                # Rewrite the args of THIS function (parameter declarations)
                self._rewrite_args(node.args)
                # Rewrite the body (but don't enter nested scopes)
                node.body = [self._visit_top_level(s) for s in node.body]
                return node
            finally:
                self._skip_nested -= 1
        # Nested function — leave it alone (its scope is separate)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef  # same logic

    def _rewrite_args(self, args: ast.arguments) -> None:
        for a in (args.posonlyargs + args.args + args.kwonlyargs):
            if a.arg in self.mapping:
                a.arg = self.mapping[a.arg]
        if args.vararg and args.vararg.arg in self.mapping:
            args.vararg.arg = self.mapping[args.vararg.arg]
        if args.kwarg and args.kwarg.arg in self.mapping:
            args.kwarg.arg = self.mapping[args.kwarg.arg]

    def _visit_top_level(self, node: ast.AST) -> ast.AST:
        # Descend through everything except nested scopes
        return self._traverse(node)

    def _traverse(self, node: ast.AST) -> ast.AST:
        # Don't descend into nested defs / classes / lambdas
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return node

        # Handle Name nodes (loads, stores, dels)
        if isinstance(node, ast.Name) and node.id in self.mapping:
            return ast.Name(id=self.mapping[node.id], ctx=node.ctx)

        # Handle global/nonlocal declarations — rewrite the names list
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            node.names = [self.mapping.get(n, n) for n in node.names]
            return node

        # Handle except-as: ExceptHandler.name is a str, not a Name node
        if isinstance(node, ast.ExceptHandler) and node.name and node.name in self.mapping:
            node.name = self.mapping[node.name]

        # Recurse into children
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                new_list = []
                for item in value:
                    if isinstance(item, ast.AST):
                        new_list.append(self._traverse(item))
                    else:
                        new_list.append(item)
                setattr(node, field, new_list)
            elif isinstance(value, ast.AST):
                setattr(node, field, self._traverse(value))
        return node


# ---------------------------------------------------------------------------
# Mutator
# ---------------------------------------------------------------------------

@dataclass
class VariableRename:
    """Mutator M1: rename a percentage of local variables to synonyms.

    The intensity is controlled by `rename_fraction` — a value in [0, 1]
    indicating what fraction of renameable local names should actually
    get renamed. Higher = more lexical shock.
    """

    name: str = "variable_rename"
    rename_fraction_range: tuple[float, float] = (0.5, 1.0)

    def applies_to(self, tree: ast.FunctionDef) -> bool:
        if not isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return False
        locals_ = _collect_local_names(tree)
        # Need at least one renameable local
        return len(locals_) > 0

    def mutate(self, tree: ast.FunctionDef, rng: random.Random) -> ast.FunctionDef:
        new_tree = deepcopy(tree)
        locals_ = _collect_local_names(new_tree)

        if not locals_:
            return new_tree

        # Pick the subset to rename
        fraction = rng.uniform(*self.rename_fraction_range)
        n_to_rename = max(1, int(len(locals_) * fraction))
        chosen = rng.sample(sorted(locals_), n_to_rename)

        # Build the rename mapping. Avoid collisions: never rename two
        # different originals to the same new name; never rename to an
        # already-existing local name (would shadow / collide).
        used: set[str] = set(locals_) | _NEVER_RENAME
        # also include any free names we observed in the function — renaming
        # to one of those would silently change semantics
        for n in ast.walk(new_tree):
            if isinstance(n, ast.Name):
                used.add(n.id)

        mapping: dict[str, str] = {}
        for original in chosen:
            # Try up to 10 candidates from synonyms; if all collide, fall back
            for _ in range(10):
                candidate = _pick_synonym(original, rng)
                if candidate not in used and candidate != original:
                    mapping[original] = candidate
                    used.add(candidate)
                    break

        if not mapping:
            return new_tree  # nothing safe to rename

        renamer = _Renamer(mapping=mapping, fn_name=new_tree.name)
        result = renamer.visit(new_tree)
        ast.fix_missing_locations(result)
        return result  # type: ignore[return-value]


VARIABLE_RENAMER = VariableRename()
register(VARIABLE_RENAMER)
