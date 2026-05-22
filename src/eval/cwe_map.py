"""CWE mapping for the evaluation harness.

Two jobs:

  1. `normalize_cwe(id)` — fold a raw CWE id (emitted by a tool that
     reports CWEs directly, e.g. Semgrep rule metadata) onto one of our
     7 target classes, collapsing MITRE parent/child relationships.

  2. `bandit_rule_to_cwe(test_id)` — map a Bandit *rule id* to a target
     CWE. Bandit's own `issue_cwe` field is not reliable for our
     purposes: it tags `eval` (B307) as CWE-78 and `yaml.load` (B506)
     as CWE-20, neither of which reflects what the rule detects. We map
     by what the rule actually flags. Bandit's raw `issue_cwe` is still
     stored in the prediction record for audit.

Soft-warning rules that do not correspond to a concrete sink (e.g.
B404 "consider possible security implications of subprocess import")
map to nothing and contribute no prediction — per the evaluation
methodology, section 6.1.
"""

from __future__ import annotations

# The 7 sink-shaped CWE classes the benchmark scores. Sorted for stable
# iteration order in reports.
TARGET_CWES: tuple[str, ...] = (
    "CWE-22",   # Path Traversal
    "CWE-78",   # OS Command Injection
    "CWE-79",   # Cross-site Scripting
    "CWE-89",   # SQL Injection
    "CWE-94",   # Code Injection
    "CWE-502",  # Insecure Deserialization
    "CWE-918",  # Server-Side Request Forgery
)

# Raw CWE id -> target class. Keys include MITRE child CWEs that tools
# emit in place of the parent we score against:
#   CWE-80/81/83/87  improper neutralization of script  -> CWE-79
#   CWE-77           command injection (generic parent) -> CWE-78
#   CWE-23/35        relative/absolute path traversal   -> CWE-22
#   CWE-95/96        eval / static code injection       -> CWE-94
#   CWE-564          SQL injection: hibernate           -> CWE-89
_CWE_FOLD: dict[int, str] = {
    22: "CWE-22", 23: "CWE-22", 35: "CWE-22", 36: "CWE-22",
    77: "CWE-78", 78: "CWE-78",
    79: "CWE-79", 80: "CWE-79", 81: "CWE-79", 83: "CWE-79", 87: "CWE-79",
    89: "CWE-89", 564: "CWE-89",
    94: "CWE-94", 95: "CWE-94", 96: "CWE-94",
    502: "CWE-502",
    918: "CWE-918",
}


def normalize_cwe(cwe_id: int | str | None) -> str | None:
    """Fold a raw CWE id onto a target class, or return None if it is
    outside the 7 scored classes.

    Accepts an int (502), a bare string ("502"), or a prefixed string
    ("CWE-502", "CWE-502: Deserialization of Untrusted Data").
    """
    if cwe_id is None:
        return None
    if isinstance(cwe_id, str):
        s = cwe_id.strip().upper().removeprefix("CWE-")
        digits = ""
        for ch in s:
            if ch.isdigit():
                digits += ch
            else:
                break
        if not digits:
            return None
        cwe_id = int(digits)
    return _CWE_FOLD.get(int(cwe_id))


# Bandit rule id -> target CWE, by what the rule actually detects.
# Rules absent from this table (B101 assert, B104 bind-all, B403/B404
# bare imports, B113 request-timeout, xml imports, crypto rules, ...)
# are outside our 7 classes and produce no prediction.
BANDIT_RULE_TO_CWE: dict[str, str] = {
    # SQL injection
    "B608": "CWE-89",   # hardcoded_sql_expressions
    "B610": "CWE-89",   # django_extra_used
    "B611": "CWE-89",   # django_rawsql_used
    # Cross-site scripting
    "B308": "CWE-79",   # mark_safe
    "B701": "CWE-79",   # jinja2_autoescape_false
    "B702": "CWE-79",   # use_of_mako_templates
    "B703": "CWE-79",   # django_mark_safe
    "B704": "CWE-79",   # markupsafe_markup_xss
    # OS command injection
    "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",   # subprocess_without_shell_equals_true
    "B604": "CWE-78",   # any_other_function_with_shell_equals_true
    "B605": "CWE-78",   # start_process_with_a_shell
    "B606": "CWE-78",   # start_process_with_no_shell
    "B607": "CWE-78",   # start_process_with_partial_path
    "B609": "CWE-78",   # linux_commands_wildcard_injection
    # Code injection
    "B102": "CWE-94",   # exec_used
    "B307": "CWE-94",   # eval (blacklist) — Bandit mis-tags this CWE-78
    # Insecure deserialization
    "B301": "CWE-502",  # pickle / cPickle
    "B302": "CWE-502",  # marshal
    "B506": "CWE-502",  # yaml_load — Bandit mis-tags this CWE-20
    # Server-side request forgery (Bandit has no dedicated SSRF rule;
    # B310 urllib.urlopen is the closest signal — user-controlled URL).
    "B310": "CWE-918",  # urllib_urlopen
}


def bandit_rule_to_cwe(test_id: str) -> str | None:
    """Map a Bandit rule id (e.g. "B608") to a target CWE, or None."""
    return BANDIT_RULE_TO_CWE.get(test_id.strip().upper())


# ---------------------------------------------------------------------------
# CWE hierarchy (subtree)
# ---------------------------------------------------------------------------
#
# Hand-coded subtree of the MITRE CWE hierarchy (version 4.14, accessed
# 2026-05-22 at https://cwe.mitre.org/data/index.html). Covers the seven
# target CWEs and the ancestors needed to compute Wu-Palmer similarity
# between any two of them.
#
# A synthetic ``ROOT`` node at depth 0 unifies the two MITRE pillars we
# touch so that every CWE in the subtree has a finite path to a common
# ancestor. Without this, cross-pillar pairs would have no LCA. Wu-Palmer
# similarity returns 0 when the LCA is ROOT, which is the right answer
# for "two unrelated weaknesses."
#
# MITRE relationships used (ChildOf-Primary):
#   CWE-78   -> CWE-77   -> CWE-74  -> CWE-707
#   CWE-79   -> CWE-74  -> CWE-707
#   CWE-89   -> CWE-74  -> CWE-707
#   CWE-94   -> CWE-74  -> CWE-707
#   CWE-22   -> CWE-668 -> CWE-664
#   CWE-502  -> CWE-913 -> CWE-664
#   CWE-918  -> CWE-441 -> CWE-664
#
# Tree:
#   ROOT (0)
#   ├── CWE-707 Improper Neutralization (1)            -- pillar
#   │   └── CWE-74 Injection (2)
#   │       ├── CWE-77 Command Injection (3)
#   │       │   └── CWE-78 OS Command Injection (4)
#   │       ├── CWE-79 XSS (3)
#   │       ├── CWE-89 SQL Injection (3)
#   │       └── CWE-94 Code Injection (3)
#   └── CWE-664 Improper Control of a Resource (1)     -- pillar
#       ├── CWE-668 Exposure of Resource (2)
#       │   └── CWE-22 Path Traversal (3)
#       ├── CWE-913 Dynamically-Managed Code Resources (2)
#       │   └── CWE-502 Insecure Deserialization (3)
#       └── CWE-441 Confused Deputy (2)
#           └── CWE-918 SSRF (3)
#
# Some CWEs have multiple MITRE ChildOf relationships (CWE-918 also lists
# CWE-610 as a parent). We use the ChildOf-Primary relationship listed
# first in each CWE's MITRE entry. Reviewers can re-derive any single
# similarity by inspecting this dict.

_CWE_ROOT = "ROOT"

CWE_PARENT: dict[str, str] = {
    # Pillars
    "CWE-707": _CWE_ROOT,
    "CWE-664": _CWE_ROOT,
    # Classes / intermediates under CWE-707
    "CWE-74":  "CWE-707",
    "CWE-77":  "CWE-74",
    # Target CWEs under CWE-707
    "CWE-78":  "CWE-77",
    "CWE-79":  "CWE-74",
    "CWE-89":  "CWE-74",
    "CWE-94":  "CWE-74",
    # Classes / intermediates under CWE-664
    "CWE-668": "CWE-664",
    "CWE-913": "CWE-664",
    "CWE-441": "CWE-664",
    # Target CWEs under CWE-664
    "CWE-22":  "CWE-668",
    "CWE-502": "CWE-913",
    "CWE-918": "CWE-441",
}


def cwe_depth(cwe: str) -> int:
    """Distance from ROOT for ``cwe`` in the hand-coded subtree.

    Raises ``KeyError`` if ``cwe`` is not in the subtree (which excludes
    ``safe`` and any CWE outside the 7 target classes and their
    listed ancestors). Callers responsible for ``safe`` handling.
    """
    d = 0
    node = cwe
    while node != _CWE_ROOT:
        node = CWE_PARENT[node]
        d += 1
    return d


def cwe_ancestors(cwe: str) -> list[str]:
    """Return [cwe, parent, grandparent, ..., ROOT]."""
    out = [cwe]
    node = cwe
    while node != _CWE_ROOT:
        node = CWE_PARENT[node]
        out.append(node)
    return out


def cwe_lca(a: str, b: str) -> str:
    """Lowest common ancestor in the subtree. Returns ``ROOT`` if the
    two CWEs share no ancestor below it (i.e. they live in different
    pillars)."""
    ancestors_a = set(cwe_ancestors(a))
    for node in cwe_ancestors(b):
        if node in ancestors_a:
            return node
    return _CWE_ROOT  # defensive; unreachable while ROOT is in both walks


def wu_palmer_similarity(a: str, b: str) -> float:
    """Wu and Palmer (ACL 1994) tree similarity in ``[0, 1]``.

    ``sim(a, b) = 2 * depth(LCA(a, b)) / (depth(a) + depth(b))``

    Returns 1.0 for an exact match, 0.0 when the LCA is the synthetic
    ROOT (cross-pillar pairs and any pair where ``a`` or ``b`` is the
    pillar itself). The 'safe' label is **not** in the tree; callers
    that need a similarity involving ``safe`` should treat it as
    similarity 0 (see ``weighted_cohen_kappa`` for the convention).
    """
    if a == b:
        return 1.0
    lca = cwe_lca(a, b)
    depth_lca = cwe_depth(lca) if lca != _CWE_ROOT else 0
    if depth_lca == 0:
        return 0.0
    return (2.0 * depth_lca) / (cwe_depth(a) + cwe_depth(b))
