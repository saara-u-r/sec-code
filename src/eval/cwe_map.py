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
