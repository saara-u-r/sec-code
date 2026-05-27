"""
red_team.sanitization — generates hard-negative samples from vulnerable code
by applying CWE-specific canonical sanitization transforms.

See docs/design/PHASE2_5_AUGMENTATION_DESIGN.md §2 for the design rationale.
"""

from src.red_team.sanitization.base import (
    SanitizationResult,
    SanitizationRule,
    all_rules,
    register,
    rules_for,
    sanitize,
)

# Importing this triggers registration of all rule instances
from src.red_team.sanitization import rules  # noqa: F401

__all__ = [
    "SanitizationResult",
    "SanitizationRule",
    "all_rules",
    "register",
    "rules_for",
    "sanitize",
]
