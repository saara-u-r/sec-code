"""
red_team.sanitization.rules — concrete sanitization rule implementations.

Each module registers its rule(s) with the global registry on import.
"""

from src.red_team.sanitization.rules import cwe22_path     # noqa: F401
from src.red_team.sanitization.rules import cwe78_cmdi     # noqa: F401
from src.red_team.sanitization.rules import cwe79_xss      # noqa: F401
from src.red_team.sanitization.rules import cwe89_sqli     # noqa: F401
from src.red_team.sanitization.rules import cwe94_codei    # noqa: F401
from src.red_team.sanitization.rules import cwe502_deser   # noqa: F401
from src.red_team.sanitization.rules import cwe918_ssrf    # noqa: F401
