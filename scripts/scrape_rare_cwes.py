#!/usr/bin/env python3
"""
scrape_rare_cwes.py — focused ingest for the rare CWEs.

Phase 2B re-scope (2026-05-13) left CWE-77 / CWE-78 / CWE-94 / CWE-502
under the audit threshold of "≥20 real samples per class". GHSA-DB has
70/98/198/193 PyPI advisories tagged with these CWEs respectively; this
script runs github_advisory_db_scraper with TARGET_CWES / CWE_VULN_MAP
monkey-patched to those 4 CWEs only.

Mirrors the pattern of scripts/scrape_cwe434.py.

Usage:
  python scripts/scrape_rare_cwes.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils import cwe_taxonomy  # noqa: E402
from src.utils.logger import get_logger  # noqa: E402

logger = get_logger(__name__)

RARE_CWES = {
    "CWE-77":  "command_injection_generic",
    "CWE-78":  "command_injection",
    "CWE-94":  "code_injection",
    "CWE-502": "insecure_deserialization",
}


def main() -> int:
    cwe_taxonomy.TARGET_CWES = set(RARE_CWES.keys())
    cwe_taxonomy.CWE_VULN_MAP = dict(RARE_CWES)
    logger.info(f"Scoped taxonomy to rare CWEs: {sorted(RARE_CWES)}")

    from src.generator.scraper import github_advisory_db_scraper
    n = github_advisory_db_scraper.run(output_dir="data/raw")
    logger.info(f"=== TOTAL rare-CWE samples saved: {n} ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
