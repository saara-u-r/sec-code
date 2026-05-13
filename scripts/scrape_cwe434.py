#!/usr/bin/env python3
"""
scrape_cwe434.py — focused CWE-434 ingest.

Phase 2B re-scope (2026-05-13) added CWE-434 (Unrestricted File Upload)
to the active taxonomy. This script runs the existing cvefixes_loader
and github_advisory_db_scraper with TARGET_CWES / CWE_VULN_MAP
monkey-patched to only emit CWE-434, so we don't redundantly
re-process the 1268 samples already on disk for the other 9 CWEs.

Usage:
  python scripts/scrape_cwe434.py --sources cvefixes
  python scripts/scrape_cwe434.py --sources ghsa_db
  python scripts/scrape_cwe434.py --sources cvefixes ghsa_db
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils import cwe_taxonomy  # noqa: E402
from src.utils.logger import get_logger  # noqa: E402

logger = get_logger(__name__)


def _scope_to_cwe434() -> None:
    """Monkey-patch the central taxonomy so scrapers emit only CWE-434.

    Both cvefixes_loader (SQL placeholders from TARGET_CWES) and
    github_advisory_db_scraper (CWE_VULN_MAP membership check) read from
    these symbols at call time, so a runtime override is sufficient.
    """
    cwe_taxonomy.TARGET_CWES = {"CWE-434"}
    cwe_taxonomy.CWE_VULN_MAP = {"CWE-434": "unrestricted_file_upload"}
    logger.info("Scoped taxonomy to CWE-434 only for this run.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sources",
        nargs="+",
        default=["cvefixes"],
        choices=["cvefixes", "ghsa_db", "osv", "pypa"],
    )
    parser.add_argument("--output-dir", default="data/raw")
    args = parser.parse_args()

    _scope_to_cwe434()

    total = 0
    for source in args.sources:
        if source == "cvefixes":
            from src.generator.scraper import cvefixes_loader
            logger.info("Running cvefixes_loader (CWE-434 only)…")
            n = cvefixes_loader.run(output_dir=args.output_dir)
            logger.info(f"cvefixes_loader: {n} samples saved")
            total += n or 0
        elif source == "ghsa_db":
            from src.generator.scraper import github_advisory_db_scraper
            logger.info("Running github_advisory_db_scraper (CWE-434 only)…")
            n = github_advisory_db_scraper.run(output_dir=args.output_dir)
            logger.info(f"github_advisory_db_scraper: {n} samples saved")
            total += n or 0
        elif source == "osv":
            from src.generator.scraper import osv_scraper
            n = osv_scraper.run(output_dir=args.output_dir)
            total += n or 0
        elif source == "pypa":
            from src.generator.scraper import pypa_scraper
            n = pypa_scraper.run(output_dir=args.output_dir)
            total += n or 0

    logger.info(f"=== TOTAL CWE-434 samples saved: {total} ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
