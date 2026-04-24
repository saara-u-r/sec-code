"""
run.py — Phase 1 orchestrator

Calls each scraper in order, then runs the cleaner.
Import and call run() from scripts/run_generator.py, or run directly:

    python -m src.generator.run --sources cvefixes osv
    python -m src.generator.run               # all sources

Sources: cvefixes (Zenodo CVE DB), osv (OSV.dev API),
         ghsa (GitHub Security Advisories), pypa (PyPA Advisory DB)

Removed: repo (deliberate vuln apps), github (keyword search),
         exploitdb (attacker PoCs) — none are CVE-confirmed real-world code.
"""

import argparse

from src.generator import cleaner
from src.generator.scraper import (
    cvefixes_loader,
    ghsa_scraper,
    osv_scraper,
    pypa_scraper,
)
from src.utils.config_loader import load_config
from src.utils.logger import get_logger

logger = get_logger(__name__)

ALL_SOURCES = ["cvefixes", "osv", "ghsa", "pypa"]

# Maps source name → scraper module
SCRAPERS = {
    "cvefixes": cvefixes_loader,
    "osv": osv_scraper,
    "ghsa": ghsa_scraper,
    "pypa": pypa_scraper,
}


def run(sources: list[str] | None = None) -> None:
    config = load_config()
    output_dir: str = config["generator"]["output_dir"]
    sources = sources or ALL_SOURCES

    total = 0
    for source in sources:
        if source not in SCRAPERS:
            logger.warning(f"Unknown source '{source}' — skipping")
            continue
        logger.info(f"=== [{source}] scraper starting ===")
        try:
            count = SCRAPERS[source].run(output_dir)
            total += count
            logger.info(f"=== [{source}] done — {count} samples ===")
        except Exception as e:
            logger.error(f"[{source}] scraper failed: {e}")

    logger.info(f"=== All scrapers done — {total} raw samples collected ===")
    logger.info("=== Running cleaner ===")
    stats = cleaner.run(output_dir)
    logger.info(f"Phase 1 complete. Final clean stats: {stats}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 1 — dataset scraper")
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=ALL_SOURCES,
        default=ALL_SOURCES,
        help="Which scrapers to run (default: all)",
    )
    args = parser.parse_args()
    run(sources=args.sources)
