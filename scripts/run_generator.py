#!/usr/bin/env python3
"""
CLI entry point for Phase 1.

Usage:
    # Run all scrapers
    python scripts/run_generator.py

    # Run only specific scrapers
    python scripts/run_generator.py --sources cvefixes osv ghsa ghsa_db pypa
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.generator.run import ALL_SOURCES, run

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Phase 1 — run dataset scrapers")
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=ALL_SOURCES,
        default=None,
        help="Scrapers to run. Omit to run all.",
    )
    args = parser.parse_args()
    run(sources=args.sources)
