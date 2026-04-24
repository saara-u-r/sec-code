#!/usr/bin/env python3
""" Standalone script to run only the cleaning & sanitization phase.
I am using this to fix data in data/raw without re-running scrapers.
"""
import sys
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.generator import cleaner
from src.utils.config_loader import load_config

if __name__ == "__main__":
    config = load_config()
    raw_dir = config["generator"]["output_dir"]
    
    print(f"--- Starting Cleanup of {raw_dir} ---")
    stats = cleaner.run(raw_dir)
    print(f"\n--- Cleanup Complete ---")
    print(f"Summary: {stats}")
