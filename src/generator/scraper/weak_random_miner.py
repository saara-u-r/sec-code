"""
weak_random_miner.py — Phase 2B, CWE-330 static miner

Same shape as hardcoded_creds_miner but targets `random.random|choice|...`
calls in security-relevant code paths. CWE-330 is rare in CVE databases
(most weak-random vulnerabilities are reported in audit findings, not as
filed CVEs), so static mining is the right approach to bootstrap a
representative training set.

The Phase 2B sink filter (`has_cwe_sink('CWE-330', ...)`) already does
the right work: it requires a `random.*` sink AND a security-context
keyword (token/password/session/auth/...) in the same file, which is
how we filter out games and simulations that legitimately use `random`.

Reuses the same TARGET_REPOS as hardcoded_creds_miner so we don't need
another curation pass.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from src.generator.scraper.hardcoded_creds_miner import TARGET_REPOS, _shallow_clone
from src.utils.cwe_taxonomy import CWE_VULN_MAP
from src.utils.file_utils import (
    build_meta,
    detect_framework,
    has_cwe_sink,
    hash_code,
    is_test_file,
    save_code_sample,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


def _scan_repo(
    repo_dir: str,
    repo_url: str,
    seen_hashes: set[str],
    output_dir: str,
    max_file_bytes: int = 100_000,
) -> int:
    """Walk one cloned repo and save CWE-330 samples. Return count saved."""
    saved = 0
    cwe = "CWE-330"
    vuln_type = CWE_VULN_MAP[cwe]
    repo_path = Path(repo_dir)
    repo_name = repo_url.rstrip("/").split("/")[-1]

    for py_path in repo_path.rglob("*.py"):
        try:
            if py_path.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue

        rel_path = str(py_path.relative_to(repo_path))
        # Skip test files (the sink filter would catch security-context
        # mismatches but tests sometimes do legitimately use random for
        # security-flavored fixtures, producing weak FPs).
        if is_test_file(rel_path):
            continue

        try:
            code_before = py_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if not code_before or len(code_before) < 50:
            continue

        sink_ok, sink_pat = has_cwe_sink(code_before, cwe, file_path=rel_path)
        if not sink_ok:
            continue

        h = hash_code(code_before)
        if h in seen_hashes:
            continue
        seen_hashes.add(h)

        framework = detect_framework(code_before)

        meta = build_meta(
            {
                "id":               f"weak_random_{vuln_type}_{h}",
                "source":           "weak_random_miner",
                "cwe":              cwe,
                "vuln_type":        vuln_type,
                "label_source":     "static_mining",
                "label_confidence": "medium",
                "framework":        framework,
                "repo":             repo_url,
                "file_path":        rel_path,
            },
            code_before,
            "",   # no paired safe version produced by this miner
        )
        save_code_sample(code_before, meta, output_dir)
        saved += 1
        logger.info(f"  [{cwe}] {repo_name}/{rel_path} (matched {sink_pat!r})")
    return saved


def run(output_dir: str = "data/raw") -> int:
    if shutil.which("git") is None:
        logger.error("git not found in PATH — install git and rerun")
        return 0

    seen_hashes: set[str] = set()
    total = 0

    for repo_url in TARGET_REPOS:
        logger.info(f"Cloning {repo_url} …")
        with tempfile.TemporaryDirectory(prefix="weak_random_") as td:
            target = os.path.join(td, "clone")
            if not _shallow_clone(repo_url, target):
                continue
            saved = _scan_repo(target, repo_url, seen_hashes, output_dir)
            total += saved
            logger.info(f"  → {saved} CWE-330 samples from {repo_url}")
        time.sleep(0.5)

    logger.info(f"weak_random_miner finished — {total} samples saved to {output_dir}")
    return total
