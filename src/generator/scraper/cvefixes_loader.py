"""
cvefixes_loader.py — Phase 1, Step 3

Loads the CVEfixes research dataset (Zenodo record 7029359 / v1.0.7), which
maps 1 754 CVEs to their corresponding GitHub commits. For each CVE that
involves Python code and one of our four target CWEs, this loader extracts:

  • The code *before* the fix  → labelled is_vulnerable=True
  • The code *after*  the fix  → labelled is_vulnerable=False

This gives us real, paired vulnerable/secure samples with authoritative CWE
labels — much higher quality signal than pattern-matched scrapes.

Download size: ~3.9 GB ZIP (SQLite database inside). Downloaded once and cached.
Source: https://zenodo.org/records/7029359
"""

import gzip
import shutil
import sqlite3
import subprocess
import zipfile
from pathlib import Path

import requests

from src.utils.cwe_taxonomy import BLOCKED_SOURCE_CWE, CWE_VULN_MAP, TARGET_CWES
from src.utils.file_utils import build_meta, detect_framework, has_cwe_sink, hash_code, save_code_sample
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Zenodo migrated from /record/ to /records/ and now ships a ZIP containing
# a gzipped SQL dump rather than a bare .db file.
CVEFIXES_ZIP_URL = "https://zenodo.org/records/7029359/files/CVEfixes_v1.0.7.zip"
CVEFIXES_ZIP_LOCAL = "data/cvefixes/CVEfixes_v1.0.7.zip"
CVEFIXES_LOCAL = "data/cvefixes/CVEfixes.db"
# Path of the SQL dump inside the ZIP
_SQL_GZ_MEMBER = "CVEfixes_v1.0.7/Data/CVEfixes_v1.0.7.sql.gz"

# SQL query: join file_change → commits → fixes → cwe_classification
# code_before/code_after live in file_change; CWE is in cwe_classification.
# Filters: Python files only, target CWEs only, both before/after must exist.
_QUERY = """
    SELECT
        f.filename,
        f.code_before,
        f.code_after,
        fx.cve_id,
        cc.cwe_id,
        cm.repo_url,
        cm.msg AS commit_message
    FROM file_change       f
    JOIN commits           cm ON f.hash      = cm.hash
    JOIN fixes             fx ON cm.hash     = fx.hash
    JOIN cwe_classification cc ON fx.cve_id  = cc.cve_id
    WHERE f.filename    LIKE '%.py'
      AND cc.cwe_id     IN ({placeholders})
      AND f.code_before IS NOT NULL
      AND f.code_after  IS NOT NULL
"""


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def _db_is_valid(db_dest: str) -> bool:
    """Return True if the DB exists and has the expected tables."""
    if not Path(db_dest).exists():
        return False
    try:
        conn = sqlite3.connect(db_dest)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()
        return "method_change" in tables and "cve" in tables
    except Exception:
        return False


def download_cvefixes(db_dest: str = CVEFIXES_LOCAL) -> bool:
    if _db_is_valid(db_dest):
        logger.info(f"CVEfixes DB already cached at {db_dest} — skipping download")
        return True
    # Remove stale/partial DB if it exists
    Path(db_dest).unlink(missing_ok=True)

    Path(db_dest).parent.mkdir(parents=True, exist_ok=True)

    # --- Download ZIP ---
    zip_dest = Path(CVEFIXES_ZIP_LOCAL)
    if not zip_dest.exists():
        logger.info(f"Downloading CVEfixes ZIP (~3.9 GB) to {zip_dest}…")
        try:
            with requests.get(CVEFIXES_ZIP_URL, stream=True, timeout=300) as r:
                r.raise_for_status()
                total_bytes = 0
                with open(zip_dest, "wb") as f:
                    for chunk in r.iter_content(chunk_size=65536):
                        f.write(chunk)
                        total_bytes += len(chunk)
                logger.info(f"Download complete ({total_bytes / 1e6:.1f} MB)")
        except Exception as e:
            logger.error(f"CVEfixes download failed: {e}")
            zip_dest.unlink(missing_ok=True)
            return False

    # --- Build SQLite DB by streaming the gzipped SQL dump into sqlite3 ---
    # Loading the full dump into memory would require ~10+ GB RAM. Instead we
    # pipe the decompressed stream directly into the sqlite3 CLI, identical to:
    #   gzcat CVEfixes_v1.0.7.sql.gz | sqlite3 CVEfixes.db
    sqlite3_bin = shutil.which("sqlite3")
    if not sqlite3_bin:
        logger.error("sqlite3 CLI not found — install it and re-run")
        return False

    logger.info("Building CVEfixes.db from SQL dump (streaming, may take several minutes)…")
    proc = None
    try:
        proc = subprocess.Popen(
            [sqlite3_bin, db_dest],
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        with zipfile.ZipFile(zip_dest, "r") as zf:
            if _SQL_GZ_MEMBER not in zf.namelist():
                logger.error(f"Expected member '{_SQL_GZ_MEMBER}' not found in ZIP")
                proc.terminate()
                return False
            with zf.open(_SQL_GZ_MEMBER) as gz_member:
                with gzip.GzipFile(fileobj=gz_member) as sql_stream:
                    shutil.copyfileobj(sql_stream, proc.stdin, length=65536)

        proc.stdin.close()
        stderr = proc.stderr.read()
        proc.wait()

        if proc.returncode != 0:
            logger.error(f"sqlite3 import failed: {stderr.decode()[:500]}")
            Path(db_dest).unlink(missing_ok=True)
            return False
        logger.info(f"CVEfixes.db built successfully at {db_dest}")
        return True
    except Exception as e:
        logger.error(f"CVEfixes DB build failed: {e}")
        if proc and proc.poll() is None:
            proc.terminate()
        Path(db_dest).unlink(missing_ok=True)
        return False


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def run(output_dir: str = "data/raw", db_path: str = CVEFIXES_LOCAL) -> int:
    if not download_cvefixes(db_dest=db_path):
        return 0

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    total = 0

    try:
        placeholders = ",".join(f'"{cwe}"' for cwe in TARGET_CWES)
        query = _QUERY.format(placeholders=placeholders)
        rows = conn.execute(query).fetchall()
        logger.info(f"CVEfixes: {len(rows)} Python method-change rows matched")

        seen: set[str] = set()
        rejected_sink = 0
        rejected_blocked = 0

        for row in rows:
            cwe = row["cwe_id"]
            if ("cvefixes", cwe) in BLOCKED_SOURCE_CWE:
                rejected_blocked += 1
                continue
            vuln_type = CWE_VULN_MAP[cwe]

            code_before = (row["code_before"] or "").strip()
            code_after  = (row["code_after"]  or "").strip()
            if not code_before:
                continue

            # Phase 2B sink-presence filter — reject samples without a
            # category-defining sink token (see docs/design/PHASE_2B_DESIGN.md §2.2).
            sink_ok, _ = has_cwe_sink(code_before, cwe, file_path=row["filename"])
            if not sink_ok:
                rejected_sink += 1
                continue

            h = hash_code(code_before)
            if h in seen:
                continue
            seen.add(h)

            framework = detect_framework(code_before)
            commit_msg = (row["commit_message"] or "").strip()
            cve_id = row["cve_id"]

            meta = build_meta(
                {
                    "id":               f"cvefixes_{vuln_type}_{h}",
                    "source":           "cvefixes",
                    "cve_id":           cve_id,
                    "cwe":              cwe,
                    "vuln_type":        vuln_type,
                    "label_source":     "nvd",
                    "label_confidence": "high",
                    "commit_message":   commit_msg,
                    "framework":        framework,
                    "repo":             row["repo_url"],
                    "file_path":        row["filename"],
                    "pair_id":          f"{cve_id}_{row['filename']}",
                },
                code_before,
                code_after,
            )
            save_code_sample(code_before, meta, output_dir)
            total += 1

    finally:
        conn.close()

    logger.info(
        f"cvefixes_loader finished — {total} samples saved to {output_dir} "
        f"(rejected: sink={rejected_sink}, blocked_source={rejected_blocked})"
    )
    return total
