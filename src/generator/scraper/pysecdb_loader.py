"""
pysecdb_loader.py — Phase 1, PySecDB source

Loads the PySecDB dataset (sunlab/PySecDB on HuggingFace) — 1,258 Python
security commits with unified-diff content, 729 of them linked to CVEs.

PySecDB is a *gated* dataset:
  1. Get a HuggingFace account, request access at
     https://huggingface.co/datasets/sunlab/PySecDB
  2. Create a token at https://huggingface.co/settings/tokens
  3. Export it: `export HF_TOKEN=hf_xxx`  or set in .env

Pipeline:
  • Filter rows where label="security" and CVE-ID != "NA"
  • Parse unified diff in `content` field with `unidiff`
  • For each .py file change, reconstruct code_before (context + removed lines)
    and code_after (context + added lines)
  • Look up CWE from NVD using the CVE-ID (cached per-CVE)
  • Keep only target CWEs; skip duplicates by content hash

Install: pip install datasets unidiff
"""

import os
import time

import requests
from dotenv import load_dotenv

from src.utils.cwe_taxonomy import BLOCKED_SOURCE_CWE, CWE_VULN_MAP
from src.utils.file_utils import build_meta, detect_framework, has_cwe_sink, hash_code, save_code_sample
from src.utils.logger import get_logger
from src.utils.mongo_writer import get_collection

load_dotenv()
logger = get_logger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_KEY = os.getenv("NVD_API_KEY", "")
HF_TOKEN = os.getenv("HF_TOKEN", "")

# CVE → CWE cache so we don't re-hit NVD for repeated CVE IDs across rows
_CVE_CWE_CACHE: dict[str, str | None] = {}


def _nvd_headers() -> dict:
    h = {"User-Agent": "PyVulSev-Scraper/1.0"}
    if NVD_KEY:
        h["apiKey"] = NVD_KEY
    return h


def _fetch_cwe_from_nvd(cve_id: str) -> str | None:
    """Return the first target CWE from NVD for a given CVE ID, else None."""
    if cve_id in _CVE_CWE_CACHE:
        return _CVE_CWE_CACHE[cve_id]

    delay = 0.7 if NVD_KEY else 6.5  # NVD rate limit: 5 req/30s without key, 50 req/30s with key
    try:
        resp = requests.get(NVD_API, params={"cveId": cve_id}, headers=_nvd_headers(), timeout=20)
        if resp.status_code == 429:
            logger.warning("NVD rate limited — sleeping 30s")
            time.sleep(30)
            resp = requests.get(NVD_API, params={"cveId": cve_id}, headers=_nvd_headers(), timeout=20)
        if resp.status_code != 200:
            _CVE_CWE_CACHE[cve_id] = None
            return None
        data = resp.json()
        for vuln in data.get("vulnerabilities", []):
            for w in vuln.get("cve", {}).get("weaknesses", []):
                for d in w.get("description", []):
                    val = d.get("value", "")
                    if val in CWE_VULN_MAP:
                        _CVE_CWE_CACHE[cve_id] = val
                        time.sleep(delay)
                        return val
        _CVE_CWE_CACHE[cve_id] = None
        time.sleep(delay)
    except Exception as e:
        logger.warning(f"NVD lookup failed for {cve_id}: {e}")
        _CVE_CWE_CACHE[cve_id] = None
    return None


def _parse_diff_to_pairs(content: str) -> list[tuple[str, str, str]]:
    """
    Parse a unified diff. Return list of (file_path, code_before, code_after)
    for each .py file in the diff.
    """
    try:
        from unidiff import PatchSet
    except ImportError:
        logger.error("`unidiff` not installed. Run: pip install unidiff")
        return []

    try:
        patch = PatchSet.from_string(content)
    except Exception as e:
        logger.debug(f"Diff parse failed: {e}")
        return []

    pairs: list[tuple[str, str, str]] = []
    for patched_file in patch:
        path = patched_file.path or ""
        if not path.endswith(".py"):
            continue
        if "/test" in path or "/tests" in path or path.startswith("test"):
            continue

        before_lines: list[str] = []
        after_lines: list[str] = []
        for hunk in patched_file:
            for line in hunk:
                if line.is_context or line.is_removed:
                    before_lines.append(line.value)
                if line.is_context or line.is_added:
                    after_lines.append(line.value)

        before = "".join(before_lines).strip()
        after = "".join(after_lines).strip()
        if before and before != after:
            pairs.append((path, before, after))
    return pairs


def _load_existing_hashes() -> set[str]:
    try:
        col = get_collection()
        return {doc["content_hash"] for doc in col.find(
            {"source": "pysecdb", "content_hash": {"$exists": True}},
            {"content_hash": 1, "_id": 0},
        )}
    except Exception:
        return set()


def run(output_dir: str = "data/raw") -> int:
    try:
        from datasets import load_dataset
    except ImportError:
        logger.error("HuggingFace `datasets` not installed. Run: pip install datasets")
        return 0

    if not HF_TOKEN:
        logger.error(
            "PySecDB is a gated dataset — set HF_TOKEN in your env after requesting "
            "access at https://huggingface.co/datasets/sunlab/PySecDB"
        )
        return 0

    if not NVD_KEY:
        logger.warning("NVD_API_KEY not set — NVD lookups will be slow (5 req / 30s)")

    logger.info("Loading sunlab/PySecDB from HuggingFace…")
    try:
        ds = load_dataset("sunlab/PySecDB", token=HF_TOKEN)
    except Exception as e:
        logger.error(f"Failed to load sunlab/PySecDB: {e}")
        return 0

    existing_hashes = _load_existing_hashes()
    logger.info(f"Skipping {len(existing_hashes)} already-ingested PySecDB hashes")

    seen: set[str] = set(existing_hashes)
    total = 0

    for split_name in ds.keys():
        rows = ds[split_name]
        logger.info(f"Processing PySecDB {split_name} split ({len(rows)} rows)…")

        for row in rows:
            if row.get("label") != "security":
                continue

            cve_id = row.get("CVE-ID", "NA")
            if not cve_id or cve_id == "NA":
                continue

            cwe = _fetch_cwe_from_nvd(cve_id)
            if not cwe:
                continue
            if ("pysecdb", cwe) in BLOCKED_SOURCE_CWE:
                continue

            vuln_type = CWE_VULN_MAP[cwe]
            content = row.get("content", "")
            if not content:
                continue

            pairs = _parse_diff_to_pairs(content)
            if not pairs:
                continue

            for file_path, code_before, code_after in pairs:
                # Phase 2B: sink-presence gate replaces is_web_code()
                sink_ok, _ = has_cwe_sink(code_before, cwe, file_path=file_path)
                if not sink_ok:
                    continue

                h = hash_code(code_before)
                if h in seen:
                    continue
                seen.add(h)

                framework = detect_framework(code_before)

                meta = build_meta(
                    {
                        "id":               f"pysecdb_{vuln_type}_{h}",
                        "source":           "pysecdb",
                        "cve_id":           cve_id,
                        "cwe":              cwe,
                        "vuln_type":        vuln_type,
                        "label_source":     "pysecdb_nvd",
                        "label_confidence": "high",
                        "framework":        framework,
                        "file_path":        file_path,
                        "row_id":           row.get("id"),
                        "diff_source":      row.get("source"),  # "MITRE" or "wild"
                    },
                    code_before,
                    code_after,
                )
                save_code_sample(code_before, meta, output_dir)
                total += 1
                logger.info(f"  Saved [{cwe}] {cve_id} — {file_path} ({framework})")

    logger.info(f"pysecdb_loader finished — {total} new samples saved")
    return total
