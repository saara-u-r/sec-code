"""
nvd_targeted_scraper.py — Phase 1, NVD-direct CWE-targeted source

Queries the NVD CVE API directly by CWE ID, mines GitHub commit references
from each CVE, and extracts before/after Python code pairs. Designed to
backfill rare CWEs in the dataset (currently CWE-502 with only 35 samples).

Why direct NVD?
  - Our other scrapers index by ecosystem/repo first, then CWE second
  - NVD lets us query by CWE first → much higher hit rate per request
    when looking for a specific weakness type
  - Gets us CVEs that PyPA/OSV/GHSA may have missed (e.g. CVEs in
    libraries not on PyPI but installed via pip from GitHub)

Pipeline:
  1. NVD API: list all CVEs for each target CWE (paginated, 2000/page)
  2. For each CVE, scan references for github.com/{owner/repo}/commit/{sha}
  3. For each commit, list changed .py files (skip tests)
  4. Fetch code_before (parent commit) and code_after (fix commit) via raw.githubusercontent
  5. Filter to web code; dedup by content hash; save with high confidence
"""

import os
import re
import time

import requests
from dotenv import load_dotenv

from src.utils.cwe_taxonomy import BLOCKED_SOURCE_CWE, CWE_VULN_MAP
from src.utils.file_utils import (
    build_meta,
    detect_framework,
    has_cwe_sink,
    hash_code,
    save_code_sample,
)
from src.utils.logger import get_logger
from src.utils.mongo_writer import get_collection

load_dotenv()
logger = get_logger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API = "https://api.github.com"

NVD_KEY = os.getenv("NVD_API_KEY", "")
GH_TOKEN = os.getenv("GITHUB_TOKEN", "")

# Phase 2B: prioritize the under-represented + newly-added rare CWEs.
# Re-scoped 2026-05-13 to the 9 sink-shaped Top-25 Python CWE set.
# CWE-434 added (file upload). CWE-611/330/400/798 removed (see
# cwe_taxonomy.py DEPRECATED_CWES).
TARGET_CWES_DEFAULT = [
    "CWE-502", "CWE-918", "CWE-94", "CWE-78", "CWE-434",
]

_CVSS_BASE_SCORES = {
    "CRITICAL": 9.5,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      2.5,
}

_COMMIT_RE = re.compile(
    r"https?://github\.com/([^/]+/[^/]+?)/commit/([0-9a-f]{7,40})",
    re.IGNORECASE,
)

# Heuristic: signals that this CVE is about Python code.
# Used to skip non-Python CVEs early (no point fetching commits we'll throw away).
#
# Phase 2B Day 3 expansion: added XML libs (lxml/defusedxml/xmltodict/feedparser),
# DevOps tooling (saltstack/awx/paramiko/fabric), ML libs (transformers/mlflow/
# numpy/scipy), crypto (cryptography/pyjwt/passlib/authlib), HTTP libs
# (requests/urllib3/httpx), and image libs (pillow). The old heuristic was
# missing too many CWE-611/400/77 advisories whose descriptions named the
# library directly rather than saying "python".
_PY_HINT_RE = re.compile(
    r"("
    # Language / package management
    r"\bpython\b|\bpypi\b|\bpip\b|\.py\b|"
    # Web frameworks
    r"\bdjango\b|\bflask\b|\bfastapi\b|\btornado\b|\baiohttp\b|\bstarlette\b|"
    r"\bbottle\b|\bquart\b|\btwisted\b|\bcelery\b|\bjinja2\b|"
    # Serialization / XML libs (CWE-502, CWE-611)
    r"\bpyyaml\b|\bpickle\b|\blxml\b|\bdefusedxml\b|\bxmltodict\b|"
    r"\bfeedparser\b|\bsqlalchemy\b|\bjsonpickle\b|"
    # DevOps / sysadmin (CWE-78, 77, 798)
    r"\bansible\b|\bsalt\b|\bsaltstack\b|\bparamiko\b|\bfabric\b|"
    # ML / scientific
    r"\btransformers\b|\bmlflow\b|\bnumpy\b|\bscipy\b|\bpandas\b|"
    # HTTP / SSRF (CWE-918, CWE-400)
    r"\brequests\b|\burllib3\b|\bhttpx\b|"
    # Crypto / auth (CWE-330, 798)
    r"\bcryptography\b|\bpyjwt\b|\bpasslib\b|\bauthlib\b|"
    # Image (historic CVE hotspot)
    r"\bpillow\b|\bPIL\b"
    r")",
    re.IGNORECASE,
)

# Phase 2B (2026-05-11): removed _passes_code_filter and its legacy
# is_web_code fallback — the per-CWE has_cwe_sink check above already
# enforces the right category-defining tokens for all 12 CWEs and lets
# non-web CWEs (798, 611, 330, 400) through cleanly.


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _nvd_headers() -> dict:
    h = {"User-Agent": "PyVulSev-Scraper/1.0"}
    if NVD_KEY:
        h["apiKey"] = NVD_KEY
    return h


def _gh_headers() -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if GH_TOKEN:
        h["Authorization"] = f"Bearer {GH_TOKEN}"
    return h


def _nvd_delay() -> float:
    # NVD rate limit: 5 req / 30s without key, 50 req / 30s with key.
    return 0.7 if NVD_KEY else 6.5


def _gh_delay() -> float:
    return 1.0 if GH_TOKEN else 5.0


# ---------------------------------------------------------------------------
# NVD: list CVEs by CWE
# ---------------------------------------------------------------------------

def _fetch_cves_for_cwe(cwe: str) -> list[dict]:
    """Return the full list of CVE objects for a given CWE ID."""
    cves: list[dict] = []
    start = 0
    page_size = 2000

    while True:
        params = {"cweId": cwe, "startIndex": start, "resultsPerPage": page_size}
        try:
            resp = requests.get(NVD_API, params=params, headers=_nvd_headers(), timeout=30)
        except Exception as e:
            logger.error(f"NVD request failed for {cwe} startIndex={start}: {e}")
            break

        if resp.status_code == 429:
            logger.warning("NVD 429 rate-limited — sleeping 30s")
            time.sleep(30)
            continue
        if resp.status_code != 200:
            logger.error(f"NVD returned {resp.status_code} for {cwe}: {resp.text[:200]}")
            break

        data = resp.json()
        page = data.get("vulnerabilities", [])
        cves.extend(page)
        total = data.get("totalResults", 0)
        logger.info(f"  NVD {cwe}: fetched {len(cves)}/{total}")

        start += page_size
        if start >= total or not page:
            break
        time.sleep(_nvd_delay())

    return cves


# ---------------------------------------------------------------------------
# NVD CVE → commit extraction
# ---------------------------------------------------------------------------

def _cve_is_python_relevant(cve_obj: dict) -> bool:
    """Quick heuristic: CVE description or references mention Python ecosystem."""
    cve = cve_obj.get("cve", {})

    # Check English description
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en" and _PY_HINT_RE.search(d.get("value", "")):
            return True

    # Check references for python/github URLs
    for ref in cve.get("references", []):
        url = ref.get("url", "")
        if "pypi.org" in url or "/python/" in url or _PY_HINT_RE.search(url):
            return True

    return False


def _extract_github_commits(cve_obj: dict) -> list[tuple[str, str]]:
    cve = cve_obj.get("cve", {})
    results: list[tuple[str, str]] = []
    for ref in cve.get("references", []):
        m = _COMMIT_RE.match(ref.get("url", ""))
        if m:
            results.append((m.group(1), m.group(2)))
    # Deduplicate while preserving order
    seen: set[tuple[str, str]] = set()
    unique = []
    for item in results:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def _extract_cvss(cve_obj: dict) -> tuple[float | None, str | None, str | None]:
    """Return (base_score, vector_string, severity) preferring CVSS v3.1."""
    metrics = cve_obj.get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            cvss = m.get("cvssData", {})
            score = cvss.get("baseScore")
            vector = cvss.get("vectorString")
            severity = m.get("baseSeverity") or cvss.get("baseSeverity")
            return score, vector, severity
    return None, None, None


# ---------------------------------------------------------------------------
# GitHub commit fetching (mirrors github_advisory_db_scraper.py helpers)
# ---------------------------------------------------------------------------

def _get_commit_info(owner_repo: str, sha: str) -> tuple[str | None, str]:
    url = f"{GITHUB_API}/repos/{owner_repo}/commits/{sha}"
    try:
        resp = requests.get(url, headers=_gh_headers(), timeout=15)
        if resp.status_code == 403:
            logger.warning("GitHub rate limit — sleeping 60s")
            time.sleep(60)
            resp = requests.get(url, headers=_gh_headers(), timeout=15)
        if resp.status_code != 200:
            return None, ""
        data = resp.json()
        parents = data.get("parents", [])
        parent_sha = parents[0]["sha"] if parents else None
        return parent_sha, data.get("commit", {}).get("message", "").strip()
    except Exception as e:
        logger.warning(f"commit_info failed {owner_repo}@{sha}: {e}")
        return None, ""


def _get_changed_py_files(owner_repo: str, sha: str) -> list[str]:
    url = f"{GITHUB_API}/repos/{owner_repo}/commits/{sha}"
    try:
        resp = requests.get(url, headers=_gh_headers(), timeout=15)
        if resp.status_code != 200:
            return []
        return [
            f["filename"] for f in resp.json().get("files", [])
            if f["filename"].endswith(".py")
            and not f["filename"].startswith("test")
            and "/test" not in f["filename"]
            and "/tests" not in f["filename"]
        ]
    except Exception as e:
        logger.warning(f"list_files failed {owner_repo}@{sha}: {e}")
        return []


def _fetch_file_at_ref(owner_repo: str, file_path: str, ref: str) -> str | None:
    url = f"https://raw.githubusercontent.com/{owner_repo}/{ref}/{file_path}"
    try:
        resp = requests.get(url, headers=_gh_headers(), timeout=15)
        return resp.text if resp.status_code == 200 else None
    except Exception as e:
        logger.warning(f"fetch_file failed {url}: {e}")
        return None


def _load_existing_cve_repos() -> set[tuple[str, str, str]]:
    """Return (cve_id, repo, fix_commit) tuples already in MongoDB to skip re-work."""
    try:
        col = get_collection()
        return {
            (doc.get("cve_id"), doc.get("repo"), doc.get("fix_commit"))
            for doc in col.find(
                {"cve_id": {"$exists": True, "$ne": None}},
                {"cve_id": 1, "repo": 1, "fix_commit": 1, "_id": 0},
            )
        }
    except Exception:
        return set()


def _load_existing_hashes() -> set[str]:
    try:
        col = get_collection()
        return {doc["content_hash"] for doc in col.find(
            {"content_hash": {"$exists": True}},
            {"content_hash": 1, "_id": 0},
        )}
    except Exception:
        return set()


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def run(
    output_dir: str = "data/raw",
    target_cwes: list[str] | None = None,
) -> int:
    target_cwes = target_cwes or TARGET_CWES_DEFAULT

    if not NVD_KEY:
        logger.warning("NVD_API_KEY not set — NVD calls will be slow (5 req/30s)")
    if not GH_TOKEN:
        logger.warning("GITHUB_TOKEN not set — GitHub calls will be slow")

    existing_cve_repos = _load_existing_cve_repos()
    existing_hashes = _load_existing_hashes()
    logger.info(
        f"Skip-set: {len(existing_cve_repos)} (cve,repo,sha) tuples, "
        f"{len(existing_hashes)} content hashes already in MongoDB"
    )

    seen_hashes: set[str] = set(existing_hashes)
    processed_commits: set[tuple[str, str]] = set()
    total = 0

    for cwe in target_cwes:
        if cwe not in CWE_VULN_MAP:
            logger.warning(f"Skipping unknown CWE {cwe}")
            continue
        if ("nvd_targeted", cwe) in BLOCKED_SOURCE_CWE:
            logger.info(f"Skipping {cwe} for nvd_targeted (blocked by audit)")
            continue
        vuln_type = CWE_VULN_MAP[cwe]

        logger.info(f"=== NVD targeted scrape for {cwe} ({vuln_type}) ===")
        cves = _fetch_cves_for_cwe(cwe)
        logger.info(f"  {len(cves)} CVEs returned by NVD for {cwe}")

        py_relevant = [c for c in cves if _cve_is_python_relevant(c)]
        logger.info(f"  {len(py_relevant)} look Python-relevant after heuristic filter")

        for cve_obj in py_relevant:
            cve_id = cve_obj.get("cve", {}).get("id", "")
            if not cve_id:
                continue

            commits = _extract_github_commits(cve_obj)
            if not commits:
                continue

            cvss_score, cvss_vector, cvss_severity = _extract_cvss(cve_obj)
            if cvss_score is None and cvss_severity:
                cvss_score = _CVSS_BASE_SCORES.get(cvss_severity.upper())

            for owner_repo, fix_sha in commits:
                # Skip if we've already ingested this CVE/repo/commit combo
                if (cve_id, owner_repo, fix_sha) in existing_cve_repos:
                    continue
                if (owner_repo, fix_sha) in processed_commits:
                    continue
                processed_commits.add((owner_repo, fix_sha))

                parent_sha, commit_msg = _get_commit_info(owner_repo, fix_sha)
                if not parent_sha:
                    continue
                time.sleep(_gh_delay())

                py_files = _get_changed_py_files(owner_repo, fix_sha)
                if not py_files:
                    continue
                time.sleep(_gh_delay())

                for file_path in py_files:
                    code_before = _fetch_file_at_ref(owner_repo, file_path, parent_sha)
                    if not code_before or not code_before.strip():
                        continue
                    # Phase 2B sink-presence gate — replaces the legacy
                    # _passes_code_filter helper. Enforces the same
                    # category-defining sink check used at training time.
                    sink_ok, _ = has_cwe_sink(code_before, cwe, file_path=file_path)
                    if not sink_ok:
                        continue

                    code_after = _fetch_file_at_ref(owner_repo, file_path, fix_sha) or ""
                    if code_before == code_after:
                        continue

                    h = hash_code(code_before)
                    if h in seen_hashes:
                        continue
                    seen_hashes.add(h)

                    framework = detect_framework(code_before)

                    meta = build_meta(
                        {
                            "id":               f"nvd_{vuln_type}_{h}",
                            "source":           "nvd_targeted",
                            "cve_id":           cve_id,
                            "cwe":              cwe,
                            "vuln_type":        vuln_type,
                            "label_source":     "nvd",
                            "label_confidence": "high",
                            "cvss_score":       cvss_score,
                            "cvss_severity":    cvss_severity,
                            "cvss_vector":      cvss_vector,
                            "cvss_source":      "nvd",
                            "nvd_enriched":     cvss_score is not None,
                            "commit_message":   commit_msg,
                            "framework":        framework,
                            "repo":             owner_repo,
                            "file_path":        file_path,
                            "fix_commit":       fix_sha,
                            "vulnerable_commit": parent_sha,
                            "pair_id":          f"{fix_sha[:8]}_{file_path}",
                        },
                        code_before,
                        code_after,
                    )
                    save_code_sample(code_before, meta, output_dir)
                    total += 1
                    logger.info(
                        f"  Saved [{cwe}] {cve_id} — "
                        f"{owner_repo}/{file_path}@{fix_sha[:7]} ({framework})"
                    )
                    time.sleep(0.5)

    logger.info(f"nvd_targeted_scraper finished — {total} new samples saved")
    return total
