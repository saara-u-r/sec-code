"""
github_advisory_db_scraper.py — Phase 1, CVE-linked source

Scrapes the GitHub Advisory Database (https://github.com/github/advisory-database),
GitHub's comprehensive, manually-reviewed collection of security advisories for
open-source software.

Why this source?
  - Every advisory is marked github_reviewed=true — manually vetted by GitHub's
    security team, not auto-generated
  - All code comes from real production PyPI packages, not synthetic examples
  - Contains CVSS v3 vectors directly in the advisory — no NVD lookup needed
    for these samples (nvd_enriched set to True immediately)
  - Covers many more CVEs than the GHSA GraphQL API returns in paginated queries
  - OSV-compatible JSON format, same structure as pypa_scraper

Pipeline:
  1. Shallow-clone github/advisory-database (cached after first run)
  2. Walk advisories/github-reviewed/**/*.json
  3. Filter: PyPI ecosystem + github_reviewed=true + target CWE
  4. Skip advisories whose GHSA ID was already ingested via ghsa_scraper
  5. Extract fix commits from references and affected[].ranges
  6. Fetch code_before (parent commit) and code_after (fix commit) via GitHub API
  7. Parse CVSS vector from advisory — no Phase 3 enrichment needed
  8. Save with label_confidence="high" (GitHub-reviewed ground truth)
"""

import json
import os
import re
import subprocess
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

from src.utils.cwe_taxonomy import BLOCKED_SOURCE_CWE, CWE_VULN_MAP
from src.utils.file_utils import (
    build_meta,
    detect_framework,
    has_cwe_sink,
    hash_code,
    parse_cvss_vector,
    save_code_sample,
)
from src.utils.logger import get_logger
from src.utils.mongo_writer import get_collection

load_dotenv()
logger = get_logger(__name__)

GITHUB_API = "https://api.github.com"
TOKEN = os.getenv("GITHUB_TOKEN", "")

GHSA_DB_REPO_URL = "https://github.com/github/advisory-database"
GHSA_DB_LOCAL_DIR = "data/github_advisory_db"

_COMMIT_RE = re.compile(
    r"https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})",
    re.IGNORECASE,
)

# CVSS score extraction from vector string
_CVSS_BASE_SCORES = {
    # Approximate base score from severity label when vector unavailable
    "CRITICAL": 9.5,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      2.5,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gh_headers() -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if TOKEN:
        h["Authorization"] = f"Bearer {TOKEN}"
    return h


def _sleep(seconds: float) -> None:
    logger.debug(f"Sleeping {seconds:.1f}s…")
    time.sleep(seconds)


def _clone_or_update(local_dir: str) -> bool:
    dest = Path(local_dir)
    if (dest / ".git").exists():
        logger.info(f"GitHub Advisory DB already cloned at {local_dir} — pulling latest")
        result = subprocess.run(
            ["git", "-C", local_dir, "pull", "--ff-only"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            logger.warning(f"git pull failed: {result.stderr[:200]}")
        return True

    logger.info(f"Cloning GitHub Advisory Database to {local_dir} (this may take a minute)…")
    dest.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", "clone", "--depth=1", GHSA_DB_REPO_URL, local_dir],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.error(f"git clone failed: {result.stderr[:300]}")
        return False
    logger.info("GitHub Advisory Database cloned successfully")
    return True


def _extract_cwe(advisory: dict) -> str | None:
    """Return the first target CWE from an advisory's database_specific.cwe_ids."""
    db = advisory.get("database_specific", {}) or {}
    for cwe in db.get("cwe_ids", []):
        if cwe in CWE_VULN_MAP:
            return cwe
    return None


def _is_pypi_advisory(advisory: dict) -> bool:
    """True if any affected package is from the PyPI ecosystem."""
    for affected in advisory.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem", "").lower() == "pypi":
            return True
    return False


def _extract_cvss(advisory: dict) -> tuple[float | None, str | None]:
    """Return (base_score, vector_string) from the advisory's severity array."""
    for sev in advisory.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            vector = sev.get("score", "")
            # GitHub Advisory DB embeds the full CVSS vector string
            # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            # Compute base score from vector components
            score = _compute_base_score_from_vector(vector)
            return score, vector
    # Fallback: use severity label
    db = advisory.get("database_specific", {}) or {}
    severity = db.get("severity", "").upper()
    return _CVSS_BASE_SCORES.get(severity), None


def _compute_base_score_from_vector(vector: str) -> float | None:
    """
    Approximate CVSS v3.1 base score from a vector string.
    Uses the NVD severity band mapping since computing the exact score
    requires the full formula. Samples get their precise score from NVD in Phase 3
    when nvd_enriched=False; we set nvd_enriched=True here only when we have a
    full vector and high confidence.
    """
    if not vector:
        return None
    try:
        parts = {p.split(":")[0]: p.split(":")[1] for p in vector.split("/")[1:] if ":" in p}
        # Use impact + exploitability components to approximate
        av  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(parts.get("AV", ""), 0)
        ac  = {"L": 0.77, "H": 0.44}.get(parts.get("AC", ""), 0)
        pr_scope_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_scope_changed   = {"N": 0.85, "L": 0.68, "H": 0.50}
        scope = parts.get("S", "U")
        pr  = (pr_scope_changed if scope == "C" else pr_scope_unchanged).get(parts.get("PR", ""), 0)
        ui  = {"N": 0.85, "R": 0.62}.get(parts.get("UI", ""), 0)
        c   = {"N": 0.0, "L": 0.22, "H": 0.56}.get(parts.get("C", ""), 0)
        i   = {"N": 0.0, "L": 0.22, "H": 0.56}.get(parts.get("I", ""), 0)
        a   = {"N": 0.0, "L": 0.22, "H": 0.56}.get(parts.get("A", ""), 0)
        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        if impact <= 0:
            return 0.0
        exploitability = 8.22 * av * ac * pr * ui
        if scope == "U":
            raw = min(impact + exploitability, 10)
        else:
            raw = min(1.08 * (impact + exploitability), 10)
        # Round up to one decimal
        import math
        return math.ceil(raw * 10) / 10
    except Exception:
        return None


def _extract_fix_commits(advisory: dict) -> list[tuple[str, str]]:
    """Return (owner/repo, sha) pairs from references and affected[].ranges."""
    results: list[tuple[str, str]] = []

    for ref in advisory.get("references", []):
        url = ref.get("url", "") if isinstance(ref, dict) else str(ref)
        m = _COMMIT_RE.match(url)
        if m:
            results.append((m.group(1), m.group(2)))

    for affected in advisory.get("affected", []):
        if affected.get("package", {}).get("ecosystem", "").lower() != "pypi":
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            repo_url = rng.get("repo", "")
            if "github.com" not in repo_url:
                continue
            m = re.search(r"github\.com/([^/]+/[^/]+?)(?:\.git)?$", repo_url)
            if not m:
                continue
            owner_repo = m.group(1)
            for event in rng.get("events", []):
                sha = event.get("fixed", "")
                if sha and len(sha) >= 7:
                    results.append((owner_repo, sha))

    # Deduplicate while preserving order
    seen: set[tuple[str, str]] = set()
    unique = []
    for item in results:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def _get_commit_info(owner_repo: str, sha: str) -> tuple[str | None, str]:
    """Return (parent_sha, commit_message) for a given commit."""
    url = f"{GITHUB_API}/repos/{owner_repo}/commits/{sha}"
    try:
        resp = requests.get(url, headers=_gh_headers(), timeout=15)
        if resp.status_code == 403:
            logger.warning("GitHub rate limit — sleeping 60s")
            _sleep(60)
            resp = requests.get(url, headers=_gh_headers(), timeout=15)
        if resp.status_code != 200:
            return None, ""
        data = resp.json()
        parents = data.get("parents", [])
        parent_sha = parents[0]["sha"] if parents else None
        commit_msg = data.get("commit", {}).get("message", "").strip()
        return parent_sha, commit_msg
    except Exception as e:
        logger.warning(f"Failed to get commit info for {owner_repo}@{sha}: {e}")
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
        logger.warning(f"Failed to list files for {owner_repo}@{sha}: {e}")
        return []


def _fetch_file_at_ref(owner_repo: str, file_path: str, ref: str) -> str | None:
    url = f"https://raw.githubusercontent.com/{owner_repo}/{ref}/{file_path}"
    try:
        resp = requests.get(url, headers=_gh_headers(), timeout=15)
        return resp.text if resp.status_code == 200 else None
    except Exception as e:
        logger.warning(f"Failed to fetch {url}: {e}")
        return None


def _load_already_scraped_ghsa_ids() -> set[str]:
    """Load GHSA IDs already in MongoDB from the ghsa_scraper to avoid reprocessing."""
    try:
        col = get_collection()
        ids = {doc["ghsa_id"] for doc in col.find(
            {"source": "ghsa", "ghsa_id": {"$exists": True, "$ne": None}},
            {"ghsa_id": 1, "_id": 0},
        )}
        return ids
    except Exception:
        return set()


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def run(output_dir: str = "data/raw") -> int:
    if not _clone_or_update(GHSA_DB_LOCAL_DIR):
        return 0

    if not TOKEN:
        logger.warning(
            "GITHUB_TOKEN not set — rate limits will slow this scraper significantly."
        )

    already_scraped = _load_already_scraped_ghsa_ids()
    logger.info(f"Skipping {len(already_scraped)} GHSA IDs already in MongoDB from ghsa_scraper")

    advisory_dir = Path(GHSA_DB_LOCAL_DIR) / "advisories" / "github-reviewed"
    if not advisory_dir.exists():
        logger.error(f"Advisory directory not found: {advisory_dir}")
        return 0

    json_files = list(advisory_dir.rglob("*.json"))
    logger.info(f"GitHub Advisory DB: {len(json_files)} reviewed advisory files found")

    delay = 1.5 if TOKEN else 6.0
    total = 0
    processed_commits: set[tuple[str, str]] = set()

    for json_path in json_files:
        try:
            with open(json_path, encoding="utf-8") as f:
                advisory = json.load(f)
        except Exception as e:
            logger.debug(f"Failed to parse {json_path}: {e}")
            continue

        if not advisory:
            continue

        # Skip non-Python advisories early (fast filter)
        if not _is_pypi_advisory(advisory):
            continue

        # Skip if this GHSA was already fully scraped via the GraphQL scraper
        ghsa_id = advisory.get("id", "")
        if ghsa_id in already_scraped:
            logger.debug(f"Skipping {ghsa_id} — already in MongoDB")
            continue

        # Must have a target CWE
        cwe = _extract_cwe(advisory)
        if not cwe:
            continue
        if ("ghsa_db", cwe) in BLOCKED_SOURCE_CWE:
            continue

        vuln_type = CWE_VULN_MAP[cwe]
        cve_id = next(
            (a for a in advisory.get("aliases", []) if a.startswith("CVE-")),
            None,
        )

        cvss_score, cvss_vector = _extract_cvss(advisory)
        cvss_fields = parse_cvss_vector(cvss_vector)

        fix_commits = _extract_fix_commits(advisory)
        if not fix_commits:
            continue

        for owner_repo, fix_sha in fix_commits:
            commit_key = (owner_repo, fix_sha)
            if commit_key in processed_commits:
                continue
            processed_commits.add(commit_key)

            parent_sha, commit_msg = _get_commit_info(owner_repo, fix_sha)
            if not parent_sha:
                continue
            _sleep(delay)

            py_files = _get_changed_py_files(owner_repo, fix_sha)
            if not py_files:
                continue
            _sleep(delay)

            for file_path in py_files:
                code_before = _fetch_file_at_ref(owner_repo, file_path, parent_sha)
                if not code_before or not code_before.strip():
                    continue

                # Phase 2B: sink-presence gate replaces is_web_code()
                sink_ok, _ = has_cwe_sink(code_before, cwe, file_path=file_path)
                if not sink_ok:
                    continue

                code_after = _fetch_file_at_ref(owner_repo, file_path, fix_sha) or ""
                if code_before == code_after:
                    continue

                h = hash_code(code_before)
                framework = detect_framework(code_before)

                meta = build_meta(
                    {
                        "id":               f"ghsa_db_{vuln_type}_{h}",
                        "source":           "ghsa_db",
                        "ghsa_id":          ghsa_id,
                        "cve_id":           cve_id,
                        "cwe":              cwe,
                        "vuln_type":        vuln_type,
                        "label_source":     "github_advisory_db",
                        "label_confidence": "high",
                        "cvss_score":       cvss_score,
                        "cvss_severity":    (advisory.get("database_specific") or {}).get("severity"),
                        "cvss_source":      "ghsa",
                        "nvd_enriched":     cvss_score is not None,
                        **cvss_fields,
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
                    f"  Saved [{cwe}] {ghsa_id} — "
                    f"{owner_repo}/{file_path}@{fix_sha[:7]} ({framework})"
                )
                _sleep(0.5)

    logger.info(f"github_advisory_db_scraper finished — {total} new samples saved")
    return total
