# Project Progress Report — April 21, 2026

## Objective

Build a high-authority, AI-driven security analysis pipeline for LLM-generated Flask
applications, focused on real-world vulnerabilities and CVSS-based severity gradients.

---

## Summary of Today's Work

Today's session focused entirely on overhauling Phase 1 (data scraping) for maximum
data quality, fixing all broken sources, and running the full pipeline to completion.

---

## 1. Scraper Quality Overhaul

### Problems identified

| # | Problem | Impact |
|---|---|---|
| 1 | github/osv/exploitdb saved whole files, not route snippets | Noisy labels — 1000-line file labeled as a single vuln type |
| 2 | `cvefixes_loader` discarded `code_after` (secure samples) | Lost all authoritative `is_vulnerable=False` labels from CVEs |
| 3 | Dataset had almost zero secure samples | Model would not learn to distinguish safe from vulnerable code |
| 4 | Django included as a scraping target | Wrong scope — Flask only |
| 5 | Cleaner wrapped invalid syntax in docstrings instead of dropping | Garbage samples (writeups, README text) kept in dataset |
| 6 | GitHub scraper labeled by query, not by code content | False positives — file matched query but didn't contain the pattern |
| 7 | repo_cloner assigned repo's primary vuln_type to every snippet | Mislabeled snippets (e.g. a command injection route labeled as sql_injection) |
| 8 | No minimum code length filter | 2-3 line stubs saved as training samples |
| 9 | Dedup only worked within a single run | Re-running scrapers produced duplicates |

### Fixes implemented

**`src/utils/file_utils.py` — new shared helpers**
- `is_flask_file()`, `extract_flask_routes()` — AST-based route extraction shared across all scrapers
- `detect_vuln_type()` — regex pattern matcher for all 4 CWE types, used to verify labels post-download
- `has_taint_source()`, `is_secure_sample()` — used by github_scraper to verify secure routes
- `_VULN_PATTERNS` and `_SECURE_PATTERNS` — pattern libraries for sql_injection, command_injection, path_traversal, insecure_deserialization

**`github_scraper.py`**
- Extracts Flask routes from downloaded files instead of saving whole files
- Verifies `detect_vuln_type(snippet) == vuln_type` before saving — drops false positives
- Added `SECURE_QUERIES` pass that finds files using safe patterns (parameterized queries, `secure_filename`, `yaml.safe_load`, etc.) and saves verified clean routes as `is_vulnerable=False`

**`osv_scraper.py`**
- Removed `django` from `TARGET_PACKAGES` and `_WEB_FRAMEWORK` regex
- Extracts Flask routes per file instead of saving whole files

**`exploitdb_scraper.py`**
- Removed `django` from `is_python_exploit()`
- Requires `is_flask_file()` and extracts routes before saving

**`cvefixes_loader.py`**
- Now saves `code_after` as `is_vulnerable=False` — was previously thrown away
- Fixed Zenodo URL (migrated from `/record/` to `/records/`, file is now a ZIP not a bare `.db`)
- Fixed ZIP extraction: SQL dump streamed via `Popen` into `sqlite3` CLI to avoid loading ~10 GB into RAM
- Fixed query to match actual v1.0.7 schema (`file_change.code_before/code_after`, `cwe_classification.cwe_id`)

**`repo_cloner.py`**
- Removed local `is_flask_file` / `extract_flask_routes` (now shared from file_utils)
- Per-snippet `detect_vuln_type()` — only saves a snippet if its detected vuln type matches the repo's declared types; unlabeled snippets are dropped
- Replaced 4 dead/wrong repos (`we45t/Vulnerable-Flask-App` 404, `christophetd/flask-vulnerable-app` 404, `ethicalhack3r/DVWA` not Flask, `DevSlop/Pixi` not Flask) with verified live Flask repos that have vulnerabilities directly in route handlers

**`cleaner.py`**
- Drops invalid syntax files instead of wrapping them in docstrings
- Drops snippets with fewer than 5 non-blank, non-comment lines
- Fixed persistent dedup: now builds `seen` set fresh from disk each run, then overwrites `.seen_hashes` — previous implementation incorrectly deleted valid files on re-runs

---

## 2. Source Fixes

### CVEfixes (Zenodo)

The original URL (`https://zenodo.org/record/7029359/files/CVEfixes.db`) returned 404.
Zenodo migrated its URL scheme and replaced the bare `.db` with a ZIP containing a
gzipped SQL dump.

**Fix chain:**
1. Updated URL → `https://zenodo.org/records/7029359/files/CVEfixes_v1.0.7.zip`
2. Added ZIP download + SQL dump extraction via streaming `Popen` (avoids loading ~10 GB into memory)
3. Added `_db_is_valid()` check so a partial/corrupted DB is detected and rebuilt
4. Fixed query to use actual v1.0.7 schema (schema introspected at runtime to confirm column names)

### repo_cloner — replaced repos

| Old repo | Status | Replacement | Vuln types |
|---|---|---|---|
| `we45t/Vulnerable-Flask-App` | 404 | `JasonHinds13/hackable` | sql_injection (inline in routes) |
| `christophetd/flask-vulnerable-app` | 404 | `BrenesRM/insecure-web` | sql_injection (inline in routes) |
| `ethicalhack3r/DVWA` | Not Flask | `abhinandanpandey-in/Command-Injection-Lab` | command_injection (inline in routes) |
| `DevSlop/Pixi` | Not Flask | *(removed)* | — |

All replacements were verified to have vulnerability patterns directly inside `@app.route`
handlers, not delegated to helper functions.

---

## 3. Dataset State (as of April 21, 2026)

> Note: github scraper still running at time of report. Counts below are live.

### Sample counts

| Source | Samples |
|---|---|
| github | 237 (in progress, expected ~634) |
| cvefixes | 176 |
| repo_clone | 2 |
| **Total** | **415** |

### By vulnerability type

| Type | CWE | Count |
|---|---|---|
| sql_injection | CWE-89 | 256 |
| path_traversal | CWE-22 | 98 |
| command_injection | CWE-78 | 33 |
| insecure_deserialization | CWE-502 | 28 |

### By label

| Label | Count |
|---|---|
| vulnerable | 325 |
| secure | 90 |

---

## 4. Outstanding Issues

### Sources producing 0 samples

| Source | Reason |
|---|---|
| `exploitdb` | Removed Django scope; remaining Flask-specific entries are attacker PoCs, not server-side code |
| `osv` | 24 advisories found (flask, bottle, pyyaml) but all live in library internals — none pass `is_flask_file` + `extract_flask_routes` filter |

### Class imbalance

- `sql_injection` is over-represented (256 of 415) vs `insecure_deserialization` (28)
- Secure samples (90) are significantly fewer than vulnerable (325)
- cvefixes is the primary source of secure samples — expanding it (or finding another paired before/after source) is the highest-value next step

### repo_cloner yield is low

Only 3 snippets saved across 4 repos. `BrenesRM/insecure-web` still saves 0 — its routes
use `f"SELECT ... {username}"` style which requires investigating whether the pattern regex
needs tuning.

---

## 5. Next Steps

1. Let github scraper finish and confirm final count (~634 expected)
2. Investigate and fix 0-sample repos (`BrenesRM/insecure-web`)
3. Address class imbalance — find more `command_injection` and `insecure_deserialization` sources
4. Address label imbalance — more secure samples needed
5. Move to Phase 2 (labeling / analysis)
