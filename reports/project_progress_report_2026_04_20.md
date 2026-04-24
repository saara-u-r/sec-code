# Project Progress Report — April 20, 2026

## Objective

Build a high-authority, AI-driven security analysis pipeline for LLM-generated Flask
applications, focused on real-world vulnerabilities and CVSS-based severity gradients.

---

## Summary of Today's Work

Today's session covered four major areas:

1. Diagnosing and fixing dataset quality problems discovered by a new health check system
2. Writing a full dataset health check and purge pipeline
3. Overhauling all five scraping sources for better precision
4. Building a new OSV.dev scraper as a sixth high-authority data source
5. Identifying future sources for dataset expansion

---

## 1. Dataset Health Check — `scripts/health_check.py`

### What was built

A multi-layer auditing script that evaluates every sample in `data/raw/` across three
independent dimensions:

**Layer 1 — CWE-Specific Pattern Detection**

Each of the four target CWEs gets its own detector:

| CWE | What the detector looks for |
|-----|-----------------------------|
| CWE-89 (SQLi) | Unsafe string formatting inside or feeding into `.execute()` calls; f-strings, `%` formatting, string concat, `.format()`, variable names like `query`/`sql`/`stmt`; ORM-level injection via `.filter()`, `.raw()`, `text()` |
| CWE-78 (CMDi) | `os.system()`, `os.popen()`, `subprocess.run()`, `eval()`, `exec()` calls |
| CWE-22 (Path Traversal) | `open()`, `send_file()`, `send_from_directory()`, `os.path.join()` with user input |
| CWE-502 (Insecure Deser.) | `pickle.loads()`, `yaml.load()` (not safe_load), `marshal.loads()` |

**Layer 2 — Taint Source Detection**

Every sample is checked for a Flask user-input entry point:
```
request.args / request.form / request.data / request.json /
request.values / request.files / request.cookies / request.headers
```
A vulnerability with no taint source is not exploitable by a real attacker.

**Layer 3 — Structural Checks**

- Valid Python syntax (AST parse check)
- Has executable code (strips docstrings and comments, counts remaining lines)
- Has Flask route handler (`@app.route`, `@bp.route`)
- Is likely an attacker PoC script (uses `requests.get/post` + `target_url` keywords)

**Verdict system**

| Status | Meaning |
|--------|---------|
| PASS | Structurally clean + CWE pattern confirmed |
| WARN | Structurally clean + CWE plausible but weak signal |
| FAIL | Invalid syntax, no executable code, or CWE has zero pattern support |
| SKIPPED | `is_vulnerable=False` samples — CWE check not applicable |

**Usage**
```bash
python scripts/health_check.py
python scripts/health_check.py --out reports/health_report.json
python scripts/health_check.py --show-warns
```

---

## 2. Dataset Purge Script — `scripts/purge_bad_samples.py`

### What was built

A safe, configurable cleanup script that removes FAIL-category samples. Always dry-runs
by default — requires `--execute` to actually delete.

**Default purge criteria (all ON)**

| Criterion | What it removes |
|-----------|----------------|
| `--invalid-syntax` | Files Python cannot parse |
| `--no-exec-code` | Pure docstrings / narratives with no executable lines |
| `--attack-pocs` | Attacker-side PoC scripts (sends HTTP requests, not serves them) |

**Optional criteria (OFF by default)**

| Criterion | What it removes | Risk |
|-----------|----------------|------|
| `--false-labels` | CWE label has zero code pattern support | May remove valid snippets with taint in a helper file |
| `--no-flask` | Vulnerable samples with no Flask or `request.*` | May remove legitimate fragments |
| `--source SOURCE` | Limit purge to a single source (e.g. `repo_clone`, `osv`) | Safe |

**Usage**
```bash
python scripts/purge_bad_samples.py              # dry run — shows what would be deleted
python scripts/purge_bad_samples.py --execute    # actually deletes
python scripts/purge_bad_samples.py --execute --source osv
```

---

## 3. First Health Check Results (Pre-Fix)

Running the health check against the original 675-sample dataset revealed:

| Metric | Value |
|--------|-------|
| Total samples | 675 |
| PASS | 227 (33.6%) |
| WARN | 142 |
| FAIL | 249 |
| SKIPPED | 57 |

**Key problems found:**

| Problem | Count | Root Cause |
|---------|-------|-----------|
| Invalid Python syntax | 206 | Cleaner wrapping failed to produce valid Python |
| No executable code | 50 | Exploit-DB narratives wrapped as docstrings, no real code |
| Attacker PoC scripts | 14 | Exploit-DB entries were attack tools, not server code |
| CWE-89 not supported | 20 | GitHub returned files with SQL keywords in comments only |
| No taint source | 82 | Vulnerability exists but uses hardcoded input, not `request.*` |

**Source breakdown:**

| Source | PASS | WARN | FAIL | SKIP |
|--------|------|------|------|------|
| repo_clone | 0 | 42 | 178 | 57 |
| github | 227 | 94 | 57 | 0 |
| exploitdb | 0 | 6 | 14 | 0 |

The 277 `pallets/flask` samples (framework source code) produced 178 FAILs with no CWE
and 57 valid secure samples. No useful vulnerable content at all.

---

## 4. Scraper Overhaul

### A. `repo_cloner.py` — Removed `pallets/flask`, added 4 new repos

**Removed:** `pallets/flask`
- Generated 277 samples with no CWE
- Framework internals (not app-level vulnerable code)
- 178 FAIL, 57 SKIPPED, 42 WARN — zero PASS

**Added:**

| Repo | Vulnerabilities |
|------|----------------|
| `incredibleindishell/Damn-Vulnerable-Flask-App` | CWE-89, CWE-78, CWE-22 |
| `adeyosemanputra/pygoat` | CWE-89, CWE-78, CWE-502 |
| `ethicalhack3r/DVWA` | CWE-89, CWE-78, CWE-22 |
| `DevSlop/Pixi` | CWE-89, CWE-502 |

All four are deliberately vulnerable applications built for security training.

### B. `exploitdb_scraper.py` — Added server-side code filter

Added `is_server_side_code()` function that distinguishes between:

| Type | Signal | Action |
|------|--------|--------|
| Server-side vulnerable app | `from flask` import OR `request.*` access | Keep |
| Attacker PoC script | `requests.get/post` + `target_url`/`victim` keywords | Skip |
| Raw snippet (no clear signal) | Has a vulnerability pattern | Keep |

This fixed all 14 attacker PoC scripts that were mislabeled as `is_vulnerable=True`.

### C. `github_scraper.py` — Rewrote all queries (10 → 28)

**Core change:** Added `"app.route"` requirement to all queries.

```
OLD: language:python flask "execute(f\"SELECT"
     → matches test files, migration scripts, utility modules

NEW: language:python "app.route" "execute(f" SELECT
     → only matches files with a Flask endpoint AND the vulnerable pattern
```

**New query count per CWE:**

| CWE | Queries |
|-----|---------|
| CWE-89 (SQLi) | 7 |
| CWE-78 (CMDi) | 7 |
| CWE-22 (Path Traversal) | 7 |
| CWE-502 (Insecure Deser.) | 7 |
| **Total** | **28** |

Additional taint-flow specific queries added:
- `"request.args.get" "SELECT"` — catches multi-line SQLi
- `"pickle.loads" "request.cookies"` — catches cookie-based deserialization

---

## 5. New OSV.dev Scraper — `src/generator/scraper/osv_scraper.py`

### What was built

A new scraper that queries Google's Open Source Vulnerability database (OSV.dev) to get
authoritative, CVE-attributed vulnerable code.

### Pipeline

```
POST https://api.osv.dev/v1/query (per package)
    ↓
Filter by CWE (database_specific.cwe_ids)
    ↓
Extract GitHub fix commit SHA from references[]
    ↓
GET /repos/{owner}/{repo}/commits/{fix_sha} → find parent SHA
    ↓
GET /repos/{owner}/{repo}/commits/{fix_sha} → list changed .py files
    ↓
Fetch file content at parent SHA (the vulnerable version)
    ↓
Save with CVE ID + authoritative CWE label
```

### Why OSV is higher quality than GitHub search

| Dimension | GitHub Scraper | OSV Scraper |
|-----------|---------------|-------------|
| CWE label | Inferred from query | Official advisory |
| CVE ID | Rarely available | Always available |
| Vulnerability confirmation | Pattern match | CVE record |
| Code precision | Full file | Pre-fix file at exact commit |

### Initial packages queried

```
flask, werkzeug, django, sqlalchemy, pyyaml,
paramiko, bottle, tornado, aiohttp
```

### Problem discovered after first run

After running all scrapers and re-running the health check (1101 samples), OSV showed:
```
osv:  2 PASS  77 WARN  146 FAIL
```

Root cause: Packages like `werkzeug`, `sqlalchemy`, `paramiko` have CVEs in their
**library internals** (e.g. `sqlalchemy/orm/query.py`). This code has no Flask import
and no `request.*` taint source — it's not application code, it's framework code.

### Fix applied

1. Narrowed `TARGET_PACKAGES` to Flask ecosystem only:
   ```python
   ["flask", "flask-login", "flask-sqlalchemy", "flask-restful",
    "flask-wtf", "django", "bottle", "pyyaml"]
   ```

2. Added `_is_app_level_code()` filter — skips files that have neither a web
   framework import nor a `request.*` taint source before saving.

This fix applies to future scraping runs. Existing bad OSV samples are cleaned with:
```bash
python scripts/purge_bad_samples.py --execute --source osv
```

---

## 6. CWE-89 Detector Improvement

### Problem

The original health check missed multi-line SQL injection:

```python
# MISSED — concat happens outside execute()
query = "SELECT * FROM users WHERE id=" + request.args.get("id")
cursor.execute(query)

# CAUGHT — concat happens inside execute()
cursor.execute("SELECT * FROM users WHERE id=" + request.args.get("id"))
```

### Fix

Extended `check_cwe89()` in `health_check.py` with two new pattern categories:

**Multi-line patterns** — unsafe SQL string built in a variable:
```python
(query|sql|stmt) = f"SELECT..."          ← f-string assignment
(query|sql|stmt) = "SELECT..." + var     ← concat assignment
(query|sql|stmt) = "SELECT..." % var     ← % formatting assignment
(query|sql|stmt) = "...".format(...)     ← .format() assignment
```

**ORM-level injection patterns** — SQLAlchemy / Django ORM:
```python
.filter(f"col = {val}")      ← f-string in filter()
.raw(f"SELECT...")           ← f-string in raw query
text(f"SELECT...")           ← SQLAlchemy text() with f-string
text("SELECT..." + var)      ← concat in text()
```

Same patterns mirrored in `purge_bad_samples.py` for consistency.

**Verified with unit tests:**
```
Multi-line SQLi  → confident: True  ✓
Inline SQLi      → confident: True  ✓
ORM SQLi         → confident: True  ✓
```

---

## 7. Second Health Check Results (Post-Fix Scrape)

After running all improved scrapers, the dataset grew to 1101 samples:

| Metric | Before (675) | After (1101) | Change |
|--------|-------------|--------------|--------|
| Total samples | 675 | 1101 | +426 |
| PASS | 227 (33.6%) | 566 (51.4%) | +339 / +17.8pp |
| WARN | 142 | 217 | +75 |
| FAIL | 249 | 261 | +12 |
| SKIPPED | 57 | 57 | — |

**By CWE (after):**

| CWE | PASS | WARN | FAIL | SKIP |
|-----|------|------|------|------|
| CWE-22 | 164 | 40 | 36 | 0 |
| CWE-502 | 162 | 29 | 25 | 0 |
| CWE-78 | 156 | 20 | 37 | 0 |
| CWE-89 | 84 | 128 | 163 | 0 |
| (no CWE) | 0 | 0 | 0 | 57 |

**By source (after):**

| Source | PASS | WARN | FAIL | SKIP |
|--------|------|------|------|------|
| github | 564 | 138 | 100 | 0 |
| osv | 2 | 77 | 146 | 0 |
| repo_clone | 0 | 0 | 9 | 57 |
| exploitdb | 0 | 2 | 6 | 0 |

**Remaining top issues:**

| Issue | Count | Action |
|-------|-------|--------|
| No Flask request.* taint source | 306 | Accept as WARN — taint may be in helper file |
| CWE-89 not supported by code patterns | 144 | Purge — scraping noise |
| Invalid Python syntax | 69 | Purge |
| CWE-89 plausible but not confirmed | 103 | Keep as WARN |

---

## 8. Run.py — OSV Added as 5th Source

```python
ALL_SOURCES = ["repo", "github", "cvefixes", "exploitdb", "osv"]
```

The pipeline now supports running individual scrapers in isolation:

```bash
python -m src.generator.run --sources osv
python -m src.generator.run --sources github osv
python -m src.generator.run               # all 5
```

---

## 9. Identified Future Data Sources

The following sources were identified for future expansion, in priority order:

| Priority | Source | Why | Effort |
|----------|--------|-----|--------|
| 1 | **CVEfixes DB** | Already written (`cvefixes_loader.py`), just needs 1 GB download | 0 code |
| 2 | **Semgrep rules test corpus** | Curated, labeled, gives secure samples too | ~1 day |
| 3 | **GitHub Security Advisories API** | Fills OSV gaps, different coverage | ~2 hours |
| 4 | **More vulnerable repos** | Search GitHub repo names for Flask vuln apps | 30 min |
| 5 | **SecurityEval dataset** | 130 Python samples, perfectly labeled for security eval | 1 hour |
| 6 | **PyPA Advisory DB** | Flask ecosystem focused, structured YAML | ~3 hours |
| 7 | **MegaVul / VulBench** | Academic datasets with CWE labels | Variable |

**Key note on CVEfixes:** This source is already fully implemented and is the single
biggest untapped source in the pipeline. If `data/cvefixes/CVEfixes.db` does not exist,
running `python -m src.generator.run --sources cvefixes` will download it and potentially
add hundreds of high-quality samples.

---

## 10. Files Created / Modified Today

| File | Status | Purpose |
|------|--------|---------|
| `scripts/health_check.py` | **New** | Multi-layer dataset auditor |
| `scripts/purge_bad_samples.py` | **New** | Safe cleanup of FAIL samples |
| `src/generator/scraper/osv_scraper.py` | **New** | OSV.dev API scraper |
| `src/generator/scraper/repo_cloner.py` | **Modified** | Removed pallets/flask, added 4 vuln repos |
| `src/generator/scraper/exploitdb_scraper.py` | **Modified** | Added server-side code filter |
| `src/generator/scraper/github_scraper.py` | **Modified** | 10 → 28 queries, `@app.route` required |
| `src/generator/run.py` | **Modified** | Added `osv` as 5th source |
| `reports/script_explanations_2026_04_20.md` | **New** | Full logic explanation of all scripts |
| `reports/scraping_pipeline_explained_2026_04_20.md` | **New** | Scraping pipeline documentation |

---

## 11. Current Dataset Status

| Metric | Value |
|--------|-------|
| Total raw samples | 1101 |
| PASS (clean, usable) | 566 |
| WARN (medium confidence) | 217 |
| FAIL (to be purged) | 261 |
| SKIPPED (secure/negative class) | 57 |
| Effective training samples (post-purge) | ~840 |
| Pass rate (vulnerable samples only) | 51.4% |

---

## 12. Immediate Next Steps

```bash
# Step 1: Clean the 261 bad samples
python scripts/purge_bad_samples.py --execute

# Step 2: Clean bad OSV samples specifically
python scripts/purge_bad_samples.py --execute --source osv

# Step 3: Check if CVEfixes DB exists — biggest untapped source
ls -lh data/cvefixes/

# Step 4: If CVEfixes not downloaded, run it
python -m src.generator.run --sources cvefixes

# Step 5: Re-scrape OSV with the fixed package list
python -m src.generator.run --sources osv

# Step 6: Re-run health check to confirm improvement
python scripts/health_check.py --out reports/health_report_post_purge.json
```

Once the dataset is clean (~840+ usable samples), the project is ready to move to:

**Phase 2 — CVE Attribution:** Build `src/labeler/cve_enricher.py` to search for
official security advisories matching the 840 snippets and link them to confirmed CVE IDs.

---

## Phase Roadmap Status

| Phase | Title | Status |
|-------|-------|--------|
| 1 | Ingestion | **Complete (improved)** |
| 2 | CVE Attribution | Pending |
| 3 | CVSS Gradient Mapping | Pending |
| 4 | Dataset Construction | Planned |
| 5 | ML Defense | Planned |
| 6 | Red Team | Planned |
| 7 | Feedback Loop | Planned |
