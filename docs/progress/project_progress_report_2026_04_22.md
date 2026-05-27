# Project Progress Report — April 22, 2026

## Objective

Build a high-authority, AI-driven security analysis pipeline for real-world Python
vulnerabilities, focused on CVE-linked code with CVSS-based severity gradients.

---

## Major Direction Change (Professor Feedback)

Today's session pivoted the entire project based on professor feedback across four axes:

| Constraint | Old approach | New approach |
|---|---|---|
| Data quality | Mix of real + deliberate vuln apps | Real-world CVE-linked commits only |
| Labels | Binary `is_vulnerable: True/False` | CVSS base score (0.0–10.0) as gradient |
| Scope | Flask only | All Python web frameworks |
| Detection | Regex `detect_vuln_type()` on code | Commit message NLP classifier |

---

## Revised Phase Roadmap

| Phase | Title | Status |
|-------|-------|--------|
| 1 | Ingestion — CVE-linked real-world code | **In progress** |
| 2 | Commit Message Classification (CWE prediction) | Planned |
| 3 | CVSS Gradient Enrichment via NVD API | Planned |
| 4 | Dataset Construction | Planned |
| 5 | ML Defense (CodeBERT fine-tune) | Planned |
| 6 | Red Team | Planned |
| 7 | Feedback Loop | Planned |

---

## Phase 1 — Data Ingestion (Revised)

### Sources removed

| Source | Reason |
|---|---|
| `repo_cloner.py` | Scrapes deliberate vuln apps (DVWA, pygoat) — not real-world code |
| `exploitdb_scraper.py` | Attacker-side PoC scripts — not app code |
| `github_scraper.py` | Keyword pattern search with no CVE confirmation — too noisy |

### Sources kept

| Source | Why |
|---|---|
| `cvefixes_loader.py` | 1,754 real CVEs → method-level diffs. Highest quality source. Flask gate removed. |
| `osv_scraper.py` | Real CVE advisories → fix commits. Expanded beyond Flask to all Python web frameworks. |

### Sources added

| Source | File | Why |
|---|---|---|
| GitHub Security Advisories (GHSA) | `ghsa_scraper.py` | GraphQL API with structured CWE IDs, fix commit SHAs, CVSS scores. Covers different CVEs than OSV. |
| PyPA Advisory Database | `pypa_scraper.py` | Python-specific structured YAML advisories. Cloned once, parsed locally. |

### Core principle

Every sample must trace back to a confirmed CVE. No pattern-matched code, no
educational repos.

---

## Phase 2 — Commit Message Classification (new, replaces regex)

### Why commit messages instead of regex

Commit messages are written by the developer who fixed the bug. They encode semantic
intent that code patterns cannot capture reliably. "Fix SQL injection in login handler"
is more reliable than checking if `execute(f"` appears in the code.

### Pipeline

```
Commit message text  →  CWE classifier  →  CWE-89 / CWE-78 / CWE-22 / CWE-502 / other
```

### Training data

CVEfixes provides thousands of commit messages each tagged with a confirmed NVD CWE —
this is the supervised training set.

### Model plan

| Stage | Model | Effort | Est. accuracy |
|---|---|---|---|
| Baseline | TF-IDF + SVM | 1 hour | ~75% |
| Better | Fine-tune DistilBERT | 1 day | ~88% |
| Best | Fine-tune CodeBERT | 2 days | ~92% |

Start with TF-IDF + SVM as a fast baseline; fine-tune DistilBERT to show NLP depth.

### Validation

For every CVE-linked sample, the NVD API returns the official CWE — used to evaluate
classifier accuracy independent of the training signal.

---

## Phase 3 — CVSS Gradient Enrichment (revised)

### Problem with old approach

`config.yaml` assigned flat default scores (e.g. `sql_injection: 9.8`) to all samples
of a given type. That is not a gradient — it is a lookup table.

### New approach

```
CVE ID  →  NVD REST API v2.0  →  CVSS v3.1 base score (per-CVE, e.g. 7.3)
```

Each sample gets its own score. Two SQLi bugs with different attack vectors and CIA
impact profiles will have different CVSS scores. That per-sample variation is the
signal the model should learn to predict.

### Additional fields stored

`attackVector`, `attackComplexity`, `privilegesRequired`, `confidentialityImpact`,
`integrityImpact`, `availabilityImpact` — stored as metadata for richer feature
engineering in Phase 5.

---

## Phase 4 — Dataset Schema (revised)

```json
{
  "id": "cvefixes_CWE-89_abc123",
  "source": "cvefixes",
  "cve_id": "CVE-2021-1234",
  "cwe": "CWE-89",
  "vuln_type": "sql_injection",
  "cvss_score": 7.3,
  "cvss_severity": "HIGH",
  "cvss_attack_vector": "NETWORK",
  "cvss_complexity": "LOW",
  "cvss_privileges_required": "NONE",
  "cvss_confidentiality": "HIGH",
  "cvss_integrity": "LOW",
  "cvss_availability": "NONE",
  "code_before": "...",
  "code_after": "...",
  "commit_message": "...",
  "repo": "...",
  "file_path": "...",
  "framework": "django",
  "timestamp": "..."
}
```

No `is_vulnerable` field. No `is_secure` field. The before/after pair is the unit;
CVSS score is the severity label.

---

## Phase 5 — ML Model (revised)

| Aspect | Old | New |
|---|---|---|
| Model | Random Forest on regex features | CodeBERT / GraphCodeBERT fine-tuned |
| Input | Code snippet with pattern flags | `(code_before, commit_message)` |
| Target | Binary vuln/not-vuln | CVSS score (regression) + CWE (classification) |
| Baseline | — | Random Forest on AST features (comparison) |
| Eval set | OSV samples | OSV holdout (external ground truth) |

---

## Implementation Priority

```
Priority 1 — Phase 1 foundation (today)
  ✓ Drop repo_cloner, exploitdb, github_scraper from run.py
  ✓ Remove is_flask_file() gate from cvefixes_loader
  ✓ Expand OSV TARGET_PACKAGES to all Python web frameworks
  ✓ Remove Flask-specific filters from osv_scraper
  ✓ Build ghsa_scraper.py (GitHub Security Advisories GraphQL)
  ✓ Build pypa_scraper.py (PyPA Advisory YAML database)
  ✓ Update run.py sources list
  ✓ Build v2.0 JSON schema (48 fields) via build_meta() in file_utils.py
  ✓ Connect to MongoDB Atlas and dual-write all samples
  ✓ Migrate all existing scraped samples to Atlas

Priority 2 — Phase 2 commit classifier
  - src/labeler/commit_classifier.py (TF-IDF + SVM baseline)
  - Evaluate against NVD ground truth

Priority 3 — Phase 3 CVSS enrichment
  - src/labeler/nvd_enricher.py
  - Fill cvss_score for CVEfixes and OSV samples (nvd_enriched: false)
  - GHSA samples already have CVSS — skip those
```

---

## v2.0 Dataset Schema — 48 Fields

All samples now written with a versioned, uniform schema via `build_meta()` in
`src/utils/file_utils.py`. Every scraper produces identical structure.

| Group | Fields |
|---|---|
| Identity | `_schema_version`, `id`, `source`, `scraped_at` |
| Advisory IDs | `cve_id`, `ghsa_id`, `osv_id`, `pysec_id` |
| Vulnerability label | `cwe`, `cwe_name`, `vuln_type`, `label_source`, `label_confidence` |
| CVSS gradient | `cvss_score`, `cvss_severity`, `cvss_version`, `cvss_vector` + 8 sub-metrics, `cvss_source` |
| Git provenance | `repo`, `file_path`, `fix_commit`, `vulnerable_commit`, `commit_message`, `commit_date`, `commit_author` |
| Code payload | `code_before`, `code_after` |
| Quality signals | `framework`, `language`, `loc_before`, `loc_after`, `syntax_valid`, `has_taint_source`, `is_web_code` |
| Pipeline state | `content_hash`, `pair_id`, `classifier_cwe`, `classifier_confidence`, `nvd_enriched`, `split` |

Key design decisions:
- `label_confidence` = `high` for NVD/GHSA/OSV sources, `medium` for PyPA
- `commit_author` always `null` — PII, not needed for training
- `nvd_enriched: false` by default — Phase 3 flips this to `true` after NVD lookup
- GHSA samples get `cvss_score` at scrape time; all others wait for Phase 3
- `content_hash` is the upsert key in MongoDB — prevents duplicates across runs

---

## MongoDB Atlas Integration

Connected the project to MongoDB Atlas (cluster: `secure-code-vuln.pqqe5ii.mongodb.net`).
All samples dual-write to both local disk and Atlas automatically via `save_code_sample()`.

### Setup
- Added `pymongo[srv]` + `dnspython` to `requirements.txt`
- SSL fix: `tlsCAFile=certifi.where()` — required on macOS for Atlas connections
- Connection config in `configs/config.yaml` under `mongodb:` section
- `MONGODB_URI` stored in `.env` (gitignored)

### Collection: `sec_code.vulnerability_samples`

Indexes created automatically on first connection:

| Index | Field(s) | Type |
|---|---|---|
| `idx_content_hash` | `content_hash` | unique — deduplication |
| `idx_cve_id` | `cve_id` | sparse |
| `idx_cwe` | `cwe` | single |
| `idx_source` | `source` | single |
| `idx_framework` | `framework` | single |
| `idx_cvss_score` | `cvss_score` | sparse |
| `idx_nvd_enriched` | `nvd_enriched` | single — Phase 3 queue |
| `idx_split` | `split` | sparse — ML train/val/test |
| `idx_enrich_queue` | `nvd_enriched + cve_id` | compound — Phase 3 |
| `idx_split_cwe` | `split + cwe` | compound — ML training |

### Migration script: `scripts/migrate_to_mongodb.py`

Handles schema upgrade from old on-disk formats (pre-v2.0) to current schema.
Idempotent — safe to run multiple times.

```bash
.venv/bin/python3 scripts/migrate_to_mongodb.py --dry-run   # preview
.venv/bin/python3 scripts/migrate_to_mongodb.py              # execute
```

---

## Dataset State (end of April 22, 2026)

| Source | Count |
|---|---|
| OSV | 180 |
| CVEfixes | 79 |
| GHSA | 18 |
| **Total in Atlas** | **277** |

| CWE | Count |
|---|---|
| CWE-89 (SQL Injection) | 133 |
| CWE-22 (Path Traversal) | 118 |
| CWE-502 (Deserialization) | 14 |
| CWE-78 (Command Injection) | 12 |

| Framework | Count |
|---|---|
| Django | 189 |
| Unknown (library-level files) | 81 |
| aiohttp | 4 |
| Starlette | 3 |

Scraper still running — counts will increase. Re-run migration script after
scraping completes to push any remaining samples.

---

## Files Changed Today

| File | Change |
|---|---|
| `src/generator/run.py` | Removed repo, exploitdb, github sources; added ghsa, pypa |
| `src/generator/scraper/cvefixes_loader.py` | Added commit_message to SQL query; new schema via build_meta |
| `src/generator/scraper/osv_scraper.py` | Expanded TARGET_PACKAGES; removed Flask gate; new schema |
| `src/generator/scraper/ghsa_scraper.py` | New — GitHub Security Advisories scraper with direct CVSS |
| `src/generator/scraper/pypa_scraper.py` | New — PyPA Advisory Database YAML parser |
| `src/utils/file_utils.py` | Added `detect_framework`, `is_web_code`, `parse_cvss_vector`, `compute_code_signals`, `build_meta`; dual-write in `save_code_sample` |
| `src/utils/mongo_writer.py` | New — MongoDB Atlas connection, upsert, index management |
| `scripts/migrate_to_mongodb.py` | New — schema migration + bulk push to Atlas |
| `configs/config.yaml` | Added `mongodb:` section |
| `requirements.txt` | Added `pymongo[srv]` |
| `reports/project_progress_report_2026_04_22.md` | This file |
