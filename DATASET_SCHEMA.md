# Dataset Schema — Field Reference

Every sample in `data/raw/` has a `.py` file (the code) and a `.meta.json` file (the metadata).
This document explains every field in the metadata, why it exists, and how it feeds into each phase of the pipeline.

---

## Sample Record

```
data/raw/cvefixes_sql_injection_a3e1e93db0d1dc83.py       ← the vulnerable code
data/raw/cvefixes_sql_injection_a3e1e93db0d1dc83.meta.json ← the metadata
```

Total fields: **50** (48 metadata fields + `code_before` + `code_after`)

---

## Field Groups

### Group 1 — Identity (4 fields)

These tell you what this record is and when it was collected.

| # | Field | Example | Purpose |
|---|---|---|---|
| 1 | `_schema_version` | `"2.0"` | Schema version tag. If the metadata format changes in a future phase, old records are still parseable because you know which version they were written under. |
| 2 | `id` | `"cvefixes_sql_injection_a3e1e93..."` | Unique primary key for MongoDB. Built as `{source}_{vuln_type}_{content_hash}`. Used to upsert records without duplicates. |
| 3 | `source` | `"cvefixes"` | Which scraper produced this record: `cvefixes`, `osv`, `ghsa`, or `pypa`. Used to audit data quality per source and to filter samples by origin. |
| 4 | `scraped_at` | `"2026-04-21T06:47:24..."` | UTC timestamp of when the scraper collected this. Lets you re-run only scrapers for new data, track dataset growth over time, and debug scraper runs. |

---

### Group 2 — Advisory IDs (4 fields)

A single vulnerability can be indexed in multiple advisory databases simultaneously. These four fields store whichever IDs are known.

| # | Field | Example | Purpose |
|---|---|---|---|
| 5 | `cve_id` | `"CVE-2017-17713"` | The universal CVE identifier assigned by MITRE. The most important ID — used in Phase 3 to query the NVD API for CVSS scores. If a sample has no CVE ID, it cannot be enriched in Phase 3. |
| 6 | `ghsa_id` | `"GHSA-xxxx-yyyy-zzzz"` | GitHub Security Advisory ID. Present only for samples collected by the GHSA scraper. GHSA advisories include CVSS directly, so these samples skip Phase 3. |
| 7 | `osv_id` | `"GHSA-xxxx-yyyy-zzzz"` | OSV.dev advisory ID. OSV often mirrors GHSA IDs but not always. Present only for OSV scraper samples. |
| 8 | `pysec_id` | `"PYSEC-2023-xxx"` | PyPA advisory ID. Present only for samples collected from the PyPA advisory database. |

All four fields exist on every record — whichever scrapers did not produce this sample leave those fields as `null`. This lets you cross-reference the same CVE across sources.

---

### Group 3 — Vulnerability Label (5 fields)

The ground truth labels that the ML model is trained to predict. These come from external security authorities, not from the scraper's own pattern matching.

| # | Field | Example | Purpose |
|---|---|---|---|
| 9 | `cwe` | `"CWE-89"` | The CWE class of the vulnerability. One of four target CWEs: CWE-89 (SQL Injection), CWE-78 (Command Injection), CWE-22 (Path Traversal), CWE-502 (Insecure Deserialization). This is the primary label for Phase 5 classification. |
| 10 | `cwe_name` | `"SQL Injection"` | Human-readable version of the CWE. Used in reports, visualisations, and slide decks. Not used directly in ML. |
| 11 | `vuln_type` | `"sql_injection"` | Internal slug for the vulnerability type. Used as filename prefix, MongoDB filter key, and dataset folder name. Directly derived from `cwe`. |
| 12 | `label_source` | `"nvd"` | Where the CWE label came from: `nvd` (CVEfixes, NVD-authoritative), `ghsa` (GitHub Security Advisories), or `osv` (OSV.dev). Determines how much to trust the label — NVD and GHSA are highest quality. |
| 13 | `label_confidence` | `"high"` | Confidence tier of the label: `high` for NVD/GHSA/OSV-sourced labels, `medium` for PyPA where CWE fields are sometimes absent or inferred. Used in Phase 5 to weight training samples — low-confidence labels get lower weight. |

---

### Group 4 — CVSS Severity (13 fields)

CVSS (Common Vulnerability Scoring System) scores describe how severe a vulnerability is across multiple dimensions. These fields are null for non-GHSA samples until Phase 3 (NVD enrichment) runs.

**Why break CVSS into individual fields instead of just storing the score?**
Each component tells you something different about the vulnerability. Attack Vector tells you if it's exploitable over the network or requires local access. Scope tells you if the exploit can jump to other systems. These components are features for Phase 5 ML training and determine which red team payloads Phase 6 uses.

| # | Field | Example | Purpose |
|---|---|---|---|
| 14 | `cvss_score` | `9.8` | Numerical score from 0–10. The most-used CVSS field. Determines severity band and is used to weight training samples (high-CVSS vulnerabilities are prioritised in Phase 5 and Phase 6). |
| 15 | `cvss_severity` | `"CRITICAL"` | Severity band: LOW (0–3.9), MEDIUM (4–6.9), HIGH (7–8.9), CRITICAL (9–10). Used for filtering, reporting, and red team prioritisation. |
| 16 | `cvss_version` | `"3.1"` | CVSS version used to calculate the score. Scoring changed between 3.0 and 3.1 — needed to compare scores fairly across records. |
| 17 | `cvss_vector` | `"CVSS:3.1/AV:N/AC:L/..."` | The full CVSS vector string. Encodes all components in a single parseable string. Stored for auditability and to re-derive any component if needed. |
| 18 | `cvss_attack_vector` | `"NETWORK"` | How the attacker reaches the vulnerable component: NETWORK (remotely exploitable over the internet), ADJACENT (requires network adjacency), LOCAL (requires local access), PHYSICAL (requires physical access). SQL injection is almost always NETWORK. |
| 19 | `cvss_attack_complexity` | `"LOW"` | How hard the exploit is: LOW (reliable, no special conditions) or HIGH (requires specific conditions that the attacker cannot control). Informs red team difficulty settings in Phase 6. |
| 20 | `cvss_privileges_required` | `"NONE"` | Whether the attacker needs an account: NONE (unauthenticated exploit), LOW (any logged-in user), HIGH (admin required). SQL injection on a public endpoint is NONE. |
| 21 | `cvss_user_interaction` | `"NONE"` | Whether a victim user must take action: NONE (fully automated exploit) or REQUIRED (e.g. victim clicks a link). Most server-side injection vulnerabilities are NONE. |
| 22 | `cvss_scope` | `"UNCHANGED"` | Whether the exploit can affect systems beyond the vulnerable component: UNCHANGED (contained) or CHANGED (can pivot to other systems). A scope-changed vulnerability is more dangerous and gets higher red team priority. |
| 23 | `cvss_confidentiality` | `"HIGH"` | Impact on data confidentiality: NONE, LOW, or HIGH. SQL injection typically allows reading the entire database — HIGH. |
| 24 | `cvss_integrity` | `"HIGH"` | Impact on data integrity: NONE, LOW, or HIGH. SQL injection can write or delete data — HIGH. |
| 25 | `cvss_availability` | `"HIGH"` | Impact on service availability: NONE, LOW, or HIGH. Dropping a table kills the service — HIGH. |
| 26 | `cvss_source` | `"ghsa"` | Where the CVSS data came from: `ghsa` (available at scrape time, no Phase 3 needed) or `nvd` (filled in by Phase 3 NVD enrichment). |

**Field 47 — `nvd_enriched`** (placed later but logically belongs here): `false` means Phase 3 has not yet run on this record. Phase 3 uses the `cve_id` to call `https://services.nvd.nist.gov/rest/json/cves/2.0` and fills in fields 14–26. GHSA samples are born with `nvd_enriched: true`.

---

### Group 5 — Provenance (7 fields)

These fields let you trace the sample back to the exact git commit it came from. Full provenance is what separates a research-grade dataset from a scraped corpus.

| # | Field | Example | Purpose |
|---|---|---|---|
| 27 | `repo` | `"https://github.com/boxug/trape"` | The GitHub repository this file came from. Lets you navigate to the project, check its history, and verify the vulnerability. |
| 28 | `file_path` | `"db.py"` | Path of the file within the repository. Combined with `repo` and `vulnerable_commit`, you can reconstruct the exact URL: `raw.githubusercontent.com/{repo}/{vulnerable_commit}/{file_path}`. |
| 29 | `fix_commit` | `"505826b469b16ab3..."` | SHA of the commit that patched the vulnerability. Used to fetch `code_after`. Null for CVEfixes samples where the DB did not store commit SHAs. |
| 30 | `vulnerable_commit` | `"673444da5e721c0d..."` | SHA of the commit just before the fix — the parent commit. This is the exact git state from which `code_before` was fetched. Null for CVEfixes samples. |
| 31 | `commit_message` | `"Fixed CVE-2020-7471..."` | The developer's own description of the fix, fetched from the GitHub API. This is the training input for the Phase 2 commit message CWE classifier. Empty for CVEfixes samples where the DB did not store messages. |
| 32 | `commit_date` | `null` | When the fix commit was authored. Useful for temporal analysis — e.g. tracking how long vulnerabilities exist before being patched. Not yet populated. |
| 33 | `commit_author` | `null` | Who authored the fix. Useful for attribution and contribution studies. Not yet populated. |

---

### Group 6 — The Code (2 fields)

The actual file content — the core of each sample.

#### `code_before` — The Vulnerable File

The Python source file exactly as it existed in the repository **before** the fix commit. Fetched from `raw.githubusercontent.com/{repo}/{vulnerable_commit}/{file_path}`.

This is the **primary training input** for the Phase 5 ML vulnerability detector. Every `code_before` record has `is_vulnerable = True` as its label. This is real production code that shipped to real users with a confirmed CVE — not a demo, not a teaching example, not an attacker PoC.

**How it is used across phases:**

- **Phase 5** — Fed to the ML model as a positive (vulnerable) training example. The model learns to recognise vulnerability patterns from this code.
- **Phase 6** — Used as the red team target. The red team engine spins up the vulnerable code and fires exploit payloads at it. A successful hit validates the CVE label through live exploitation.
- **Phase 2 (indirect)** — `code_before` is what `commit_message` describes. The two together form the training pair for the CWE classifier: the message explains what type of bug is in the code.

**Example from CVE-2017-17713 (`db.py`, trape project):**
```python
def prop_sentences_stats(self, type, vId=None):
    return {
        'get_preview': "SELECT * FROM victims WHERE victims.id = '%s'" % (vId),
        'id_networks': "SELECT * FROM networks WHERE id = '%s'" % (vId),
    }.get(type, False)
```
`vId` arrives from `request.form['vId']` in the Flask routes. The `%s` string formatting pastes it directly into the SQL. An attacker sends `' OR '1'='1` and the database returns every row.

---

#### `code_after` — The Patched File

The same file fetched from `raw.githubusercontent.com/{repo}/{fix_commit}/{file_path}` — the version **after** the vulnerability was fixed.

This is the **negative class** for Phase 5. Because `code_before` and `code_after` are the same file differing only by the patch, the model is trained on a clean paired comparison: same codebase, same structure, only the vulnerable logic removed. This is much higher-quality signal than comparing random safe code against random vulnerable code.

**How it is used across phases:**

- **Phase 5** — Fed to the ML model as a negative (safe) training example with `is_vulnerable = False`. The paired before/after approach teaches the model what specifically changed to make the code safe, not just what safe code looks like in general.
- **Phase 5 (advanced)** — Diffing `code_before` against `code_after` gives line-level ground truth: which exact lines were vulnerable. This enables training a **line-level detector** that can point to the specific vulnerable line, not just flag the whole file. This is the technique used in the LineVul paper (Fu & Tantithamthavorn, MSR 2022) which achieved 160–379% higher F1 than prior methods.
- **Phase 6** — After the red team exploits `code_before`, you swap in `code_after` and re-run the same payload. If the exploit fails, the fix is confirmed. If it still succeeds, the patch is incomplete — a valuable finding.
- **Phase 7** — When the feedback loop needs to suggest fixes for newly detected vulnerabilities in LLM-generated code, `code_after` examples from similar CVEs serve as reference patches.

**Why many samples have `code_after = ""`:**
CVEfixes stores code from its own historical crawl and does not always include the patched version. OSV and GHSA samples fetched with a real `fix_commit` SHA will have `code_after` populated. CVEfixes samples often do not. This is a known limitation — the samples with both `code_before` and `code_after` are your highest-value records and should be weighted accordingly in Phase 5.

**Getting the diff programmatically:**
```python
import difflib

diff = list(difflib.unified_diff(
    code_before.splitlines(),
    code_after.splitlines(),
    fromfile="vulnerable",
    tofile="patched",
    lineterm=""
))
# Lines starting with - were removed (the vulnerable logic)
# Lines starting with + were added (the fix)
```

---

### Group 7 — Code Analysis Flags (8 fields)

Computed at scrape time by static analysis. Used by the cleaner to filter low-quality samples and by Phase 5 as additional features.

| # | Field | Example | Purpose |
|---|---|---|---|
| 36 | `framework` | `"django"` | Detected web framework: `flask`, `django`, `fastapi`, `aiohttp`, `tornado`, `bottle`, `quart`, or `unknown`. Detected by scanning imports. Used to stratify the dataset and filter by framework. |
| 37 | `language` | `"python"` | Always `python` for now. Kept for future expansion to other languages. |
| 38 | `loc_before` | `91` | Non-blank lines of code in `code_before`. Size feature for ML — vulnerability patterns differ between small utility files and large application modules. |
| 39 | `loc_after` | `0` | Non-blank lines in `code_after`. Zero when `code_after` is empty. Used to compute the size delta of the fix. |
| 40 | `syntax_valid` | `true` | Whether `code_before` passes Python `ast.parse()`. Files that fail are dropped by the cleaner — a syntax error means the file cannot be tokenised or parsed for ML. |
| 41 | `has_taint_source` | `false` | Whether `request.args`, `request.form`, `request.data`, `request.json`, or similar user-input sources appear directly in this file. `false` for `db.py` because the taint originates in the Flask routes file — this is a known limitation of file-level analysis. |
| 42 | `is_web_code` | `false` | Whether the file looks like web application code based on framework imports and HTTP patterns. Used by the scraper to drop library internals and test files. `false` for `db.py` because it has no Flask or HTTP imports — it is the database layer, called by the web layer. |
| 43 | `content_hash` | `"be7ce007..."` | SHA-256 hash of `code_before`. The primary deduplication key — if two samples from different scrapers produce the same file content, only the first is kept. |

---

### Group 8 — ML Pipeline State (6 fields)

These fields start as `null` at scrape time and are written by later phases of the pipeline.

| # | Field | Set by | Purpose |
|---|---|---|---|
| 44 | `pair_id` | Scraper | Links the before/after pair: `{fix_commit_prefix}_{file_path}` for OSV/GHSA/PyPA, or `{cve_id}_{file_path}` for CVEfixes. Used to join paired records in Phase 5. |
| 45 | `classifier_cwe` | Phase 2 | The CWE predicted by the Phase 2 commit message classifier (e.g. `"CWE-89"`). Provides a secondary label for samples where the advisory CWE is absent or uncertain. |
| 46 | `classifier_confidence` | Phase 2 | Confidence of the Phase 2 prediction, 0–1. Low-confidence predictions are down-weighted in Phase 5. If DistilBERT's confidence exceeds the SVM's, DistilBERT's prediction replaces it. |
| 47 | `nvd_enriched` | Phase 3 | `false` until Phase 3 (NVD enrichment) runs. When Phase 3 fills in the CVSS fields, this is set to `true`. GHSA samples are born `true`. Prevents Phase 3 from re-processing records unnecessarily. |
| 48 | `split` | Phase 2 | `"train"`, `"val"`, or `"test"`. Written by Phase 2 data prep after stratified splitting. Ensures the same split is used consistently across all experiments. |
| 49 | `valid_syntax` | Cleaner | Duplicate of `syntax_valid`. Legacy field kept for backward compatibility with early records written before the field was renamed. |
| 50 | `has_flask_import` | Cleaner | Whether `from flask` or `import flask` appears in the file. Quick boolean filter — weaker than `framework` but computed by the cleaner independently. |

---

## Summary — Which Fields Matter for Each Phase

| Phase | Fields used |
|---|---|
| **Phase 2** — Commit classifier | `commit_message`, `cwe`, `split`, → writes `classifier_cwe`, `classifier_confidence` |
| **Phase 3** — NVD enrichment | `cve_id`, `nvd_enriched` → writes `cvss_score` through `cvss_source` |
| **Phase 5** — ML vulnerability detector | `code_before`, `code_after`, `cwe`, `cvss_score`, `label_confidence`, `classifier_confidence`, `split`, `framework`, `loc_before` |
| **Phase 6** — Red team engine | `code_before`, `code_after`, `vuln_type`, `cvss_score`, `cvss_attack_vector`, `cvss_privileges_required`, `repo`, `fix_commit` |
| **Phase 7** — Feedback loop | `code_after` (reference patches), `classifier_cwe`, `cvss_severity` |
