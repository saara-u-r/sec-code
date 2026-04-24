# Scraping Pipeline Explained — April 20, 2026

## Overview

This document explains exactly how data is being scraped across all 5 sources,
how each scraper works step by step, and how they differ from the original
GitHub code search scraper.

---

## Your 5 Scraping Sources

### 1. `repo_cloner.py` — Clone entire repos, extract route functions

**How it works:**
```
Clone full GitHub repo (depth=1)
    ↓
Walk every .py file in the repo
    ↓
Filter: only files that have "from flask" or "import flask"
    ↓
AST parse each file, find every function with @app.route decorator
    ↓
Extract just that route function as a snippet
    ↓
Save snippet + metadata
```

**What makes it different:** It does not search for vulnerability patterns at all.
It trusts the **repo itself** as the signal — every repo in `VULNERABLE_REPOS` was
hand-picked because it is a deliberately vulnerable Flask app. So anything scraped
from it is labeled vulnerable by repo-level trust, not by pattern matching.

**Example output:**
```python
# Extracted route snippet from we45t/Vulnerable-Flask-App
@app.route("/users")
def get_user():
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id={user_id}"
    db.execute(query)
```

---

### 2. `github_scraper.py` — Search GitHub code by vulnerability pattern

**How it works:**
```
For each of 28 search queries (7 per CWE × 4 CWEs):
    ↓
Hit GitHub Code Search API
    ↓
Get back list of matching files across ALL of GitHub
    ↓
Download each file's full content
    ↓
Hash it (skip duplicates)
    ↓
Save file + metadata with inferred CWE label
```

**What makes it different:** This casts the widest net. It searches across every
public Python file on GitHub. The CWE label is **inferred** from which query matched
— if the file was found by the `"app.route" "pickle.loads" "request.data"` query,
it gets labeled `CWE-502`. The label is an educated guess, not confirmed.

**The key improvement made:**
```
OLD query: language:python flask "execute(f\"SELECT"
           → matches test files, migration scripts, any Python file with that string

NEW query: language:python "app.route" "execute(f" SELECT
           → only matches files that also have a Flask route decorator
           → much more likely to be an actual vulnerable endpoint
```

---

### 3. `exploitdb_scraper.py` — Clone Exploit-DB, filter Python web exploits

**How it works:**
```
Clone the full Exploit-DB mirror from GitLab (shallow clone)
    ↓
Read files_exploits.csv (index of all 50,000+ exploits)
    ↓
Filter rows: only webapps + Python platform
    ↓
Keyword match description → infer CWE
    ↓
Read the exploit file content
    ↓
NEW: is_server_side_code() check — skip attacker PoC scripts
    ↓
Save + metadata
```

**What makes it different:** Exploit-DB is a **structured database of real exploits**
— every entry was submitted by a security researcher and reviewed. The downside is
most entries are attacker-side scripts (the tool you run to exploit something), not
the vulnerable server code itself. The new filter catches and discards those.

---

### 4. `cvefixes_loader.py` — Query a pre-built SQLite database of CVE commits

**How it works:**
```
Download CVEfixes.db (~1 GB SQLite from Zenodo, one-time)
    ↓
SQL query: join CVE table → fixes table → commits → file_change → method_change
    ↓
Filter: Python files only, our 4 target CWEs only
    ↓
For each row: extract code_before (vulnerable) and code_after (fixed)
    ↓
Save code_before as is_vulnerable=True
```

**What makes it different:** This is a **pre-curated academic dataset**. Someone
else already did the work of mapping CVEs to their exact git commits and extracting
the before/after code at the method level. The CWE labels are authoritative (from NVD).
You are not scraping — you are querying a research database.

---

### 5. `osv_scraper.py` *(new)* — Query OSV.dev API, fetch pre-fix code live

**How it works:**
```
For each of 9 Python packages (flask, werkzeug, django, ...):
    POST https://api.osv.dev/v1/query → get list of advisories
    ↓
    For each advisory: GET full OSV entry → check CWE
    ↓
    Extract GitHub fix commit SHA from references[]
    ↓
    GitHub API: GET /commits/{fix_sha} → find parent SHA
    ↓
    GitHub API: GET /commits/{fix_sha} → list changed .py files
    ↓
    Fetch file at parent SHA (the vulnerable version)
    ↓
    Save with CVE ID + authoritative CWE label
```

**What makes it different:** It fetches the vulnerable code **live from GitHub** at
the exact commit where the CVE existed. The CWE comes from the official advisory.
It is essentially what `cvefixes_loader.py` does, but via live APIs instead of a
pre-built database — so it is more up to date.

---

## Side-by-Side Comparison

| | `repo_cloner` | `github_scraper` | `exploitdb` | `cvefixes` | `osv` |
|---|---|---|---|---|---|
| **Source** | Known-vulnerable repos | All of GitHub | Exploit-DB mirror | CVEfixes SQLite DB | OSV.dev + GitHub |
| **How vuln is identified** | Repo trust | Query pattern match | Keyword in description | CVE record in DB | CVE advisory |
| **CWE label quality** | Medium (repo-level) | Low (inferred from query) | Medium (keyword match) | High (NVD) | High (GHSA/NVD) |
| **CVE ID available** | No | Rarely | Sometimes | Yes | Yes |
| **Code precision** | Route-function level | Full file | Full file | Method level | Full file |
| **Volume** | Medium | High | Low | Medium | Low-Medium |
| **Internet required** | Yes (clone) | Yes (API) | Yes (clone once) | No (after download) | Yes (API) |

---

## The Core Difference from the Original Scraper

The original `github_scraper.py` had one idea: **search GitHub for files containing
dangerous patterns**. That is a keyword search. It finds files that *look* vulnerable.

The new pipeline adds two fundamentally different approaches:

**CVEfixes + OSV** work backwards from *known vulnerabilities* → find the code.
The vulnerability is confirmed first, then the code is retrieved. This is the opposite
of the GitHub scraper, which finds code first and infers a vulnerability from it.

**repo_cloner** works by *repo-level trust* → extract all route functions.
Rather than pattern matching individual files, it says "this entire repo was built to
be vulnerable, so every route in it is a training sample."

---

## Three Independent Signals

Together the five sources give you three independent signals:

```
Pattern signal     → github_scraper, exploitdb
Repo trust signal  → repo_cloner
CVE ground truth   → cvefixes, osv
```

When all three agree on a sample — it contains the pattern, comes from a
known-vulnerable repo, AND has a CVE record — that is your highest-confidence
training data.

---

## About the ML Model

In Phase 5, the plan is to train a **Random Forest classifier** (configured in
`configs/config.yaml` and `src/ml/`) that takes a Flask code snippet as input
and predicts:

- Is this code vulnerable? (yes/no)
- If yes, which CWE? (89, 78, 22, or 502)

OSV-sourced samples serve as the external benchmark for evaluating this model.
Because OSV labels come from confirmed public CVEs (not from your own pattern
matching), correctly classifying them is an externally validated result — not
just accuracy on your own data.

| Evaluation on scraped data | Evaluation on OSV data |
|---|---|
| You labeled it yourself via pattern matching | Labeled by security researchers + NVD |
| Model could overfit to your own heuristics | Independent ground truth |
| Weaker research claim | Strong, externally validated claim |
