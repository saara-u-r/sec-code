# Script Explanations & Defensive Logic — April 20, 2026

## Overview

This document explains every script generated or modified during the April 20 session.
Each section covers: what the script does, the logic behind each function, and how it
contributes to the defensive security goal of the project.

---

## 1. `scripts/health_check.py`

This is the most important new script. Its job is to **audit every sample in `data/raw/`
and answer: "Is this sample actually a real, exploitable Flask vulnerability of the type
we claim?"**

### Why it exists

Your dataset's quality directly determines your ML model's quality. If a sample is
labeled `CWE-89` (SQL injection) but the code doesn't actually contain a SQL injection
pattern, the model learns from false signal. The health checker catches this before you
ever run Phase 2.

---

### Layer 1 — CWE-Specific Pattern Detectors

Each CWE gets its own detector function. The logic behind each:

#### `check_cwe89` — SQL Injection (CWE-89)

```python
# Looks for two things together:
# 1. A .execute() call (the SQL query runner)
# 2. Unsafe string formatting flowing into it
_SQL_FORMAT_PATTERNS = [
    execute(f"SELECT...    ← f-string in execute = definite SQLi
    execute("SELECT" + ... ← string concat = definite SQLi
    execute("... % ...     ← % formatting = definite SQLi
    execute(query/sql/stmt ← variable name suggests SQL = probable
]
```

The key insight is that SQL injection requires **two conditions simultaneously**: a query
runner AND unsanitized user data flowing into it. A file that has `execute()` but uses
parameterized queries (`execute("SELECT ? WHERE id=?", [user_id])`) is safe. That is why
`confident` requires both `has_sql_execute` AND `has_unsafe_format`.

#### `check_cwe78` — Command Injection (CWE-78)

```python
_CMD_PATTERNS = [
    os.system(      ← executes shell command
    os.popen(       ← opens pipe to shell
    subprocess.run( ← runs subprocess
    eval(           ← evaluates arbitrary Python code
    exec(           ← executes arbitrary Python code
]
```

`eval()` and `exec()` are included because they are the Python-specific command injection
— if a user can control what gets `eval()`-ed, they have full code execution. `shell=True`
in subprocess is flagged separately because `subprocess.run(["ls"], shell=False)` is safe,
but `subprocess.run(user_input, shell=True)` is not.

#### `check_cwe22` — Path Traversal (CWE-22)

```python
_PATH_PATTERNS = [
    open(                   ← file read/write
    send_file(              ← Flask file response
    send_from_directory(    ← Flask directory serve
    os.path.join(           ← path construction
]
```

Path traversal happens when `open("files/" + request.args.get("name"))` can be fed
`../../etc/passwd`. The `has_traversal_hint` check (looking for `../` in the code)
catches samples that explicitly demonstrate the attack vector in their docstring or
comments.

#### `check_cwe502` — Insecure Deserialization (CWE-502)

```python
# Most dangerous: pickle.loads(request.data) — one line = RCE
# Second:         yaml.load(request.data) WITHOUT safe_load — also RCE
# has_safe_yaml flag: yaml.safe_load() is actually safe, so we do not flag it
```

`json.loads()` is listed but not counted toward `confident` — it is flagged for review
only. Regular JSON deserialization is safe (JSON cannot execute code). `pickle` and
`marshal` are fundamentally unsafe because they can serialize arbitrary Python objects
including code.

---

### Layer 2 — Taint Source Detection

```python
TAINT_SOURCES = re.compile(
    r"request\s*\.\s*(args|form|data|json|values|files|cookies|headers)",
)
```

This is the **taint source** check — the concept from static analysis that says "where
does attacker-controlled data enter the program?" In Flask, user input always enters
through `request.*`. A file that has `pickle.loads(some_hardcoded_value)` is not
vulnerable. A file that has `pickle.loads(request.data)` is exploitable. The
`has_taint_source` flag tells you whether the vulnerability is actually reachable by a
real attacker.

---

### Layer 3 — Structural Checks

```python
def structural_checks(source, meta):
    # valid_syntax:        can Python even parse this file?
    # has_executable_code: strip all docstrings and comments —
    #                      are there more than 2 real lines left?
    # has_route_handler:   does it have @app.route or @bp.route?
    # is_likely_attack_poc: uses requests.get/post (client-side HTTP)
    #                       AND has target_url/victim keywords
```

The `is_likely_attack_poc` heuristic catches files that are **attacker scripts** — they
send malicious payloads to a server, not serve them. The heuristic looks for: (1)
`requests.get/post` — the HTTP client library, and (2) words like `target_url`, `victim`,
`http://` — indicators that the script is contacting something, not serving something.

---

### Verdict Logic

| Status    | Meaning |
|-----------|---------|
| `PASS`    | Structurally clean + CWE pattern confirmed |
| `WARN`    | Structurally clean + CWE plausible but weak signal |
| `FAIL`    | Invalid syntax, no executable code, or CWE not found |
| `SKIPPED` | `is_vulnerable=False` samples — CWE check not applicable |

FAIL samples should not be used for training. WARN samples might be fine (the
vulnerability exists but the taint source is in a helper function in another file).
PASS samples are the gold standard.

### How this defends the project

The health checker is the **data validation gate**. Without it, the ML model trains on
mislabeled data and learns wrong associations. With it, you can prove to anyone evaluating
your research that your dataset has X% confirmed-pattern samples, not just "we scraped
stuff that looked relevant."

---

## 2. `scripts/purge_bad_samples.py`

The **cleanup script**. Deletes samples that the health checker would mark as FAIL before
they pollute training data.

### Three purge criteria (all ON by default)

#### `--invalid-syntax` (206 samples caught)

```python
def is_valid_python(source):
    try:
        ast.parse(source)   # Python's built-in AST parser
        return True
    except SyntaxError:
        return False
```

Files that Python cannot parse are completely useless. The analyzer in Phase 2 uses
`ast.parse()` to find vulnerability patterns. If the file is not valid Python, Phase 2
will crash on it.

#### `--no-exec-code` (50 samples caught)

```python
stripped = re.sub(r'"""[\s\S]*?"""', "", source)  # remove triple-quote strings
stripped = re.sub(r"#.*", "", stripped)            # remove comments
executable_lines = [l for l in stripped.splitlines() if l.strip()]
return len(executable_lines) > 2
```

This strips all docstrings and comments then counts what remains. The `cleaner.py`
salvaged 47+ invalid Exploit-DB files by wrapping narrative text in docstrings. Those
files are syntactically valid Python but have `# No executable code extracted.` as their
only real line — zero vulnerability signal.

#### `--attack-pocs` (14 samples caught)

```python
def is_attack_poc(source):
    has_flask = "from flask" in source
    has_server_request = bool(TAINT_SOURCES.search(source))
    has_client = bool(re.search(r"\brequests\.(get|post|put)\s*\(", source))
    has_target = bool(re.search(r"target_url|victim|http://", source))

    if has_flask or has_server_request:
        return False   # server-side code — keep it
    return has_client and has_target  # attacker script — purge it
```

A file that imports Flask OR reads from `request.*` is server-side code — keep it even
if it also makes HTTP calls. A file that makes outbound HTTP calls to a `target_url` with
no server-side code is an attacker script — remove it.

### Optional criteria (OFF by default)

| Flag | What it removes | Risk |
|------|----------------|------|
| `--false-labels` | CWE label has zero matching code patterns | May remove snippets where vuln is in a helper function |
| `--no-flask` | Vulnerable samples with no Flask import or `request.*` | May remove legitimate fragments |
| `--source repo_clone` | Limit purge to a specific scraping source | Safe — use to clean a single source |

### The `--dry-run` / `--execute` design

The script **never deletes anything by default**. You must explicitly pass `--execute`.
This is a safety mechanism — data deletion is irreversible.

```bash
python scripts/purge_bad_samples.py              # safe: just shows counts
python scripts/purge_bad_samples.py --execute    # actually deletes
```

### How this defends the project

A cleaner dataset means fewer false positives in the ML model. Training on 675 samples
where 270 are garbage is effectively training on 405 real examples plus 270 noisy labels.
After purging, 405 clean samples beat 675 noisy samples every time.

---

## 3. `src/generator/scraper/osv_scraper.py`

The most technically sophisticated new piece. Connects to **OSV.dev** (Google's Open
Source Vulnerabilities database) to get authoritative, curated vulnerability data.

### Why OSV instead of more GitHub pattern matching

The existing GitHub scraper finds files that **look like** they have vulnerabilities by
searching for dangerous function calls. OSV gives files that **are known** to have
vulnerabilities — linked to real CVE records with CWE IDs already assigned by security
researchers.

### The pipeline — step by step

#### Step 1: Query OSV.dev

```python
def query_osv_package(package, ecosystem="PyPI"):
    # POST https://api.osv.dev/v1/query
    # {"package": {"name": "flask", "ecosystem": "PyPI"}}
    # Returns list of vulnerability stubs (IDs and brief info)
```

OSV is queried per Python package. The 9 packages (`flask`, `werkzeug`, `django`,
`sqlalchemy`, `pyyaml`, etc.) cover all realistic Flask application dependency trees.
Django is included because SQLi and CMDi patterns in Django are identical to Flask —
same code patterns, different imports.

#### Step 2: Filter by CWE

```python
def _extract_cwe(vuln):
    # Checks database_specific.cwe_ids  (GHSA entries)
    # Falls back to severity[].type field
    # Only returns CWE if it is one of our four targets
```

OSV entries come from multiple databases (GHSA, NVD, OSS-Fuzz). GitHub Security Advisory
(GHSA) entries store CWEs in `database_specific.cwe_ids`. This filter rejects everything
that is not CWE-89/78/22/502.

#### Step 3: Find the fix commit on GitHub

```python
def _extract_fix_commits(vuln):
    # Pattern 1: references[] with type="FIX" pointing to GitHub commit URL
    #   https://github.com/owner/repo/commit/abc123
    # Pattern 2: affected[].ranges[] with type="GIT" and events[].fixed = sha
```

Every OSV entry has a `references` list. Fix commits appear as
`{"type": "FIX", "url": "https://github.com/owner/repo/commit/sha"}`.
Two parsing methods cover both OSV formats.

#### Step 4: Get the parent (vulnerable) commit

```python
def _get_parent_sha(owner_repo, fix_sha):
    # GET /repos/{owner}/{repo}/commits/{fix_sha}
    # Returns: {"parents": [{"sha": "abc123_parent"}]}
    # The parent = the state of the code BEFORE the fix = the vulnerable version
```

If commit `fix_sha` is "the commit that fixed CVE-2023-XXXX", then its parent commit is
the last commit where the vulnerability existed. That parent's file content is exactly
what you want — real, confirmed vulnerable code.

#### Step 5: Fetch the pre-fix file content

```python
def _fetch_file_at_ref(owner_repo, file_path, ref):
    # https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{path}
    # Returns the exact file content at the vulnerable commit
```

`raw.githubusercontent.com` serves file content at any git ref. By requesting the file
at `parent_sha`, you get the vulnerable version, not the fixed version.

#### Metadata stored per sample

```python
meta = {
    "osv_id":            "GHSA-xxxx-yyyy-zzzz",  # advisory ID
    "cve_id":            "CVE-2023-XXXX",         # from aliases[]
    "cwe":               "CWE-89",                # confirmed, not inferred
    "fix_commit":        fix_sha,                 # what fixed it
    "vulnerable_commit": parent_sha,              # what you are saving
}
```

Unlike the GitHub scraper (which infers CWE from search patterns), OSV samples have
**authoritative CWE labels** — from the official advisory, not pattern matching.
This is the highest-confidence labeling possible without manual review.

### How this defends the project

OSV gives you the "ground truth" subset of the dataset. In Phase 5, you can report
results separately for OSV-sourced samples vs. scraped samples. OSV samples being
correctly classified proves the model works on real-world CVEs — a strong research claim.

---

## 4. Modified `src/generator/scraper/repo_cloner.py`

### What changed: removing `pallets/flask`

```python
# Before:
SECURE_REPOS = [{"url": "https://github.com/pallets/flask", "is_vulnerable": False}]

# After:
SECURE_REPOS: list[dict] = []  # removed
```

`pallets/flask` is the Flask **framework** source code — things like `flask/app.py`,
`flask/wrappers.py`. When route functions are extracted from it, you get internal
framework methods that handle routing and context management. These are written by
security-conscious maintainers, have no `request.args.get()` patterns, and produce
mostly invalid Python from partial internal snippets. They generated 277 samples with
no CWE and 206 invalid syntax files — noise, not signal.

### New repos added

| Repo | Why added |
|------|-----------|
| `incredibleindishell/Damn-Vulnerable-Flask-App` | Explicit Flask, covers CWE-89/78/22 |
| `adeyosemanputra/pygoat` | Intentionally vulnerable Python web app |
| `ethicalhack3r/DVWA` | Classic security lab with Python routes |
| `DevSlop/Pixi` | Flask OAuth app with intentional API vulnerabilities |

All four are **deliberately vulnerable applications** — the code was written intentionally
with vulnerabilities for security training. Every file is meant to demonstrate a real
attack pattern.

### How this defends the project

The ML model needs both vulnerable and non-vulnerable examples. However, non-vulnerable
examples should be **real Flask application code written by developers**, not framework
internals. If secure negative samples are needed later, a better source is random public
Flask apps from GitHub that pass the health checker (no vulnerability patterns found).

---

## 5. Modified `src/generator/scraper/exploitdb_scraper.py`

### What changed: `is_server_side_code()` filter

```python
def is_server_side_code(code):
    has_flask = bool(re.search(r"(from flask|import flask)", code))
    has_server_request = bool(re.search(r"request\.(args|form|data|...)", code))

    has_client_requests = bool(re.search(r"\brequests\.(get|post|put)\s*\(", code))
    has_target_url = bool(re.search(r"(target_url|victim|http://)", code))

    if has_flask or has_server_request:
        return True   # server-side code — keep it
    if has_client_requests and has_target_url:
        return False  # attacker script — skip it
    # No clear signal — keep if a raw vulnerability pattern exists
    return any(re.search(p, code) for p in vuln_patterns)
```

Exploit-DB has two types of Python entries:

| Type | What it is | Useful for |
|------|-----------|------------|
| Server-side PoC | The vulnerable app itself | Phase 1 dataset (want this now) |
| Attacker-side PoC | Script that exploits a target URL | Phase 6 red team payloads (later) |

The original scraper grabbed both indiscriminately. The filter separates them. The
attacker-side scripts are not wasted — they are good candidates for Phase 6 later.

### How this defends the project

All 14 attacker PoC scripts that were in the dataset were labeled `is_vulnerable=True`
with CWE labels they did not support. The model was being shown exploit scripts and told
"this is what a SQL injection vulnerability looks like" — which is wrong. An exploit
script is not the vulnerable code, it is the attack. This filter ensures the model only
learns from server-side vulnerable code.

---

## 6. Modified `src/generator/scraper/github_scraper.py`

### What changed: requiring `"app.route"` in all queries

**Before** (10 queries, no route requirement):
```
language:python flask "execute(f\"SELECT"
```
Matches: test files, utility scripts, ORM helpers, database migration scripts — anything
with `execute()` + an f-string.

**After** (28 queries, route required):
```
language:python "app.route" "execute(f" SELECT
```
Matches: only files with a Flask route decorator AND the unsafe SQL pattern. Files without
`@app.route` are not Flask endpoints and cannot receive HTTP requests.

A file with `execute(f"SELECT {user_id}")` in a **database migration script** is not a
vulnerability (running server-side with trusted input). The same pattern inside
`@app.route("/users")` that reads from `request.args` is a real vulnerability.

### Additional taint-flow queries added

```
language:python "app.route" "request.args.get" "SELECT"
```
Catches: `query = "SELECT * WHERE id=" + request.args.get("id")` — even when not directly
inside `execute()`.

```
language:python "app.route" "pickle.loads" "request.cookies"
```
Catches: deserialization via cookie — a real attack vector (Flask session cookies are
base64-encoded pickled objects in some configurations).

### How this defends the project

More precise queries = fewer false-positive samples = less noise in training data = a
model that learns real vulnerability patterns, not coincidental code that happens to
contain the same keywords.

---

## 7. Modified `src/generator/run.py`

```python
ALL_SOURCES = ["repo", "github", "cvefixes", "exploitdb", "osv"]
SCRAPERS = {"osv": osv_scraper, ...}
```

The orchestration layer. Now individual scrapers can be run in isolation:

```bash
python -m src.generator.run --sources osv           # just OSV
python -m src.generator.run --sources github osv    # GitHub + OSV
python -m src.generator.run                         # all 5 sources
```

The `--sources` flag means you can re-run slow scrapers (OSV, CVEfixes) separately from
fast ones (GitHub, repo_cloner) without re-running everything. New scrapers can be added
later by adding one entry to the `SCRAPERS` dict.

---

## The Overall Defensive Picture

```
Real-world CVEs (OSV, CVEfixes)
        ↓
GitHub vulnerable repos + pattern search
        ↓
health_check.py     ← validates CWE labels are real
        ↓
purge_bad_samples.py  ← removes unusable data
        ↓
Clean, labeled dataset (Phase 4)
        ↓
ML model trained on confirmed vulnerabilities (Phase 5)
        ↓
Model can scan new Flask code and flag real CWEs
        ↓
Red team tests the model's detection limits (Phase 6)
        ↓
Feedback loop retrains on misses (Phase 7)
```

Every script built in this session exists to **protect the integrity of the data
pipeline**. Garbage in = garbage out applies more severely to security ML than anywhere
else — a model that misses a real vulnerability is worse than no model at all, because
it creates false confidence.

---

## Quick Reference — Commands

```bash
# Audit current dataset quality
python scripts/health_check.py

# Audit and save full JSON report
python scripts/health_check.py --out reports/health_report.json

# Preview what would be deleted (safe — no deletions)
python scripts/purge_bad_samples.py --dry-run

# Execute cleanup (deletes 270 bad samples)
python scripts/purge_bad_samples.py --execute

# Re-scrape with all improvements
python -m src.generator.run --sources repo github exploitdb osv

# Re-run health check after scraping
python scripts/health_check.py --out reports/health_report_post_scrape.json
```
