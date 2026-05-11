# Phase 2B — Dataset expansion to MITRE Top 25 (Python-relevant)

**Date:** 2026-05-11
**Timeline:** 4 days
**Goal:** Expand `data/raw/` from the current 7 web-skewed CWEs to ~12 CWEs covering web, CLI, ML, scientific, and stdlib Python — with sink-presence quality filters applied at scrape time so the noise found in the v1 audit never re-enters the pipeline.

This document is the contract for the work. Day-2 implementation should not deviate from this without updating it.

---

## 1. CWE scope

### 1.1 Keep (existing 7)

| CWE | Name | Current count | Status |
|---|---|---|---|
| 89 | SQL Injection | 332 | Healthy — keep, will benefit from per-CVE cap |
| 79 | Cross-site Scripting | 309 | Healthy — keep |
| 78 | OS Command Injection | 56 | Low count — add CLI/devops sources |
| 22 | Path Traversal | 181 | Healthy — keep |
| 918 | SSRF | 127 | Healthy — keep |
| 502 | Insecure Deserialization | 34 | Low + label-noisy — sink filter required |
| 94 | Code Injection | 48 | Low + label-noisy — sink filter required, drop vudenc |

### 1.2 Add (5 new, MITRE Top 25 2025, Python-relevant)

| CWE | Name | Why this one | Target sample count |
|---|---|---|---|
| 798 | Hard-coded Credentials | Static-mineable from PyPI top-N; abundant; underrepresented in vuln-classifier literature | 100–150 |
| 611 | XML External Entity (XXE) | lxml / xml.etree CVEs are well-documented; clear sink pattern | 50–80 |
| 77 | Command Injection (generic) | Cousin of CWE-78 with broader sink set; cheap to harvest alongside 78 | 50–80 |
| 330 | Insufficient Randomness | `random.random` / `random.choice` for security tokens — static-mineable + CVE-confirmed | 50–80 |
| 400 | Resource Exhaustion / DoS | ReDoS, zip bombs, recursion — abundant in CVE feeds | 50–80 |

**Total target:** ~1,400 → ~1,700–1,900 labeled positives across 12 CWEs.

### 1.3 Explicitly out of scope for Phase 2B

- **CWE-352 (CSRF), 862, 863, 287, 269** — require authn/authz context; hard to mine at file level. Defer to Phase 2C.
- **CWE-787, 125, 416, 119, 476, 190** — C/C++ memory bugs, not meaningful for Python.
- **CWE-20 (input validation)** — too broad; would dominate the dataset with low-quality samples.
- **Sample-count parity with CWE-89.** We are not trying to balance; rare classes stay rare. Class-balanced sampler handles training.

---

## 2. Architecture changes

### 2.1 Centralize the CWE map

Every scraper currently duplicates the same `CWE_VULN_MAP`. Refactor to a single source of truth:

```
src/utils/cwe_taxonomy.py     (new)
    CWE_VULN_MAP        — {CWE-NNN: snake_case_name}
    TARGET_CWES         — set of CWE-NNN strings
    SINK_PATTERNS       — {CWE-NNN: [re.Pattern, ...]}
    CWE_NAMES           — {CWE-NNN: "Human Readable Name"}  (moves from file_utils)
```

Each scraper changes from:
```python
CWE_VULN_MAP = {"CWE-89": "sql_injection", ...}    # delete
```
to:
```python
from src.utils.cwe_taxonomy import CWE_VULN_MAP, TARGET_CWES
```

Eight scrapers updated identically. Adding a new CWE later = edit one file, not eight.

### 2.2 Sink-presence filter at scrape time

Add to `src/utils/file_utils.py`:

```python
def has_cwe_sink(code: str, cwe: str) -> bool:
    """Return True if `code` contains at least one sink pattern for `cwe`.
    Returns True (skip filter) for unknown CWEs."""
```

Wire into `build_meta()` so every sample gets a `has_cwe_sink: bool` field auto-computed. Then in each scraper, before saving:

```python
if not has_cwe_sink(code_before, cwe):
    logger.debug(f"Skipping sink-less sample for {cwe}")
    continue
```

This means **the noisy vudenc-style samples never get written to disk in Phase 2B.** The v3a-planned post-hoc filter becomes a pre-ingest filter.

### 2.3 Per-CVE cap (deferred to ingest-side, not scrape-side)

Cap-of-2-per-CVE is applied during dataset assembly, not during scraping (so we don't throw away samples we might want for analysis). Implement in `src/labeler/data_prep.py` or a new `scripts/build_split.py`.

### 2.4 Replace `is_web_code()` gate with `has_cwe_sink()` gate

Current `osv_scraper.py:302` drops non-web code. For non-web CWEs (798, 611, 330, 400) this is wrong. Remove the `is_web_code()` rejection; rely on `has_cwe_sink()` for label-validity gating. Keep `is_web_code` as a *signal* (still computed in `build_meta`), just not as a *filter*.

---

## 3. Sink patterns per CWE

These are the regex patterns used by `has_cwe_sink()`. Conservative — false negatives are acceptable (we'd rather drop a real sample than ingest a noisy one); false positives are dangerous.

```python
SINK_PATTERNS = {
    "CWE-89":  [r"\.execute\s*\(\s*f['\"]", r"\.execute\s*\(.*?%\s",
                r"\.execute\s*\(.*?\+", r"text\s*\(\s*f['\"]"],
    "CWE-79":  [r"\|\s*safe\b", r"mark_safe\s*\(", r"Markup\s*\(",
                r"render_template_string\s*\(", r"\.innerHTML"],
    "CWE-78":  [r"os\.system\s*\(", r"os\.popen\s*\(",
                r"subprocess\..*shell\s*=\s*True", r"commands\."],
    "CWE-77":  [r"os\.system\s*\(", r"subprocess\..*shell\s*=\s*True",
                r"\.communicate\s*\(.*shell"],
    "CWE-22":  [r"open\s*\(.*request", r"send_file\s*\(.*request",
                r"os\.path\.join\s*\(.*request", r"\.\./", r"send_from_directory\s*\(.*request"],
    "CWE-918": [r"requests\.(get|post|put|delete)\s*\(.*request",
                r"urllib.*urlopen\s*\(.*request", r"urllib\.request\.urlopen\s*\("],
    "CWE-502": [r"pickle\.loads?\s*\(", r"cPickle\.loads?\s*\(",
                r"yaml\.load\s*\((?!.*safe_load)", r"marshal\.loads?\s*\(",
                r"__reduce__", r"shelve\."],
    "CWE-94":  [r"\beval\s*\(", r"\bexec\s*\(", r"\bcompile\s*\(",
                r"__import__\s*\(", r"importlib\.import_module"],
    "CWE-798": [r"password\s*=\s*['\"][A-Za-z0-9_!@#$%^&*\-]{6,}['\"]",
                r"api[_-]?key\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
                r"secret\s*=\s*['\"][A-Za-z0-9_\-]{12,}['\"]",
                r"token\s*=\s*['\"][A-Za-z0-9_\-]{20,}['\"]",
                r"AWS_SECRET", r"private[_-]?key\s*=\s*['\"]-----BEGIN"],
    "CWE-611": [r"lxml.*resolve_entities\s*=\s*True", r"XMLParser\s*\(",
                r"etree\.parse\s*\(", r"xml\.sax\.", r"xml\.dom\.",
                r"feedparser\.parse"],
    "CWE-330": [r"random\.(random|choice|randint|sample|shuffle)\s*\(",
                r"random\.SystemRandom"],
    "CWE-400": [r"re\.(match|search|findall|compile)\s*\(.*\(.+\)\+.+\)\+",
                r"zipfile\.ZipFile.*extractall", r"recursion",
                r"while\s+True", r"\.read\(\)"],
}
```

**Caveats:**
- CWE-798 patterns need a `is_test_file()` exclusion (filenames matching `test_*`, `*_test.py`, in `tests/`, `examples/`, `docs/`). Otherwise we'll harvest fixture creds.
- CWE-330 patterns will false-positive on legitimate non-security uses of `random` (games, simulations). Pair with a "security context" check — sample must also contain `token`, `password`, `secret`, `session`, or similar near the sink. Implement as a second-pass filter in the static miner.
- CWE-400 patterns are weakest; rely on CVE-confirmed sources (NVD/GHSA) rather than static mining for this CWE.

---

## 4. Sources per CWE

### 4.1 Existing scrapers extended

Update `TARGET_PACKAGES` in OSV / PyPA / GHSA-DB scrapers to add non-web Python:

```python
NEW_PACKAGES = [
    # CLI / devops
    "ansible", "salt", "paramiko", "fabric", "invoke", "click",
    # ML / scientific
    "transformers", "torch", "tensorflow", "mlflow", "ray", "datasets",
    "huggingface-hub", "numpy", "scipy", "pandas", "jupyter", "ipython",
    # Stdlib-adjacent
    "lxml", "defusedxml", "pyyaml", "requests", "urllib3",
    # Crypto / auth
    "cryptography", "pyjwt", "authlib", "passlib",
]
```

Combined with existing web packages, this should yield broader CWE coverage on the next scrape pass.

### 4.2 New: CWE-798 static miner

`src/generator/scraper/hardcoded_creds_miner.py` (new):
- Input: list of PyPI packages (top-1000 or curated)
- Approach: for each package, clone shallow + walk `.py` files
- Apply CWE-798 sink regex
- Exclude: filename matches `test_*|*_test\.py|conftest\.py`, paths containing `/tests/`, `/test/`, `/examples/`, `/docs/`, `/fixtures/`
- For each match, save the file as a CWE-798 sample with `code_after = file with the literal credential redacted to '<REDACTED>'`
- This gives us natural paired samples without needing a fix commit

### 4.3 New: CPython security advisories

`src/generator/scraper/cpython_advisories_scraper.py` (new, lower priority — day 3):
- Pull from `https://www.python.org/news/security/` feed
- Map to CVE IDs, then use NVD lookup to get details
- Lower-volume source but high-quality

### 4.4 Drop vudenc CWE-94 entirely

In `src/generator/scraper/vudenc_loader.py`, the existing `LABEL_MAP` keeps label 7 → CWE-94. Change to `None` so all vudenc CWE-94 samples are silently dropped. Document in code comment.

---

## 5. Schema impact

`build_meta()` adds two new auto-computed fields:

```python
"has_cwe_sink":     bool,    # NEW — result of has_cwe_sink(code_before, cwe)
"sink_pattern":     str,     # NEW — which pattern matched (for debuggability), or None
```

`SCHEMA_VERSION` bumps from `"2.0"` → `"2.1"`. Old samples on disk remain readable (missing fields default to None at read time).

`configs/config.yaml` adds five new entries:

```yaml
analyzer.vuln_types:
  + hardcoded_credentials
  + xml_external_entity
  + command_injection_generic
  + weak_randomness
  + resource_exhaustion
labeler.cwe_mapping:
  + hardcoded_credentials: "CWE-798"
  + xml_external_entity: "CWE-611"
  + command_injection_generic: "CWE-77"
  + weak_randomness: "CWE-330"
  + resource_exhaustion: "CWE-400"
labeler.cvss_mapping:
  + hardcoded_credentials: 9.8
  + xml_external_entity: 7.5
  + command_injection_generic: 9.8
  + weak_randomness: 5.3
  + resource_exhaustion: 7.5
```

`configs/class_weights.json` and `configs/cvss_targets.json` get five new entries — regenerated by re-running `scripts/run_phase2.py` after the scrape.

---

## 6. Day-by-day plan

### Day 1 (today)
- [x] Write this design doc
- [ ] Create `src/utils/cwe_taxonomy.py`; migrate all 8 scrapers to import from it
- [ ] Update `configs/config.yaml` with 5 new vuln types
- [ ] Add `has_cwe_sink()` to `file_utils.py`; wire into `build_meta()`
- [ ] Bump `SCHEMA_VERSION` to "2.1"
- [ ] Smoke test: run cvefixes scraper on existing 7 CWEs, confirm sink filter rejects ≥1 known-noisy sample

### Day 2
- [ ] Drop vudenc CWE-94 mapping
- [ ] Broaden `TARGET_PACKAGES` in OSV/PyPA/GHSA-DB scrapers
- [ ] Write `hardcoded_creds_miner.py` (PyPI static scan for CWE-798)
- [ ] Kick off long-running scrape — runs overnight, IO-bound
- [ ] In parallel: spot-check 5 samples per new CWE manually for label quality

### Day 3
- [ ] Apply per-CVE cap (max 2) via `scripts/build_split.py`
- [ ] Generate stratified train/val/test split with rare classes oversampled in val
- [ ] Write `PHASE_2B_RESULTS.md` with pre/post counts, dropped sample inventory, sink-coverage per CWE
- [ ] Parallel CPU work: update `FIELD_JUSTIFICATION.md`

### Day 4
- [ ] Launch training on expanded dataset, same schedule as v2 (warmup=3, phase_a=8, phase_b=0). Call it `runs/phase3_v4/`.
- [ ] In parallel: update `PHASE1_PROGRESS_REPORT.md` and `MOTIVATION_REPORT.md`
- [ ] Capture results in `runs/phase3_v4/RESULTS.md` vs v2 baseline

---

## 7. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| GHSA/NVD API throttling extends Day 2 by 12+ hours | Medium | Day 4 slips | Cache aggressively; start scrape on Day 1 evening |
| CWE-77/330/400 yield <20 real samples after sink filter | Medium | Drop those CWEs, end at 9 instead of 12 | Acceptable — drop in priority order: 400, 330, 77 |
| Static miner for CWE-798 produces too many false positives | High | Manual triage burns Day 3 | Use the `is_test_file()` exclusion aggressively; require a "security context" co-occurrence |
| Sink filter regex has false negatives, drops real positives | Medium | Smaller dataset than expected | Accept it; conservative filter > noisy data per audit findings |
| New CWE labels confuse the existing 7-class CVSS targets table | Low | Training won't start | Add new CWEs to `cvss_targets.json` before retraining |

---

## 8. Success criteria for Phase 2B

This phase succeeds if **all** of:

1. `data/raw/` contains ≥9 CWEs with ≥30 sink-validated samples each (down from 12-target only if rare CWEs underperform).
2. `runs/phase3_v4/` macro-F1 ≥ v2's 0.4839 — or if lower, the per-class breakdown shows ≥3 CWEs with F1 ≥ 0.4 (i.e., we traded easy-class F1 for broader real-coverage, deliberately).
3. CWE-94 F1 ≥ 0.30 (vs v2's 0.21) — confirming that pre-ingest filtering beats post-hoc augmentation.
4. CWE-798 F1 ≥ 0.50 — easy class, should learn fast if the data is clean.
5. Documented: every dropped sample category has a reason in `PHASE_2B_RESULTS.md`.

If criterion 1 or 2 fails, that's the writeup conclusion — pivot to canonical hand-curated positives in Phase 2C.

---

## 9. Out-of-scope follow-ups (Phase 2C+)

- Hand-curated canonical positives for the lowest-yield rare CWEs (likely 502, 611, 330)
- Authn/authz CWEs (352, 862, 863, 287, 269) — needs function-level taint tracking, not file-level
- Cross-language transfer (Python → JavaScript via shared CWE labels)
- Synthetic positive generation via LLM (separate methodological question)
