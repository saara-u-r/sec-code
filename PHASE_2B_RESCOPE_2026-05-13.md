# Phase 2B Re-scope — 8 sink-shaped Top-25 Python CWE benchmark

**Date:** 2026-05-13
**Status:** FINAL — 9 labels (8 sink-shaped CWEs + safe). Ready for evaluation.
**Trigger:** Top-25 taxonomy analysis (*"the alphabet closes when there is a sink"*)
+ evaluation-benchmark scope decision (CASTLE-style table; ≤10-label cap from professors).

**End-of-day refinements (2026-05-13 evening pass):**
1. Dropped CWE-798 (single-source bias, 2-bucket alphabet outside the 5-bucket framing)
2. Merged CWE-77 into CWE-78 (parent/child in MITRE; identical sink set in Python — kept as one "command injection" class with 60 samples)
3. Scraped 192 additional rare-CWE samples via GHSA-DB (CWE-94: 21→91, CWE-502: 21→101, CWE-78: 16→60)
4. Added 28 hand-curated canonical samples (textbook OWASP/SANS examples) tagged `source=canonical` as calibration points

---

## 1. Framework

The MITRE Top-25 list contains 25 CWEs. We classified each by *applicability to Python* and *whether the fix has a closed-alphabet shape*:

| Category | Count | Examples | Decision |
|---|---:|---|---|
| C/C++ memory bugs | 7 | CWE-787, 416, 120, 121, 122, 125, 476 | **Skip** — surface only via C extensions; bug lives in C code |
| Meta categories | 2 | CWE-20, CWE-770 | **Skip** — alphabet would have to be too wide to be useful |
| **Sink-shaped Python CWEs** | **9** | CWE-79, 89, 22, 78, 94, 434, 502, 918, 77 | **PRIMARY — closed alphabet, included** |
| Structural Python CWEs | 7 | CWE-352, 862, 863, 284, 306, 639, 200 | **Defer to Phase 2C** — bug is *absence* of code, no sink to anchor |

The 9 sink-shaped Top-25 Python CWEs (+ CWE-798 retained for the static miner) are the active set for the alphabet exercise.

---

## 2. Changes from Phase 2B Day 3 state

### 2.1 Dropped (not Top-25; correctly labeled but out of scope)

| CWE | Samples moved to `data/raw_rejected/` | Why dropped |
|---|---:|---|
| CWE-611 (XXE) | 5 | Not in MITRE Top-25 |
| CWE-330 (Weak Randomness) | 22 | Not in Top-25; line-proximity filter still kept for CWE-798 |
| CWE-400 (Resource Exhaustion) | 6 | Not in Top-25; ReDoS heuristic would underperform without taint tracking |

Manifest: `data/raw_rejected/manifest_rescope_not_top25_20260513T*.json` — reversible for Phase 2C revival.

`src/utils/cwe_taxonomy.py:DEPRECATED_CWES` records the set; `CWE_NAMES` and `SINK_PATTERNS` keep the entries for back-compat with already-saved samples.

### 2.2 Added — CWE-434 (Unrestricted File Upload)

Sink patterns (`src/utils/cwe_taxonomy.py:SINK_PATTERNS["CWE-434"]`):

| Sink | Pattern | Framework |
|---|---|---|
| Flask/Werkzeug receive | `request.files`, `FileStorage` | Flask |
| Flask save form | `save(os.path.join(...))` | Flask |
| Django receive | `request.FILES`, `FileField(...)`, `ImageField(...)` | Django |
| FastAPI/Starlette receive | `UploadFile`, `await x.read(` | FastAPI |
| Defense-co-occurrence | `secure_filename(`, `ALLOWED_EXTENSIONS` | (proximity signal, not positive evidence) |

**Why no static miner for CWE-434:** the vulnerability is the *absence* of an allowlist / mime-type / magic-byte check around the sink. Without taint tracking we can't reliably tell "sink + no defense" from "sink + defense N lines away." Restricted to CVE-confirmed sources (cvefixes, ghsa_db, osv, pypa, nvd_targeted).

### 2.3 CWE-798 also dropped (evening pass, 2026-05-13)

After the morning's narrowing to 10 active CWEs, an evaluation-scope review found that CWE-798 should also be dropped:

| Reason | Detail |
|---|---|
| Alphabet mismatch | CWE-798's 2-bucket fix alphabet (remove literal / move to vault) doesn't fit the 5-bucket SQLi-style framing of the other 9 sink-shaped CWEs |
| Single-source bias | All 29 CWE-798 samples are from `hardcoded_creds_miner`; for an evaluation benchmark this biases tool-detectability comparisons toward what the miner happened to find |
| Professor 10-label cap | Dropping CWE-798 lands at exactly 10 labels (9 sink-shaped + safe), matching the evaluation-benchmark guidance |

The 29 samples are at `data/raw_rejected/` (manifest `manifest_drop_cwe798_*.json`). `hardcoded_creds_miner` is deregistered from `ALL_SOURCES`/`SCRAPERS` in `src/generator/run.py`. Code retained for Phase 2C revival.

---

## 3. Deferred — structural Top-25 Python CWEs (Phase 2C)

Seven Top-25 CWEs are Python-relevant but the bug is the *absence* of a check, not a misuse of a sink. They need verification-metadata, not fix-pattern labels.

| CWE | Name | "Missing thing" |
|---|---|---|
| CWE-352 | CSRF | `@csrf_protect` decorator, CSRF token field |
| CWE-862 | Missing Authorization | `@permission_required`, `has_perm()` |
| CWE-863 | Incorrect Authorization | wrong `has_perm()` arg / wrong scope |
| CWE-284 | Improper Access Control | (umbrella) |
| CWE-306 | Missing Authentication for Critical Function | `@login_required` on a privileged route |
| CWE-639 | IDOR | ownership check on the queried object (`obj.owner == request.user`) |
| CWE-200 | Info Exposure | serializer/response/log redaction |

### 3.1 Hybrid cases — CWE-200 and CWE-639

These two have *partial* sink-shape:

#### CWE-200 (Info Exposure)

| Variant | Shape | Detectable? |
|---|---|---|
| `logger.info(password)`, `print(token)` | Sink-shaped (call + sensitive arg) | Yes, with proximity + secret-keyword cooccurrence |
| `HttpResponse(token)`, `return jsonify({"secret": ...})` | Sink-shaped (response + sensitive field) | Yes |
| Exception message exposing internals | Sink-shaped, hard to tell intent | Borderline |
| DRF serializer missing `exclude`/`fields` | **Structural** (absence of restriction list) | No without taint |
| Django model `__repr__` printing secret attrs | **Structural** | No without taint |

#### CWE-639 (IDOR)

| Variant | Shape | Detectable? |
|---|---|---|
| `Model.objects.get(pk=request.GET['id'])` without user filter | **Sink-shaped** (the query is the sink; missing `user_id=request.user.id` is the absent defense) | Yes, with view-context proximity |
| `MyView(get_object_or_404(...))` without ownership check | Structural | No without view-flow analysis |

### 3.2 Recommendation for Phase 2C

1. **Build a verification-flag taxonomy first.** Add fields to `build_meta()` like `requires_authz_check`, `requires_csrf_token`, `requires_redaction`. These are the structural counterparts to `has_cwe_sink`.
2. **Tackle CWE-200 sink-shaped subset only.** Patterns: `(logger\.|print\(|HttpResponse\(|JsonResponse\(|return\s+jsonify\().*secret|token|password` proximity. Defer serializer/repr variants.
3. **Tackle CWE-639 sink-shaped subset only.** Patterns: `Model\.objects\.(get|filter)\(.*request\.(GET|POST)` proximity, with absence-of-user-filter as the defense signal.
4. **Defer pure-structural CWEs (CWE-352, 862, 863, 284, 306).** These require AST-level absence detection — not regex.

---

## 4. Final dataset state (end of 2026-05-13)

```
Label       Total  Train   Val  Test    Class
------------------------------------------------------
CWE-89       297    208    45    44     SQL Injection
CWE-79       229    160    34    35     XSS
CWE-22       195    136    29    30     Path Traversal
CWE-502      96     67    14    15     Insecure Deserialization
CWE-94       87     61    13    13     Code Injection
CWE-918      63     44     9    10     SSRF
CWE-78       60     42     9     9     OS Command Injection (now incl. CWE-77)
CWE-434      15     11     2     2     Unrestricted File Upload
safe         429    311    59    59     hard negatives
------------------------------------------------------
Total      1,471  1,040   214   217     (+ 11 NONE: content-hash dupes)
```

**Repo-leakage check:** ✓ 0 overlap across train/val/test (verified by `run_phase2.py`).

**Above the 20-sample audit threshold for stable per-class F1:** all 8 CWE classes except CWE-434 (15 total). The eval table will report CWE-434 with a small-N caveat; every other class has ≥9 test samples.

**Source distribution (after the evening scrape):**
- CWE-502: nvd_targeted=18, cvefixes=9, ghsa_db=63, canonical=6
- CWE-94: nvd_targeted=11, cvefixes=11, ghsa_db=56, osv=1, canonical=6 (others)
- CWE-78: cvefixes=10, ghsa_db=35, vudenc=3, canonical=8 (others)
- CWE-434: ghsa_db=6, cvefixes=1, canonical=8
- The merged CWE-77 contribution: 9 samples now under CWE-78

---

## 5. What landed in this session (code)

| Path | Change |
|---|---|
| `src/utils/cwe_taxonomy.py` | Active map narrowed to 10 CWEs. CWE-434 added with 9 sink patterns. CWE-611/330/400 moved out of `CWE_VULN_MAP` / `TARGET_CWES`. `DEPRECATED_CWES` constant added. `CWE_NAMES` and `SINK_PATTERNS` retain entries for back-compat. `CWES_REQUIRING_SECURITY_CONTEXT` reduced to `{CWE-798}`. |
| `src/utils/file_utils.py` | Unchanged in this session — line-proximity + suppression + docstring blanking already landed 2026-05-12. |
| `src/generator/run.py` | `weak_random_miner` deregistered from `ALL_SOURCES` and `SCRAPERS`. |
| `src/generator/scraper/nvd_targeted_scraper.py` | `TARGET_CWES_DEFAULT` re-scoped: removed 611/330/400, added 434/798. |
| `configs/config.yaml` | `analyzer.vuln_types`, `labeler.cwe_mapping`, `labeler.cvss_mapping` re-scoped to the 10 active CWEs. |
| `scripts/scrape_cwe434.py` | (new) Focused CWE-434 ingest — monkey-patches the taxonomy at runtime to scope cvefixes/ghsa_db output to just CWE-434. |
| `data/raw_rejected/manifest_rescope_not_top25_*.json` | (new) Manifest documenting the 33 CWE-611/330/400 samples moved out of `data/raw/`. |

---

## 6. Open items for the next session

**Now on the evaluation-benchmark track** (training demoted to one row in the
eval table — see `PROGRESS_REPORT_2026-05-13_eval_pivot.md` / chat log).

1. **Stage-1 sample audit** — manual spot-check across the 9 CWEs to surface
   any remaining mislabels. ~30 random samples for big classes (22/79/89/918)
   + full audit for small classes (77/434/78/502/94).
2. **Tool harness** — Bandit + Semgrep runners first, then 2-3 LLMs
   (Claude Sonnet, Claude Opus, GPT-4o) via API. CodeQL deferred.
3. **Robustness eval columns** — apply each of the 4 mutators
   (`dead_code_injection`, `string_split`, `variable_rename`,
   `wrapper_extraction`) to every test sample, run every tool again,
   report per-tool F1-drop per mutator.
4. **Headline tables** — TP/TN/FP/FN per (tool, CWE); macro/per-CWE F1;
   robustness-drop composite.
5. **Train the GraphCodeBERT model as one eval row** — `runs/phase3_v4/` on
   a GPU box. Same schedule, ten output classes now (`src/model/dataset.INDEX_TO_CWE`).
6. **`FIELD_JUSTIFICATION.md`** — still untouched. Update needed:
   add 5 Phase 2B fields (`has_cwe_sink`, `sink_pattern`,
   `is_hard_negative`, `parent_sample_id`, `sanitization_transform`),
   update field count, swap "4 target CWE classes" section for "9
   sink-shaped Top-25 Python CWEs."
