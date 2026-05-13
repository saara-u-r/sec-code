# Phase 2B Re-scope — Top-25 sink-shaped Python CWE alphabet

**Date:** 2026-05-13
**Status:** Re-scope landing. Dataset narrowed from 12 → 10 active CWEs.
**Trigger:** Top-25 taxonomy analysis — *"the alphabet closes when there is a sink"*.

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

### 2.3 CWE-798 retained, but flagged as a special case

CWE-798 (Hardcoded Credentials) is sink-shaped but yields a *2-bucket* fix alphabet (`remove the literal` / `move to env-var or vault`) rather than the 5-bucket SQLi-style alphabet. Kept because:
  * In MITRE Top-25 (#22)
  * The static miner produces high-precision samples post-2026-05-12 line-proximity audit
  * 29 verified samples already on disk

If the writeup wants the cleanest "sink → alphabet" story, CWE-798 can be presented as a *secondary* class with its own "remove-literal" alphabet.

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

## 4. Dataset state at end of re-scope

```
CWE-22:  174   Path Traversal           (sink-shaped, Phase 1)
CWE-78:   16   OS Command Injection     (sink-shaped, Phase 1)
CWE-79:  229   XSS                      (sink-shaped, Phase 1)
CWE-89:  282   SQL Injection            (sink-shaped, Phase 1)
CWE-94:   21   Code Injection           (sink-shaped, Phase 1)
CWE-918:  63   SSRF                     (sink-shaped, Phase 1)
CWE-502:  21   Insecure Deserialization (sink-shaped, Phase 1)
CWE-77:    4   Generic Cmd Injection    (sink-shaped, Phase 2B)
CWE-434:   1+  Unrestricted Upload      (sink-shaped, Phase 2B re-scope; +N from running ghsa_db scrape)
CWE-798:  29   Hardcoded Credentials    (2-bucket alphabet; Top-25)
safe:    429   hard negatives
----
Total:  1268 + new CWE-434 from ghsa_db
```

CWE-77 (4) and CWE-434 (1 + pending) are below the audit threshold of "≥20 real samples per class." Acceptable for the writeup (small classes report N/A on per-class F1) but should be expanded in Phase 2C.

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

1. **Wait for the background `ghsa_db` CWE-434 scrape to complete.** Tail `logs/cwe434_ghsa_db_*.log`. Expected: 5-20 verified samples.
2. **Re-run `scripts/run_phase2.py`** for the new stratified split with the 10-CWE taxonomy.
3. **Update `configs/class_weights.json` and `configs/cvss_targets.json`** — both were generated from the pre-re-scope dataset and contain entries for the dropped CWEs.
4. **Day 4 GraphCodeBERT training (`runs/phase3_v4/`)** — unblocked once split + configs regen.
5. **`FIELD_JUSTIFICATION.md`** — still untouched. Pure writing task, can parallelize with training.
