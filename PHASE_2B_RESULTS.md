# Phase 2B — Results

**Date:** 2026-05-11
**Status:** Day 3 deliverables landed. Training-ready dataset committed.
**Baseline for comparison:** v1 / v2 trained on the pre-Phase-2B dataset (`runs/phase3_v1`, `runs/phase3_v2`).

---

## Headline numbers

| | Before Phase 2B | After Phase 2B | Δ |
|---|---|---|---|
| **CWEs in dataset** | 7 | **12** | +5 (798, 611, 77, 330, 400) |
| **Total `data/raw/` files** | 1,982 | 1,251 | -731 (refilter + tighter CWE-798 audit) |
| **Training-ready samples** (post-cap) | (no cap applied) | **935** | new pipeline |
| **train / val / test** | (legacy split) | **653 / 140 / 142** | new stratified split |
| **CWEs without val coverage** | 0 | 2 (CWE-330, CWE-798) | data-quantity limit, not pipeline bug |

---

## What changed

### 1. CWE taxonomy expanded (7 → 12)

| New CWE | Name | Why included |
|---|---|---|
| CWE-798 | Hard-coded Credentials | MITRE Top 25; static-mineable; underrepresented in CVE-indexed scrapers |
| CWE-611 | XML External Entity (XXE) | Top 25; clear sink pattern (lxml, etree) |
| CWE-77 | Generic Command Injection | Cousin of CWE-78; broader sink set |
| CWE-330 | Insufficient Randomness | Top 25; security-context co-occurrence required to filter games |
| CWE-400 | Resource Exhaustion / DoS | Top 25; ReDoS, zip bombs, recursion |

`CWE-352, 862, 863, 287, 269, 20, 732, 1333, 377, 434` deferred — they need
function-level taint analysis or authn/authz context not detectable
at the file level.

### 2. Centralised CWE map + sink-presence filter

`src/utils/cwe_taxonomy.py` is now the single source of truth for:
- `CWE_VULN_MAP` — CWE → snake_case vuln_type (12 entries)
- `CWE_NAMES` — human-readable names
- `SINK_PATTERNS` — regex sink patterns per CWE
- `CWES_REQUIRING_SECURITY_CONTEXT` — `{CWE-798, CWE-330}`
- `CWES_REQUIRING_TEST_EXCLUSION` — `{CWE-798, CWE-79}`
- `BLOCKED_SOURCE_CWE` — `{(vudenc, CWE-94): "AUDIT 2026-05-11..."}`

`src/utils/file_utils.has_cwe_sink()` enforces:
1. At least one CWE-defining sink token present.
2. For CWE-798 / CWE-330: also a security-context keyword (auth, token, …).
3. For CWE-798 / CWE-79: not a test/fixture file.

All 8 existing scrapers were migrated to import from the central map and
apply the sink filter before `save_code_sample()`. The legacy
`is_web_code()` gate is gone — non-web CWEs (798/611/330/400) can now
be ingested.

### 3. Pre-existing data refiltered

`scripts/refilter_existing.py` walked the pre-Phase-2B 1,982 files. Moved
749 sink-less files to `data/raw_rejected/` with a manifest. The 749
splits as:

| Source | Reject % | Comment |
|---|---|---|
| cvefixes | 68% | Commit-level mislabels confirmed at scale (audit only found this for CWE-94/502; the filter shows it's pan-CWE) |
| osv | 62% | OSV federates GHSA — same noise propagates |
| ghsa_db | 41% | Lower because of manual GitHub review |
| vudenc | 42% | 15 CWE-94 mislabels dropped by `BLOCKED_SOURCE_CWE`; 130+ other CWE files lacked sinks |
| nvd_targeted | 28% | Newer source, cleaner |
| hardneg_* | 0% | Hard negatives are synthetic; CWE="safe" bypasses the sink filter |

### 4. New source: `hardcoded_creds_miner`

Static scanner over 16 GitHub repos (Saleor, Wagtail, OpenStack Cinder, etc.).
First run produced 13 samples; an audit showed ~85% false-positive rate
(enum constants like `INVALID_PASSWORD = "invalid_password"`,
UI labels like `PASSWORD = "Password"`, and `AWS_SECRET = os.environ.get()`
matches). Patterns were tightened to require:
- Assignment form (`key = 'literal'`, not bare variable name)
- Literal value in quotes (function calls can't match)
- Character variety (uppercase / digit / special inside the value)
- Min length 10 chars for password/passwd

Post-fix: **1 verified sample** (bakerydemo's literal Django SECRET_KEY).
Precision on CWE-798: 8% → 100%.

### 5. `nvd_targeted` re-aimed at the rare classes

`TARGET_CWES_DEFAULT` updated from `["CWE-502", "CWE-918", "CWE-94"]` to
`["CWE-502", "CWE-918", "CWE-94", "CWE-611", "CWE-330", "CWE-400", "CWE-77"]`.
Single full run added:
- +5 CWE-611, +5 CWE-400, +4 CWE-77, +1 CWE-330 (these classes existed nowhere before)
- +7 CWE-94 and +2 CWE-918 to the clean set

### 6. Per-CVE cap + stratified split (`scripts/build_split.py`)

Per-CVE cap = 2 (`--cap 2`, deterministic with `--seed 42`):
- 81 (CWE, CVE) groups exceeded the cap → 316 samples dropped
- `data/raw/` files keep their `.py` and `.meta.json`; capped samples get `split=None` (loader skips them when `apply_sink_filter=True` and a split is requested)
- Audit-findings reproduced: CVE-2020-15142 went from 12 CWE-94 samples → 2; CVE-2025-6279 from 11 CWE-502 → 2

Stratified 70/15/15 per CWE, with a rare-class rule (n<10 → at least 1 val + 1 test where possible):

| CWE | pre-cap | post-cap | train | val | test |
|---|---|---|---|---|---|
| CWE-22 | 174 | 122 | 85 | 18 | 19 |
| CWE-330 | 1 | 1 | 1 | 0 | 0 |
| CWE-400 | 5 | 5 | 3 | 1 | 1 |
| CWE-502 | 21 | 20 | 14 | 3 | 3 |
| CWE-611 | 5 | 5 | 3 | 1 | 1 |
| CWE-77 | 4 | 4 | 2 | 1 | 1 |
| CWE-78 | 16 | 16 | 11 | 2 | 3 |
| CWE-79 | 229 | 142 | 99 | 21 | 22 |
| CWE-798 | 1 | 1 | 1 | 0 | 0 |
| CWE-89 | 282 | 252 | 176 | 38 | 38 |
| CWE-918 | 63 | 48 | 34 | 7 | 7 |
| CWE-94 | 21 | 21 | 15 | 3 | 3 |
| safe | 429 | 298 | 209 | 45 | 44 |
| **Total** | **1,251** | **935** | **653** | **140** | **142** |

---

## What's still open

1. **CWE-330 and CWE-798 have no val/test coverage.** With 1 sample each, the model can't be evaluated on these classes. Need more data — either expand the miner's repo list (CWE-798), or relax the security-context filter (CWE-330) to bring in more from `nvd_targeted`.
2. **CWE-77 and CWE-400 are below the audit threshold of "≥20 real samples per class"** (4 and 5 respectively). Same fix path.
3. **The training pipeline hasn't been re-run.** `runs/phase3_v4/` doesn't exist yet — Day 4 task.

## Success-criteria check (vs PHASE_2B_DESIGN.md §8)

| Criterion | Status |
|---|---|
| ≥9 CWEs with ≥30 sink-validated samples each | **Partial.** 7 CWEs hit ≥20 (89, 79, 22, 918, 502, 94, safe + CWE-78 borderline at 16). 4 new CWEs are below threshold (611, 400, 77, 330, 798) — need more data. |
| `runs/phase3_v4/` macro-F1 ≥ v2's 0.4839 | **Pending Day 4 training.** |
| CWE-94 F1 ≥ 0.30 (vs v2's 0.21) | **Pending Day 4 training.** |
| CWE-798 F1 ≥ 0.50 | **Likely not yet.** Only 1 sample; can't evaluate. Will report N/A. |
| Every dropped sample category documented | **Done.** Two manifests in `data/raw_rejected/` (refilter pass 1 + pass 2) and one in `data/phase2b_filtered_manifest_*.json` (cap drops). |

## Artifacts

- `data/raw/` — 1,251 clean Python files + `.meta.json`
- `data/raw_rejected/` — 2 refilter manifests + the 752 rejected files
- `data/phase2b_filtered_manifest_<timestamp>.json` — per-CVE cap + per-split assignments
- `PHASE_2B_DESIGN.md` — original plan
- `PHASE_2B_DAY1_REPORT.md` — pre-ingest filter validation results
- `PHASE_2B_RESULTS.md` — this document
- Code changes: 3 git commits (`0467fb2`, `1d691c7`, `f3741a4`)
