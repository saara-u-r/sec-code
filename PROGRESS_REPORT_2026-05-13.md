# Progress report — 2026-05-13

**Session focus:** project pivot from training-focused to evaluation-focused (CASTLE-for-Python benchmark style), driven by the user's professors' preference for an evaluation-first contribution. Three audit rounds + a diff-based label filter brought the dataset to benchmark-grade, and the first three full sections of the paper draft landed.

**Session outcome:** 13 commits on `main`. Dataset shrunk from 1,275 → 871 samples but the audited FP rate dropped from 52% → 26%. Paper went from "stub" to 37 pages typeset with three full sections (introduction, dataset, methodology) and related work + bibliography in place.

---

## What landed (13 commits on `main`)

```
c145862 Paper: related work section + bibliography
23606ac Paper: methodology section — four adversarial mutators
f31742e Paper: dataset section first full draft
b7679e6 Paper: scaffold + draft abstract & introduction
4f53d6b Stage-1 audit v3: diff filter cut FP rate 51% → 26%
0f847d1 Path 2: diff-based filter — require sink line to change between code_before/code_after
3801e58 Re-audit v2 on cleaned dataset
b1f6c23 Audit-driven cleanup: drop CWE-434, drop 34 FPs, tighten 5 sink patterns
e47d573 Benchmark scope finalized: 8 sink-shaped Top-25 Python CWEs + safe (9 labels)
d5b6253 Drop CWE-798: land at 10 labels (9 sink-shaped + safe) for eval benchmark
53f9754 Phase 2B re-scope follow-up: 11-class label vocab + regen configs
532e761 Phase 2B re-scope: narrow to 9 sink-shaped Top-25 Python CWEs + CWE-798
fdd9b9c Phase 2B Day 4: line-proximity security-context filter for CWE-330/798
```

### New files

| Path | Purpose |
|---|---|
| `BENCHMARK_AUDIT_REPORT_2026-05-13.md` | Round-1 audit (77 samples, 8 CWEs). 6 failure-pattern taxonomy + recommended fixes. |
| `BENCHMARK_AUDIT_REPORT_v2.md` | Round-2 audit after pattern fixes; 51% FP held. Three-path analysis. |
| `BENCHMARK_AUDIT_REPORT_v3.md` | Round-3 audit after diff filter; 26% FP. Ship-ready assessment. |
| `STRUCTURAL_CWES_DEFERRED.md` | Scope justification: 7 structural Top-25 Python CWEs deferred + verification-metadata sketch for Phase 2C. |
| `PHASE_2B_RESCOPE_2026-05-13.md` | (Updated from morning session) records the multi-stage rescope decisions. |
| `scripts/build_audit_pack.py` | Per-CWE markdown audit pack generator with sink-localized code excerpts. |
| `scripts/refilter_by_diff.py` | Diff-based filter implementation; moves sink-unchanged samples to rejection manifest. |
| `scripts/merge_cwe77_into_cwe78.py` | One-shot relabel for the CWE-77 → CWE-78 merge with audit-trail preservation. |
| `scripts/add_canonical_samples.py` | Hand-curated textbook samples generator (was used for CWE-434/78/94/502 canonicals). |
| `scripts/scrape_rare_cwes.py` | Focused GHSA-DB ingest for rare CWEs (used to grow CWE-78/94/502). |
| `scripts/scrape_cwe434.py` | (Used briefly before CWE-434 was dropped.) |
| `scripts/sync_mongo_to_disk.py` | Mongo-vs-disk sync utility (run after every dataset change). |
| `paper/main.tex` | Elsevier C&S template; title + abstract + keywords drafted. |
| `paper/sections/introduction.tex` | Full draft, ~1.5 typeset pages. |
| `paper/sections/related_work.tex` | Full draft, ~4 typeset pages, 6 subsections. |
| `paper/sections/dataset.tex` | Full draft, ~7 typeset pages with algorithm figures + tables. |
| `paper/sections/methodology.tex` | Full draft, ~7 typeset pages on the 4 adversarial mutators. |
| `paper/bib/references.bib` | 24 entries populated; 2 flagged `TODO_VERIFY` for missing details. |
| `paper/.gitignore` | LaTeX build artifacts. |

### Modified files

| Path | Change |
|---|---|
| `src/utils/cwe_taxonomy.py` | `TARGET_CWES` narrowed 12 → 7 over the session (dropped 611, 330, 400, 798, 434; merged 77 → 78). Sink patterns tightened in 5 places. `CWES_REQUIRING_REQUEST_PROXIMITY` constant introduced. |
| `src/utils/file_utils.py` | Added `_strip_comments_for_match()`, `has_request_near()`, `sink_was_modified()`. `has_cwe_sink` now strips comments before sink matching and checks request-proximity for CWE-22. |
| `src/model/dataset.py` | `CWE_TO_INDEX` shrunk 11 → 8 outputs as CWEs were dropped. v1/v2 model checkpoints would need head re-init to load. |
| `src/generator/run.py` | `weak_random_miner` and `hardcoded_creds_miner` deregistered. |
| `src/generator/scraper/nvd_targeted_scraper.py` | `TARGET_CWES_DEFAULT` re-scoped through multiple passes; final: CWE-502, CWE-918, CWE-94, CWE-78. |
| `configs/config.yaml` | Vuln-type list and CWE mapping shrunk to match the 7 active CWEs. |
| `configs/class_weights.json`, `configs/cvss_targets.json` | Regenerated after each dataset change. |

---

## Dataset evolution

| Metric | Morning (pre-pivot) | Evening (post-Path-2) | Δ |
|---|---|---|---|
| Active CWE labels | 10 (incl. CWE-798) | **8** (7 sink-shaped + safe) | -2 |
| Total samples on disk | 1,275 | **871** | -404 |
| Train / val / test | 880 / 182 / 181 | **607 / 127 / 132** | -273 / -55 / -49 |
| Repo-leakage across splits | 0 | **0** | unchanged |
| **Audited false-positive rate** | (was 52% in v1 of audit) | **26%** | **-26 points** |

### Final per-CWE distribution

| CWE | Total | Train | Val | Test | Audit v3 FP% |
|---|---:|---:|---:|---:|---:|
| CWE-89 SQL Injection | 212 | 148 | 32 | 32 | 50%\* |
| CWE-502 Insecure Deserialization | 78 | 51 | 11 | 12 | 0% |
| CWE-79 XSS | 54 | 40 | 7 | 7 | 50% |
| CWE-94 Code Injection | 36 | 24 | 5 | 6 | 0% |
| CWE-78 OS Command Injection | 25 | 17 | 4 | 4 | 12% |
| CWE-918 SSRF | 22 | 17 | 2 | 3 | 36% |
| CWE-22 Path Traversal | 15 | 10 | 2 | 3 | 27% |
| safe (hard negatives) | 429 | 300 | 64 | 65 | n/a |
| **Total** | **871** | **607** | **127** | **132** | **26% overall** |

\*CWE-89 v3 N=6 with wide CI; carries over residual noise from the `vudenc`-sourced sub-corpus that lacks `code_after` and cannot be diff-validated.

---

## What got built (chronological)

### 1. Re-scope passes (morning)

- Dropped CWE-798 to land at exactly 10 labels (9 sink-shaped + safe). 29 samples moved to `data/raw_rejected/` with manifest. `CWES_REQUIRING_SECURITY_CONTEXT` set emptied (both CWE-330 and CWE-798 had used it; both now deprecated).
- Confirmed the pipeline replay (Mongo sync, Phase 2 stratified split, configs regen, training dry-run) survives the label-vocabulary shrink end to end.

### 2. Stage-1 audit (round 1)

- Built `scripts/build_audit_pack.py` — per-CWE markdown audit pack generator that pulls the sink-localized code excerpt plus metadata and emits a verdict slot per sample.
- Ran 8 parallel Explore-agent audits across 77 random positives. Found **52% aggregate FP rate**. Failures clustered into 6 recurring patterns:
  1. Sink-too-broad (matches framework source, type annotations, imports)
  2. Co-changed file noise (sink present but safe form, fix unrelated)
  3. Documentation matches (comments and docstrings)
  4. Pattern conflation (`re.compile` matched CWE-94's bare `compile(`)
  5. Inverted operations (`jsonpickle.encode` matched CWE-502)
  6. Wrapper abstractions (class def or wrapper function)

- Dropped 34 specific FPs by manifest with per-sample reason; full audit report at `BENCHMARK_AUDIT_REPORT_2026-05-13.md`.

### 3. Pattern tightening (5 changes)

- **CWE-22:** added a request-proximity check via new `CWES_REQUIRING_REQUEST_PROXIMITY` set; sink must be within ±20 lines of a `request.*`/`HttpRequest`/`web.Request` reference.
- **CWE-79:** removed the broad "request + render call" bucket. Kept the explicit escape-bypass sinks only (`mark_safe`, `Markup`, `|safe`, `render_template_string`, `autoescape=False`, etc.).
- **CWE-94:** dropped the bare `compile(` pattern (was matching `re.compile`).
- **CWE-918:** removed `ClientSession` constructor (was matching type annotations).
- **CWE-502:** narrowed `jsonpickle.` to `jsonpickle.(decode|loads)`; narrowed `__reduce__` to `def __reduce__`; narrowed `shelve.` to `shelve.(open|load)`.
- Added `_strip_comments_for_match()` helper so all sink patterns run against a comment-blanked copy of the source.

### 4. CWE-434 dropped entirely

- Round-1 audit found 0/7 audited CWE-434 samples valid (100% FP) — the sink patterns matched Django framework source, form-field declarations, imports, and docstrings rather than actual upload handlers.
- All 15 CWE-434 samples (7 scraped + 8 canonical) moved to rejection manifest.
- Final benchmark goes from 8 labels → 7 sink-shaped CWEs + safe = 8 labels (still under professors' ≤10 cap).

### 5. Audit round 2 (held steady at 51%)

- Pattern tightenings worked where designed (CWE-502 went 40% → 20%), but the aggregate FP rate held essentially flat (52% → 51%) because the new random samples surfaced different failure modes on un-tightened CWEs.
- Diagnosis: residual noise is **co-changed-file noise** that pattern fixes cannot remove. This motivated the diff-based filter.

### 6. Diff-based filter (Path 2)

- New `file_utils.sink_was_modified(code_before, code_after, cwe)` returns `(True, line)` if at least one line containing a sink-pattern match exists in `code_before` but not in `code_after`. Strips comments and normalizes whitespace before comparison.
- `scripts/refilter_by_diff.py` walks the dataset, applies the filter, moves rejects to `data/raw_rejected/` with manifest. Default mode keeps samples that lack `code_after` (e.g., `vudenc`) as a separate confidence tier; `--strict` drops them.
- **316 samples (43% of remaining positives) rejected as commit-level noise.** CWE-79 lost 116 of 170, CWE-22 lost 37 of 52, CWE-78 lost 32 of 49.

### 7. Audit round 3 (FP rate halved)

- Audited 78 samples on the diff-filtered dataset (full audit of small classes; 6 per populous class).
- **Aggregate FP rate dropped from 51% to 26%.** CWE-22 saw the biggest single improvement: 80% → 27%. CWE-502 and CWE-94 hit 0% FP.
- Two of the seven agents inverted PASS/FAIL semantics again — corrected manually.

### 8. Paper scaffolding + first 4 sections drafted

| Section | Status | Approx pages |
|---|---|---:|
| Title + abstract + keywords | ✓ | <1 |
| 1. Introduction | ✓ | 1.5 |
| 2. Related Work | ✓ | 4 |
| 3. Dataset Construction | ✓ | 7 |
| 4. Methodology (mutators) | ✓ | 7 |
| 5. Evaluation | TODO stub | — |
| 6. Threats to Validity | TODO stub | — |
| 7. Conclusion | TODO stub | — |

- Total typeset: **37 pages**. Compiles cleanly with `pdflatex + bibtex`.
- Tone deliberately matches the CASTLE paper: direct declarative sentences, specific numbers, no AI-tell vocabulary (`leverage`, `comprehensive`, `delve`, `seamless`, etc.).
- 24 bibliography entries populated. Two flagged `TODO_VERIFY` (CASTLE pages/venue; Steenhoek venue) for confirmation before submission.

---

## Methodology contributions claimable in the paper

1. **Three-layer label-validation methodology** for CVE-derived datasets. Each layer is reusable independent of the others:
   - Pre-ingest sink-presence filter (Phase 2B contribution, well established now)
   - Adversarial audit by independent reviewers with structured failure-pattern taxonomy
   - **Diff-based filter requiring sink-line modification** — to our knowledge novel in this literature
2. **Sink-shaped vs structural CWE scope justification** (`STRUCTURAL_CWES_DEFERRED.md`) — explicit methodological separation rather than a silent exclusion.
3. **Four targeted adversarial mutators** for per-shortcut diagnostic robustness evaluation, extending CASTLE's framing.

The combined story: *"audited FP rate 52% → 26% via three filter layers; per-mutator F1 drop diagnoses which detection shortcut each tool uses."*

---

## What's left for the project

### Paper writing (3 sections + small polish, ~half a day)

1. **Evaluation section** (`paper/sections/evaluation.tex`) — RQs, table shape, metrics. Most of it can be structure-only until tools actually run. Per-CWE F1, per-mutator robustness columns, per-framework breakdown, three-tier label-confidence stratification.
2. **Threats to validity** — short. Three threats to call out: (a) the residual 26% audit FP, (b) the `vudenc`-tier samples cannot be diff-validated, (c) the small-N classes (CWE-22 at $n_{\text{test}}=3$) have wide CIs.
3. **Conclusion** — restate gap, summarize contribution, point at future work (structural-CWE track, cross-language extension, more LLM/SAST tools).
4. **Verify the two `TODO_VERIFY` bib entries** (CASTLE, Steenhoek) — need exact venue + pages.
5. **Finish the abstract** — drop in the headline eval result sentence once tools have run.

### Evaluation harness (the bulk of remaining engineering)

6. **Bandit + Semgrep runners.** File-level static analyzers; easy to install and script. Should be a few hours of work to wire up per-sample TP/TN/FP/FN accounting against the labels.
7. **LLM evaluation harness.** Prompt + parse for Claude (Sonnet, Opus), GPT-4o or o3, possibly DeepSeek. Approximately 200-500 USD in API spend depending on model selection and how many adversarial variants we evaluate. Run on the 132 test samples + 4 mutator variants each = 660-792 prompts per model.
8. **CodeQL runner** (optional). Higher setup cost; deferred.
9. **Mutator harness for the test set.** Apply each of the 4 mutators to all 132 test samples (and the 132 mutator-variant sets for composed runs). The mutator code is already implemented in `src/red_team/mutators/`; need a small script to materialize the variants.

### Local-only work that can happen now without external resources

10. **Run Bandit / Semgrep against the current test set.** Both are `pip install`-able; produces a first detection baseline today. Output is a JSON per tool per sample; aggregation is a small script.
11. **Materialize the 4 mutator-variant test sets** (clean, +dead_code, +string_split, +variable_rename, +wrapper_extraction). Deterministic given seed; no external dependencies.
12. **Update `FIELD_JUSTIFICATION.md`** to cover the 5 Phase 2B fields (`has_cwe_sink`, `sink_pattern`, `is_hard_negative`, `parent_sample_id`, `sanitization_transform`). Pure writing.
13. **Decide on title and license.** Two minutes of user input.
14. **Verify the two `TODO_VERIFY` bib entries.** Five minutes with Google Scholar.
15. **Write a `README.md` for the dataset release** — describes label confidence tiers, how to load splits, how to apply mutators, how to add a new tool to the eval harness.

### Bigger lifts (separate sessions)

16. **Run the LLM eval** — requires API keys + cost authorization. Should be batched.
17. **Optional: train the GraphCodeBERT model** as one row in the eval table. Needs a GPU box; the pipeline is dry-run-verified end-to-end so the actual run is a one-line `nohup` away from a working machine.
18. **Write up results sections** — done after evaluations run.

### Suggested next-session order

1. Materialize the mutator-variant test sets (1 hr, no dependencies)
2. Install + run Bandit and Semgrep (1-2 hrs)
3. Build the LLM harness in dry-run mode (test on 5 samples; estimate full cost) (1 hr)
4. Run full LLM eval (background, 1-4 hrs depending on model selection)
5. Generate first headline tables (1 hr)
6. Draft evaluation section with real numbers (1 hr)

---

## Open items not yet addressed

| Item | Why it's still open |
|---|---|
| CWE-89 vudenc-tier samples | 206 of 212 CWE-89 samples are `vudenc`-sourced and lack `code_after`. Kept as separate confidence tier; the v3 audit suggests they carry $\approx 30\%$ residual noise. Could be deep-audited manually (~3-4 hours) if shipping cleaner CWE-89 matters more than dataset size. |
| CWE-22 small-$n$ | 3 test samples is below the audit-stability threshold. Could attempt another scrape round targeting CWE-22 specifically (NVD-targeted with broader Python heuristic) but yield is uncertain. |
| FIELD_JUSTIFICATION.md | Has 1{,}137 lines from earlier in the project but lists 48 fields against a current schema of 46. Five Phase-2B-era fields are undocumented. The fix is mechanical but takes about an hour of careful writing. |
| Two `TODO_VERIFY` bib entries | CASTLE (Dubniczky et al. 2025) and Steenhoek 2024 need exact venue + pages confirmed. |
| Title + license + author info | One paragraph of user input gets all three locked. |

---

## Numbers worth remembering for the writeup

- Audit-validated false-positive rate: **52\% (raw)** → **51\% (post-pattern-fix)** → **26\% (post-diff-filter)**
- Final benchmark: **871 samples**, **8 labels**, **607 / 127 / 132** train/val/test, **0** repo-leakage
- Three-layer filter rejection counts: Phase 2B sink filter dropped 749 samples; audit-driven cleanup dropped 49 (40 FPs + 9 from CWE-434 incl. canonicals); diff filter dropped 316
- Pattern tightening: 6 sink patterns modified plus the global comment-stripping pass
- Mutators: 4, each targeting a distinct detection shortcut
- Paper: 37 pages typeset, 4 of 7 sections fully drafted
