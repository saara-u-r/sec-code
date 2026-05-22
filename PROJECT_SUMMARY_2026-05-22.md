# sec_code — Project Summary (as of 2026-05-22)

A research pipeline that builds **PyVulSev**, a Python vulnerability-detection
benchmark targeting Python web frameworks (Flask, Django, FastAPI, aiohttp,
Tornado, Bottle, Quart, Starlette) plus adjacent ecosystems where the target
CWEs appear (CLI/devops, ML/scientific, XML/serialization, crypto/auth, HTTP
clients, cloud SDKs). The pipeline scrapes real-world vulnerability fixes,
filters and splits them into a benchmark, generates adversarial variants, trains
a detection model, and evaluates SAST tools, LLMs, and the trained model against
the benchmark — including under adversarial code rewrites.

The original seven-phase scope has been re-scoped along the way: Phase 2 was
gutted, Phase 2B and Phase 2.5 were added as a benchmark-quality pass and an
adversarial-augmentation pass, Phase 5 was collapsed into Phase 3, and Phase 4
is the new evaluation harness.

---

## Step-by-step pipeline (current state)

### Phase 1 — Scrape & ingest (`src/generator/`, `scripts/run_generator.py`)

- **Sources scraped:** CVEfixes, OSV.dev, GHSA (GitHub Security Advisories),
  PyPA Advisory DB, NVD-targeted scrape, VUDENC, canonical hand-written
  samples, and hard-negative variants of each.
- **Coverage:** ~80 Python packages across web frameworks, CLI/devops,
  ML/scientific, XML/serialization, crypto/auth, HTTP, image/media, cloud
  SDKs. Configured in `src/generator/scraper/osv_scraper.py:46`
  (`TARGET_PACKAGES`).
- **Per-record schema:** 26 fields (schema 3.0) built in
  `src/utils/file_utils.py:621` (`build_meta()`). Trimmed 2026-05-22 from the
  previous 53-field 2.x schema after the user noted "I don't want more than 40."
  Drops removed redundant fields (the 8 per-CVSS-metric columns collapsed into
  `cvss_vector`; `cwe_name` and `vuln_type` derivable from `cwe`), filter-time-
  only signals with no downstream readers (`syntax_valid`, `has_taint_source`,
  `is_web_code`, `has_cwe_sink`, `loc_*`), and fields from removed pipeline
  phases (`classifier_cwe`, `classifier_confidence`). Literature justifications
  for all dropped fields preserved in `FIELD_JUSTIFICATION.md` appendix.
- **Documentation:** `DATASET_SCHEMA.md` + `FIELD_JUSTIFICATION.md`
  (literature citations for each field, per professor request).
- **Current dataset:** 871 samples in `data/raw/` — Django 252, Flask 136,
  FastAPI 29, aiohttp 12, Starlette 9, Tornado 5, Bottle 1, no-framework-tag
  (CLI/lib) 427.

### Phase 2 — Stratified split (`src/labeler/`, `scripts/run_phase2.py`)

**The big change:** professors rejected the original commit-message
classifier. Phase 2 is now just the stratified train/val/test split.

**What the split does** (`src/labeler/stratified_splitter.py`):
A Stratified-Group-Shuffle in three steps, with two correctness requirements
that drive the algorithm:

1. **Anti-leakage by repo.** Every sample from the same `repo` field lands in
   the same split. Without this, the model can memorize repo-specific
   conventions (decorator names, helper-function patterns) that appear in
   both train and test, inflating accuracy by 15–30 F1 points (the
   PrimeVul / DiverseVul finding from the literature). Samples with no
   `repo` (e.g., VUDENC functions) get their own group of size 1 — no
   leakage risk because there's nothing to leak.
2. **Stratification by CWE.** Each CWE appears in train/val/test in roughly
   the same proportion as the overall dataset. Without this, rare CWEs
   (CWE-22 has 15 samples) can land entirely in train, leaving test with
   zero — making per-class F1 undefined.

**Algorithm:** group by repo → compute each group's *dominant CWE* → shuffle
groups → greedy assignment to whichever split's per-CWE deficit is largest.
This beats `sklearn.StratifiedShuffleSplit` when group sizes vary widely
(some repos have 60+ samples, others have 1). Deterministic given a seed.

**Helpers:**
- `class_weights.py` — inverse-frequency weights for the trainer's
  cross-entropy loss (compensates for `safe` having 50% of samples).
- `cvss_targets.py` — generates per-sample CVSS regression targets for the
  Phase-3 dual-task model from NVD-enriched scores, with a fallback to the
  CWE-default in `configs/config.yaml` when NVD lookup fails.
- `data_prep.py` — tokenization + tensor packing for the GraphCodeBERT
  trainer.

**Output:** `data/phase2_split_report.json` — current totals 610 train /
127 val / 132 test, with the full per-CWE breakdown.

**Vestigial files (still on disk, unused):**
`src/labeler/commit_classifier.py` (TF-IDF + SVM) and
`src/labeler/distilbert_classifier.py` (DistilBERT fine-tune) — the dropped
classifiers. Kept in tree because git history is enough but the imports
are not wired up anywhere.

### Phase 2B — Benchmark-quality re-scope (multi-day arc)

Phase 2B is not a single step; it's the arc that turned the dataset from "all
Top-25 Python CWEs" into a **sink-shaped benchmark**. It runs across the
commit log from `0467fb2` (Day 1) to `4f53d6b` (audit v3) and the design is
captured in `PHASE_2B_DESIGN.md`, `PHASE_2B_RESCOPE_2026-05-13.md`, and three
audit reports (`BENCHMARK_AUDIT_REPORT_*.md`).

**Why a re-scope was needed:** the original 11–12 CWE label set was a mix of
*sink-shaped* CWEs (where a closed alphabet of fix patterns exists — e.g.,
"replace `%s` with parameterized query") and *structural* CWEs (where the
vulnerability is the *absence* of something — e.g., CWE-434 unrestricted
file upload). Sink patterns for structural CWEs were matching framework
source, imports, docstrings, and form field declarations — not actual
vulnerable handlers. The Stage-1 audit found CWE-434 had 0/7 audited
samples valid (100% FP rate).

**What Phase 2B did, step by step:**

1. **Centralized the CWE taxonomy** (`src/utils/cwe_taxonomy.py`, commit
   `0467fb2`). Replaced ad-hoc per-scraper sink patterns with a single
   source of truth: `CWE_VULN_MAP`, `BLOCKED_SOURCE_CWE`, sink regex per
   CWE. Added a `has_cwe_sink()` filter that runs at scrape time — any
   sample whose `code_before` doesn't contain a sink regex for its claimed
   CWE gets routed to `data/raw_rejected/` instead of `data/raw/`.
2. **Broadened the scrape sources** (`1d691c7`, `f3741a4`,
   `c741da7`). Expanded OSV target packages beyond web-only to surface
   advisories for non-web CWEs (798, 611, 330, 400, 77). Tightened CWE-798
   patterns. Added the `hardcoded_creds_miner.py` static miner.
3. **Per-CVE cap + stratified split** (`b2e2ca5`). Prevented a single CVE
   from dominating its CWE class (without a cap, one Django CVE produced
   60+ near-duplicate XSS samples from the same fix).
4. **Line-proximity filter for CWE-330/798** (`fdd9b9c`). For
   randomness/credentials CWEs, the sink alone isn't enough — added a
   filter requiring a "security context" token within N lines of the
   sink (`secret`, `password`, `token`, `key`).
5. **Iteratively narrowed the label set: 11 → 10 → 9 → 8.**
   - CWE-611 (XXE), CWE-330 (weak rand), CWE-400 (resource exhaustion) →
     dropped because they're not in MITRE Top-25.
   - CWE-77 (command injection parent of CWE-78) → merged into CWE-78
     in-place by `scripts/merge_cwe77_into_cwe78.py`.
   - CWE-434 (file upload) → dropped per the 100% FP rate audit.
   - CWE-798 (hardcoded credentials) → dropped 2026-05-13. Reasons:
     2-bucket fix alphabet (remove literal / move to vault); all samples
     came from one static miner, so the class was a single-source bias.
6. **Diff-based filter** (`0f847d1`, then audit v3 `4f53d6b`).
   This is the **biggest single quality win in the whole project.** Before:
   a sample passed if `code_before` contained a sink regex anywhere.
   After: the sink line must actually *change* between `code_before` and
   `code_after`. If the sink is identical in both versions, the fix is
   somewhere else and this isn't a real example of the CWE. **FP rate
   dropped from 51% → 26%** on the audit pack of 100 samples.
7. **Audit-driven cleanup** (`b1f6c23`). Dropped 34 false positives
   identified by hand audit; tightened 5 sink regexes.

**Final benchmark label set: 7 CWEs + `safe` = 8 labels.** The 7:
CWE-89, CWE-79, CWE-22, CWE-78, CWE-94, CWE-918, CWE-502. All
sink-shaped Top-25 Python CWEs.

**Phase 2B scripts:**
- `scripts/run_phase2b_configs.py` — orchestrates the full re-scope sweep.
- `scripts/refilter_by_diff.py` — applies the diff filter to existing data.
- `scripts/refilter_existing.py` — applies updated sink regexes.
- `scripts/build_audit_pack.py` — samples 100 records per CWE for the
  human audit cycle.
- `scripts/purge_bad_samples.py` — removes audit-rejected records.
- `scripts/scrape_rare_cwes.py`, `scripts/scrape_cwe434.py` — historical;
  CWE-434 scraping was rolled back.

### Phase 2.5 — Adversarial augmentation (`src/red_team/`)

Phase 2.5 is where the dataset gets two new things: a **robustness test set**
(same samples, mutated 5 different ways) and a pool of **hard negatives**
(superficially-vulnerable-looking code that has been sanitized — the model
must learn the fix pattern, not the sink keyword).

**Four mutators** (`src/red_team/mutators/`), each preserves semantics and
the CWE label:

1. **`dead_code.py` — Dead-code injection.** Inserts unreachable branches,
   unused variables, and no-op statements around the vulnerable site. Tests
   whether the detector reasons about reachability or just pattern-matches
   on tokens.
2. **`string_split.py` — String splitting.** Breaks string literals across
   concatenations and `.join()` calls: `"SELECT * FROM users"` →
   `"SELECT " + "* " + "FROM users"`. Tests whether the detector tracks
   string content through concatenation or only matches literal strings.
3. **`variable_rename.py` — Variable renaming.** Replaces meaningful names
   (`user_input`, `sql_query`) with neutral ones (`a`, `b`, `tmp`). Tests
   whether the detector relies on identifier semantics ("anything called
   `query` near `execute` is SQL injection") versus actual dataflow.
4. **`wrapper_extraction.py` — Wrapper extraction.** Pulls the vulnerable
   sink call into a helper function and calls it from the original site.
   Tests whether the detector tracks dataflow across function calls.

**One composed variant** — all four mutators applied in sequence. The
hardest of the lot.

**Sanitization rules** (`src/red_team/sanitization/rules/`) — one module per
CWE (1040 lines total across CWE-22/78/79/89/94/502/918). Each rule
implements a *fix pattern* drawn from real CVE fixes. Examples:
- `cwe89_sqli.py`: `percent_execute_to_parameterized`,
  `fstring_execute_to_parameterized`.
- `cwe79_xss.py`: `markup_to_escape`, `wrap_render_template_string_with_escape`.
- `cwe78_cmdi.py`: `shell_true_to_shell_false_with_list`.

Applying a sanitization rule to a vulnerable sample produces a **hard
negative** — same surface features (same imports, similar variable names,
same control flow), but the sink is no longer exploitable. The hard-negative
miner (`scripts/run_phase2_5_hardneg.py`) scans the dataset, finds samples
where an applicable rule exists, applies it, and writes the result back as
a new sample with `is_hard_negative: true` and a `parent_sample_id`
pointing to the original. Of 1553 samples scanned in the last run, 434
hard negatives were generated (`data/phase2_5_hardneg_report.json`).

**Augmenter** (`src/red_team/augmenter.py`) — orchestrates mutator chains
and ensures the output is still syntactically valid Python (AST check) and
still contains the original sink (regex check). Failures get logged and
the sample falls back to "clean."

**Materialized variants** (`scripts/build_mutator_variants.py`) — writes
the test split into `data/test_variants/{clean, dead_code_injection,
string_split, variable_rename, wrapper_extraction, composed}/` so the
evaluation harness can score each detector on all six versions of the test
set in one pass and report per-mutator F1 drops.

**Docs:** `PHASE2_5_AUGMENTATION_DESIGN.md`, `RED_TEAM_MUTATORS_GUIDE.md`.

### Phase 3 — Detection model (`src/model/`, `scripts/run_phase3_train.py`)

- **Architecture:** GraphCodeBERT dual-task — CWE classification head +
  CVSS score regression head, shared encoder. File:
  `graphcodebert_dualtask.py`.
- **Loss:** Weighted cross-entropy (CWE) + Huber loss (CVSS), summed with
  configurable α/β. Class weights from Phase 2 used here. File:
  `losses.py`.
- **Optimizer:** SAM (Sharpness-Aware Minimization). File: `sam_optimizer.py`.
- **Trainer:** Mixed-precision, gradient accumulation, per-mutator eval at
  end of each epoch. File: `trainer.py`.
- **Training bundle:** `sec_code_train_bundle.zip` prepared for Kaggle GPU
  (`KAGGLE_TRAINING.md`, `GPU_TRAINING_HANDOFF.md`). Not yet run.

### Phase 4 — Evaluation harness (`src/eval/`, `scripts/run_eval.py`)

The most recent area of focus. Three detector tiers per
`EVALUATION_TOOLS_SURVEY.md`:

- **Tier 1 — SAST:** Bandit + Semgrep (3-ruleset config). Both wired and
  run. Files: `src/eval/detectors/bandit.py`, `src/eval/detectors/semgrep.py`.
- **Tier 2 — LLM:** Anthropic detector built with offline cost dry-run;
  `.env` auto-loaded so no manual `ANTHROPIC_API_KEY` export. File:
  `src/eval/detectors/llm.py`. **Not yet run live.**
- **Tier 3 — Specialized / neuro-symbolic:** surveyed (CodeQL, IRIS,
  Kolega.Dev), not yet integrated.

**Scoring:** `src/eval/scoring.py` computes macro-F1, per-CWE F1, and a
robustness-drop metric (clean-F1 minus per-mutator-F1).

**CWE mapping:** `src/eval/cwe_map.py` maps Bandit IDs (e.g., `B608` → CWE-89)
and Semgrep rule IDs to the benchmark's 7-CWE label set.

**Baseline results** (`reports/eval/`):
- Bandit macro-F1 (clean): **0.49**. Strong on CWE-89/94/502; zero on
  CWE-22 and CWE-918.
- Semgrep macro-F1 (clean): **0.32**. Same blind spots.
- Robustness drop under mutators: near-zero for both
  (~0.001–0.009 mean drop). Expected for rule matchers — they ignore
  most of the program, so trivial rewrites don't move them. The
  interesting deltas will come from the LLM and trained-model runs.

### Phase 5 — (vestigial)

In the original seven-phase plan, Phase 5 was "Train vulnerability detection
models" under `src/ml/`. That training step was renumbered to **Phase 3**
when Phases 2 and 3 of the original plan (CVE attribution + CVSS gradient
mapping) collapsed into the single stratified split. `src/ml/` still exists
on disk but contains only an empty `__init__.py` — it's a leftover from the
original numbering, not an active phase. The phase numbers are kept
non-contiguous (1, 2, 2B, 2.5, 3, 4, 6, 7) rather than renumbered so commit
history and progress reports remain coherent.

### Phases 6–7 — Red team & feedback loop

Mutators exist; full red-team engine and feedback loop are still skeletons
(`src/redteam/`, `src/feedback/`). The intended distinction from Phase 2.5:
Phase 2.5 mutates *code* to attack detectors at the syntactic level; Phase 6
would generate *exploits* — concrete inputs that demonstrate the
vulnerability — against detectors' verdicts, and Phase 7 would feed exploit
outcomes back into retraining the Phase-3 model.

### Paper (`paper/main.tex`, `paper/sections/`)

Drafted: abstract, intro, dataset, methodology (4 adversarial mutators),
related-work (incl. vulnerability-detection benchmarks subsection),
evaluation rewritten around the benchmark framing, threats, conclusion.

### Testing

354 tests across `tests/red_team/`, `tests/model/`, `tests/labeler/`.

---

## How we got here — the design changes that actually mattered

1. **Phase 2 classifier removed** — professors didn't want commit-message
   classification.
2. **Schema trimmed twice:** 48 → 53 (Phase 2.5 fields were added, classifier fields were never actually removed) → 26 (schema 3.0, 2026-05-22 trim, with the field-tiering structure for the paper). Each retained field literature-justified; removed fields preserved in appendix for traceability.
3. **Scope broadened from Flask-only to all Python web frameworks +
   adjacent ecosystems** — the README was stale for a while; corrected
   2026-05-22.
4. **Re-scoped to sink-shaped CWEs** — better signal-to-noise than chasing
   the full Top-25. CWE-434 (structural) failed audit at 100% FP rate.
5. **Diff filter** (require the sink line to be the one that changed) —
   biggest single quality win, halved FP rate (51% → 26%).
6. **Benchmark framing** — the project is now a benchmark paper
   (PyVulSev) rather than a "build a detector" paper, which is what the
   rewritten evaluation section reflects.
7. **Three-tier evaluation** — SAST + LLM + specialized, driven by
   `EVALUATION_TOOLS_SURVEY.md`'s read of RealVuln/CASTLE/IRIS.

---

## What we can do next

**Short term (close out the eval section):**
- Actually run the Anthropic LLM detector (cost dry-run done; real run is
  one command).
- Add a second LLM (GPT or Gemini) so the LLM tier isn't a single-model
  claim.
- Train and evaluate the GraphCodeBERT model on Kaggle — the bundle is
  ready.
- Fix the CWE-22 / CWE-918 zero-F1 holes — almost certainly missing or
  mismapped rules in `src/eval/cwe_map.py`, not a real "tools can't detect
  these" finding.

**Medium term (paper-ready):**
- Add a tier-3 detector (CodeQL or IRIS-style LLM+CodeQL) so all three
  tiers are represented — currently the most likely reviewer objection.
- Re-run mutator robustness on the LLM and trained-model tiers — that's
  where mutators are *supposed* to bite. SAST being flat is expected and
  not interesting on its own.
- Tighten the audit: the 26% FP rate after the diff filter is still high
  for a benchmark paper.
- Broaden NVD-targeted CVE queries to surface more FastAPI / Starlette /
  Tornado fixes — Django and Flask dominate the current framework
  distribution.

**Longer term (Phases 6–7, currently stubs):**
- Wire up the autonomous red-team engine (`src/redteam/`) — generate
  exploits against detector verdicts, not just code mutations.
- Feedback loop (`src/feedback/`) — exploit outcomes feeding back into
  retraining the Phase-3 model.
- Sandboxed exploit execution (`docker/` is scaffolded, unused).

The realistic path to a submittable paper is: finish the LLM run, fix the
CWE-22/918 mapping bug, add one tier-3 detector, then write up.
Phases 6–7 are a follow-up paper, not blockers.
