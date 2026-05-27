# PyVulSev — A Python Vulnerability-Severity Benchmark and Detection Pipeline

## Project Overview

PyVulSev is a research benchmark and end-to-end pipeline for vulnerability
detection on **Python code** — primarily Python web frameworks (Flask,
Django, FastAPI, aiohttp, Tornado, Bottle, Quart, Starlette), with
additional coverage of CLI/devops, ML/scientific, XML/serialization,
crypto/auth, HTTP-client and cloud-SDK packages where the target CWEs
appear.

The pipeline scrapes real-world vulnerability fixes from public sources,
labels and splits them into a benchmark, generates adversarial variants
for robustness testing, trains a detection model, and evaluates SAST
tools, LLMs, and the trained model against the benchmark.

## Target CWEs (sink-shaped Top-25 Python)

- **CWE-89** — SQL injection
- **CWE-79** — Cross-site scripting (XSS)
- **CWE-22** — Path traversal
- **CWE-78** — OS command injection
- **CWE-94** — Code injection (`eval` / dynamic import)
- **CWE-918** — Server-side request forgery (SSRF)
- **CWE-502** — Insecure deserialization

The benchmark uses **8 labels**: the 7 CWEs above + `safe`. CWE-798
(hardcoded credentials) was scraped during Phase 2B but dropped from
the active label set on 2026-05-13 — single-source bias from one
static miner and a 2-bucket fix alphabet.

## Pipeline phases

| Phase | Module | Description |
|-------|--------|-------------|
| 1 | `src/generator` | Scrape Python vulnerability fixes from CVEfixes, OSV, GHSA, PyPA, NVD |
| 2 | `src/labeler` | Stratified train/val/test split (commit classifier removed per project revision) |
| 2B | `src/generator/scraper` | Sink-presence filter, diff filter, hardcoded-creds miner |
| 2.5 | `src/red_team` | Adversarial mutators + sanitization rules + hard-negative miner |
| 3 | `src/model` | GraphCodeBERT dual-task model (CWE classification + CVSS regression) |
| 4 | `src/eval` | Evaluation harness — Bandit, Semgrep, LLM detector |
| 6 | `src/redteam` | Autonomous red-team simulation (skeleton) |
| 7 | `src/feedback` | Feedback loop: exploit results → retraining (skeleton) |

## Data sources

Scraped from:
- **CVEfixes** — academic CVE-fix dataset
- **OSV.dev** — Google's Open Source Vulnerability database
- **GHSA** (GitHub Security Advisories) and the `ghsa_db` mirror
- **PyPA Advisory DB** — Python Packaging Authority advisories
- **NVD** — targeted scrape via CVE → repo → commit
- **VUDENC** — vulnerability-detection dataset (additional Python coverage)
- **Canonical examples** — hand-written reference samples per CWE
- **Hard-negative mining** — derived from each of the above (`hardneg_*`)

## Current dataset snapshot

`data/raw/` holds **871 samples** (split 70/15/15 → 607 train / 127 val / 132 test after content-hash deduplication; 5-sample gap from the raw 871 is recorded in the dataset paper).

**By framework (when detectable):**

| Framework | Samples |
|-----------|---------|
| Django    | 252 |
| Flask     | 136 |
| FastAPI   | 29  |
| aiohttp   | 12  |
| Starlette | 9   |
| Tornado   | 5   |
| Bottle    | 1   |
| (no framework tag — CLI/lib/utility code) | 427 |

**By CWE:**

| Label   | Samples |
|---------|---------|
| safe    | 429 |
| CWE-89  | 212 |
| CWE-502 | 78  |
| CWE-79  | 54  |
| CWE-94  | 36  |
| CWE-78  | 25  |
| CWE-918 | 22  |
| CWE-22  | 15  |

Adversarial test variants for robustness evaluation live in
`data/test_variants/{clean,dead_code_injection,string_split,variable_rename,wrapper_extraction,sink_attr_obfuscate,sink_via_globals,taint_through_dict,composed}/`.
The seven single mutators fall into three families:

- **Sink-preserving** (DC, SS, VR, WE): modify code around the sink, leave the sink token intact.
- **Sink-targeted** (SAO, SVG): rewrite the sink call itself via `getattr` indirection or `__dict__` indexing on the builtins module.
- **Dataflow** (TTD): route the sink's first argument through a one-entry dict subscript.

## Directory layout

```
sec_code/
├── data/
│   ├── raw/             # Scraped + canonical + hard-negative samples (.py + .meta.json)
│   ├── test_variants/   # Mutator-augmented test set for robustness eval
│   ├── cvefixes/        # CVEfixes mirror
│   ├── github_advisory_db/ pypa_advisory_db/   # Source mirrors
│   └── raw_rejected/    # Samples that failed sink-presence / diff filters
├── src/
│   ├── generator/       # Phase 1: scrapers (osv, ghsa, cvefixes, nvd, hardcoded_creds_miner)
│   ├── labeler/         # Phase 2: stratified splitter, class weights, CVSS targets
│   ├── red_team/        # Phase 2.5: mutators + sanitization rules + hard-neg miner
│   ├── model/           # Phase 3: GraphCodeBERT dual-task, losses, SAM optimizer, trainer
│   ├── eval/            # Phase 4: detectors (bandit, semgrep, graphcodebert, llm), scoring, cwe_map
│   ├── redteam/         # Phase 6: red-team engine (skeleton)
│   ├── feedback/        # Phase 7: feedback loop (skeleton)
│   └── utils/           # Schema, CWE taxonomy, logging
├── configs/             # Pipeline + augmentation + class-weight configs
├── paper/               # LaTeX source for the benchmark paper
├── reports/eval/        # Detector predictions and per-CWE/per-mutator F1
├── runs/                # Phase-3 training run artifacts
├── scripts/             # CLI entry points (run_phase2, run_phase2_5_hardneg, run_phase3_train, run_eval, …)
└── tests/               # 354 pytest tests across red_team, model, labeler
```

## Quick start

```bash
pip install -r requirements.txt

# Phase 1: scrape (requires GITHUB_TOKEN in .env)
python scripts/run_generator.py

# Phase 2: stratified train/val/test split
python scripts/run_phase2.py

# Phase 2.5: build hard-negatives + materialize mutator variants
python scripts/run_phase2_5_hardneg.py
python scripts/build_mutator_variants.py --apply

# Phase 3: train GraphCodeBERT dual-task model
python scripts/run_phase3_train.py

# Phase 4: evaluate detectors on the benchmark
#   --tool all runs Bandit + Semgrep + GraphCodeBERT (free local detectors)
#   --tool claude runs the Anthropic LLM detector (requires ANTHROPIC_API_KEY)
python scripts/run_eval.py --tool all
```

The eval harness writes `reports/eval/{tool}_predictions.jsonl` and
`reports/eval/{tool}_summary.json` per detector. Summaries include
macro-F1, detection MCC, severity-weighted recall, hierarchical CWE
macro-accuracy (HCMA, Wu–Palmer over a hand-coded subtree of MITRE
CWE 4.14), and weighted Cohen's κ, computed per variant.

## Notes

- Scope was deliberately broadened from Flask-only to all Python web
  frameworks (and adjacent ecosystems where the target CWEs occur) per
  project revision; see `src/generator/scraper/osv_scraper.py`.
- The commit-message classifier was removed from Phase 2 per supervisor
  feedback; Phase 2 is now the stratified split alone.
- Dataset schema is 26 fields (schema 3.0, 2026-05-22), trimmed from
  the previous 53-field schema by removing derivable, filter-time-only,
  and removed-phase-tied fields. Per-field literature justification in
  `docs/reference/FIELD_JUSTIFICATION.md`; "removed in 3.0" appendix lists each drop.
- The evaluation methodology is documented at three levels of detail:
  `docs/reference/EVALUATION_GUIDE.md` (plain-language for project use),
  `docs/reference/EVALUATION_METHODOLOGY.md` (formal spec, paper-aligned),
  `docs/reference/EVALUATION_TOOLS_SURVEY.md` (the broader tool landscape, most of
  which we did not select).
