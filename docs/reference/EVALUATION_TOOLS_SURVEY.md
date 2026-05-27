# Evaluation Tools Survey: Detectors for the PyVulSev Benchmark

**Compiled:** 2026-05-18. **Scope:** SAST tools, LLMs, specialized ML
models, and AI-augmented/agentic security tools that can be run as
*detectors* against the PyVulSev benchmark.

This document grounds the tool-selection decision for the evaluation
section of the paper. The benchmark scores detectors on **7 sink-shaped
CWE classes** in Python web code (CWE-89 SQL injection, CWE-79 XSS,
CWE-22 path traversal, CWE-78 OS command injection, CWE-94 code
injection, CWE-918 SSRF, CWE-502 insecure deserialization) by scanning
individual `.py` files and mapping findings to CWEs. Two SAST tools
(Bandit, Semgrep) are already integrated and run; an Anthropic LLM
detector is built but not yet run.

All findings are from web research conducted May 2026. Model versions
and prices move fast, so **verify current model IDs and pricing before
any paid run.**

## 1. The landscape: three detector tiers

Every 2025-2026 evaluation (RealVuln, CASTLE, IRIS, LLM-vs-SAST) reaches
the same shape: detectors split into three tiers with a consistent
performance ordering on *real-world* code.

| Tier | What it is | Real-world recall | False positives | Robustness to code rewrites |
|---|---|---|---|---|
| **1. Rule-based SAST** | Bandit, Semgrep, CodeQL, Snyk, SonarQube | Low (~13% on real vulns) | Very high (often >90%) | High; invariant, because it ignores most of the program |
| **2. General-purpose LLMs** | Claude, GPT, Gemini, DeepSeek, Qwen | Moderate, best out-of-the-box | Moderate; closed models over-flag | **Low**; trivial code rewrites flip verdicts |
| **3. Neuro-symbolic / specialized** | IRIS (LLM+CodeQL), security-tuned scanners, fine-tuned code models | Highest on real-world code | Tunable | Varies |

The headline benchmark numbers (RealVuln, April 2026, the closest prior
art to PyVulSev, also Python, also tiered):

- Security-specialized **Kolega.Dev**: F3 = 73.0 (recall 0.81)
- Best general LLM **Claude Sonnet 4.6**: F3 = 51.7 (recall 0.50)
- Best rule-based SAST **Semgrep**: F3 = 17.7, about **3x lower** than
  the best LLM.

The practical implication for PyVulSev: a credible 2026 paper is
expected to evaluate **all three tiers**. Evaluating only SAST tools (or
only LLMs) is the most likely reviewer objection.

## 2. Tier 1: Static analysis (SAST) tools

The fundamental split inside this tier decides how well a tool can do
on the 7 target CWEs.

**Pattern / AST matchers** (Bandit, Dlint, pylint plugins) flag the
*sink* (`eval()`, `pickle.loads()`, `subprocess(shell=True)`) without
proving the input is attacker-controlled. They catch CWE-94, CWE-78,
CWE-502 reasonably (the sink is a fixed API call) but are structurally
weak on CWE-89/79/22/918, where danger depends on whether a *string*
is tainted.

**Taint / dataflow engines** (CodeQL, Semgrep Pro/Opengrep, Pysa,
Snyk Code, paid SonarQube) trace source to sink and handle all 7
classes far better, at the cost of needing whole-project context,
which complicates single-file scanning.

### 2.1 Recommended / harness-ready

| Tool | License | Technique | 7-CWE coverage | Output | Cost | Harness fit |
|---|---|---|---|---|---|---|
| **Bandit** | Apache-2.0 | AST pattern | Strong on 78/94/502; weak on 89/79/22/918 | JSON, SARIF | Free | ★★★★★ already integrated |
| **Semgrep CE** | LGPL-2.1 | Pattern + intraproc taint | All 7 via rulesets | JSON, SARIF | Free | ★★★★★ already integrated |
| **Opengrep** | LGPL-2.1 | Pattern + **interproc** taint | All 7 | JSON, SARIF | Free | ★★★★☆ free cross-function taint; drop-in for Semgrep |
| **CodeQL CLI** | Free for OSS/research | Interprocedural taint/dataflow | All 7 (dedicated, well-maintained queries) | SARIF | Free (research) | ★★★☆☆ needs a DB per project; best precision |
| **Snyk Code** | Commercial | ML + symbolic dataflow | All 7 | SARIF, JSON | Free tier (~100 tests/mo) | ★★★★☆ `snyk code test --sarif`; watch quota |
| **Bearer** (Cycode) | Elastic License 2.0 | Static dataflow | Most of the 7 | JSON, SARIF | Free CLI | ★★★★☆ `bearer scan`; verify SSRF/path depth |
| **datadog-static-analyzer** | Open source | Static analysis | Injection CWEs | SARIF | Free CLI | ★★★☆☆ scriptable; AI triage is cloud-only |

### 2.2 Heavyweight or poor single-file fit

| Tool | Why it is awkward |
|---|---|
| **Meta Pysa/Pyre** | Whole-project, config-heavy (needs models per framework, and only Django/SQLite3 ship pre-built); JSON output with **no native SARIF/CWE mapping**. |
| **SonarQube** | Server-centric; taint analysis is **paid only** (Developer Edition and up), so free Community Edition cannot do injection dataflow. |
| **GitHub Advanced Security** | CI/cloud product wrapping CodeQL; for a harness just use the CodeQL CLI directly. Split April 2025 into Code Security ($30/committer/mo) plus Secret Protection. |
| **DeepSource** | VCS/PR-integrated, not ad-hoc file scanning. ~$24/user/mo. |
| **Checkmarx / Fortify / Veracode** | Enterprise; quote-based licensing; Veracode analyzes *binaries* (upload model). Project-scale tools, impractical per-file. |

### 2.3 Exclude

- **Amazon CodeGuru Security**: **discontinued Nov 20, 2025.** Folded
  into Amazon Q Developer (IDE-centric, poor harness fit).
- **PyT (Python Taint)**: abandoned; chokes on modern Python.
- **Horusec**: platform archived March 2025; for Python it just wraps
  Bandit + Semgrep, so it adds nothing.
- **Dlint, pylint security plugins**: sink-only, no CWE tags, no SARIF;
  marginal next to Bandit.

### 2.4 The SAST reality check (cite in the paper)

- **Ghost Security, 2025**: scanned ~3,000 OSS repos and found **>91% of
  flagged vulnerabilities were false positives.** Python/Flask command
  injection (CWE-78) was the worst case at a **99.5% FP rate** (1,166
  flagged, 6 real).
- **Repo-level study (arXiv 2407.16235)**: SAST detects only **~12.7%**
  of real-world vulnerabilities; on benign code **CodeQL flagged 68.2%**
  and **Semgrep 74.8%** as positive.

This is *why* PyVulSev's sink-validated labels and the macro-F1 metric
matter, and why the SAST rows are a floor, not a target.

## 3. Tier 2: General-purpose LLMs as detectors

This is the tier where PyVulSev's task design (single small Python file,
2-7K tokens, 7-class + safe) plays to LLM strengths. CASTLE shows LLMs
do best exactly in this small-snippet regime.

**Integration note:** the harness's `LLMDetector` currently uses the
Anthropic SDK only. Evaluating OpenAI / Gemini / open-weight models means
adding a provider backend per family (each is a thin subprocess/SDK
wrapper around the same prompt + parse logic).

### 3.1 Current models, pricing, and fit

Prices are USD per 1M tokens (input / output), as found May 2026, so
**verify before spending.** "Full run" means the 467-call PyVulSev pass.

| Family | Model to use | Context | Price in/out | Full-run cost | Notes |
|---|---|---|---|---|---|
| **Anthropic Claude** | Opus 4.7 | 1M | $5 / $25 | ~$9-18 | Strongest agentic-coding frontier model; best on SecVulEval. Harness-native. |
| | Sonnet 4.6 | 1M | $3 / $15 | ~$5-11 | Best general LLM in RealVuln (F3 51.7). |
| | Haiku 4.5 | 200K | $1 / $5 | ~$1.8-3.5 | Cheapest Claude; no extended thinking. |
| **OpenAI** | GPT-5-class / o-series | 200K-1M | ~$1.25-5 / $8-30 | ~$5-25 | `reasoning_effort` knob; o-series strong on FP reduction (IRIS). |
| **Google Gemini** | 3 Pro / 3 Flash | 1M | Flash ~$0.50 / $3 | ~$2-20 | Gemini 3 Flash topped a 2026 vuln-FP leaderboard; Flash is cheap and capable. |
| **DeepSeek** | V3 / R1 | 128K | ~$0.14-0.55 / $0.28-2.19 | ~$0.4-5 | Open-weight; R1 reasoning very cheap; self-hostable for reproducibility. |
| **Alibaba Qwen** | Qwen3-Coder | 256K-1M | ~$0.11-0.65 / $0.80-3.25 | ~$0.5-3 | Strongest open-weight *code* family; open weights. |
| **Meta Llama** | Llama 4 Maverick | 1M | ~$0.2-1 / $0.6-1.5 (host-dep.) | ~$1-4 | Open weights; reference for Meta CyberSecEval. |
| **Mistral** | Codestral | 256K | ~$0.30 / $0.90 | ~$1 | Cheap code specialist baseline. |
| **xAI Grok** | Grok 4.x | 256K-2M | ~$0.20-3 / $0.50-15 | ~$1-10 | No notable vuln-detection track record. |

### 3.2 Cost levers (important, the project is cost-constrained)

- **Prompt caching:** PyVulSev's system prompt is fixed; the cacheable
  prefix is ~90% cheaper on a hit. (Note: on Opus 4.7 the prompt must
  exceed 4096 tokens to cache at all, and currently it does not.)
- **Batch APIs:** 50% off on Anthropic, OpenAI, Google. Latency is
  irrelevant for an offline benchmark. Caching plus batch can roughly
  halve a full sweep.
- **Cheap-tier substitution:** a full sweep of Haiku 4.5 + Gemini 3
  Flash + DeepSeek + Qwen costs **under $10 combined**. Open-weight
  models (DeepSeek, Qwen, Llama) can also be self-hosted on a GPU for
  near-zero marginal cost and full reproducibility.

### 3.3 What the LLM-detection literature concludes

- **SecLLMHolmes** (IEEE S&P 2024): no LLM reached satisfactory
  performance; verdicts are **non-deterministic** and **flip under
  trivial semantics-preserving edits** (renaming, dead code). This is
  the closest prior art to PyVulSev's mutators; its augmentation
  taxonomy is directly reusable. Best prompt: a security-expert *role*
  prompt ("R2").
- **PrimeVul** (ICSE 2025): benchmarks overestimate badly. A model at
  68% F1 on BigVul scored **3.09%** on PrimeVul. LLMs are near-random at
  telling a vulnerability from its patch.
- **CASTLE** (2025): LLMs win on small snippets (GPT-o3-mini topped all
  tools), accuracy collapses on larger code.
- **SecVulEval**: best model (Claude 3.7 Sonnet) only 23.83% F1; closed
  models **over-flag** (high recall, low precision).
- **Multi-language study (arXiv 2503.01449)**: Python shows severe
  *under-counting* (recall <0.30 on complex files); in-context-learning
  prompting lifts Python F1 by 4-68%.

**Failure modes to expect and measure:** over-flagging, recall collapse
on complex/multi-vuln files, non-determinism, *unfaithful reasoning*
(right label, wrong justification, 36% of correct verdicts in one 2026
study), and sensitivity to trivial perturbations.

## 4. Tier 3: Specialized ML models and neuro-symbolic systems

### 4.1 The honest constraint

Almost every classic specialized detector (**VulBERTa, LineVul,
Devign, ReVeal, VulDeePecker, SySeVR, White-Basilisk**) was trained and
evaluated **only on C/C++.** Running them on Python is out-of-distribution
and not defensible as a fair evaluation. They belong in *related work*,
not in the results table.

### 4.2 Usable on Python: fine-tune yourself

These are general code encoders with no built-in vulnerability
knowledge; you add a head and fine-tune on Python vuln data.

| Model | Params | Notes |
|---|---|---|
| **GraphCodeBERT** | 125M | Data-flow-aware. **PyVulSev already has a dual-task GraphCodeBERT model built (Phase 3)**, the natural Tier-3 entry: the project's own trained detector becomes one row in the table. |
| **UniXcoder** | 125M | Best published *multilingual* fine-tuning results (incl. Python on CVEFixes); strong alternative. |
| **CodeT5+ (`codet5p-770m-py`)** | 770M | Python-specialized checkpoint; encoder-decoder, can do generative CWE labeling. |
| **CodeBERT** | 125M | Baseline encoder; 512-token limit. |

512-token limits mean function-level rather than file-level scanning, a
granularity decision to state explicitly.

### 4.3 Python-targeted specialized models (cite; benchmark only if a checkpoint is public)

- **SecureQwen** (Computers & Security 2024): decoder-only, 64K context,
  built for Python, 14-CWE multi-class. Strong candidate **if** a
  checkpoint is released.
- **DetectVul**: statement-level Python detection.
- **VulnLLM-R** (arXiv 2512.07533): open 7B reasoning model plus an agent
  scaffold; claims to beat CodeQL. Open weights, GPU-runnable.
- **Fine-tuned SLM for Python CWEs** (arXiv 2504.16584): 350M model
  fine-tuned on 500 examples to detect MITRE Top-25 CWEs in Python;
  proof that a small Python-specific multi-class detector is feasible.

### 4.4 Neuro-symbolic: the current real-world SOTA

**IRIS** (ICLR 2025) pairs an LLM with CodeQL. IRIS+GPT-4 found **55**
vulnerabilities versus CodeQL's **27** on CWE-Bench-Java, and *improved*
CodeQL's false-discovery rate. The consensus direction is hybrid
LLM-plus-static-analysis, not either alone. Including at least one
hybrid/specialized system is the strongest way to pre-empt reviewer
objections.

## 5. AI-augmented and agentic security tools

Mostly **cite-for-the-trend**, not benchmarkable in an automated harness.

| Tool | Status for the harness |
|---|---|
| **Semgrep Assistant** | Detection is the OSS engine (already used); the AI layer is triage/fix, cloud-bound. |
| **Snyk Agent Fix / DeepCode AI** | Snyk Code CLI is scriptable (Tier 1); the agent layer is remediation. |
| **GitHub Copilot Autofix** | Remediation only; CodeQL does the detection. |
| **Anthropic `claude-code-security-review`** | Open-source GitHub Action; **adaptable**, the prompt/harness can be repurposed for batch file scanning. A usable "LLM agent" baseline. |
| **OpenAI Aardvark / "Codex Security"** | Enterprise-gated, repo-oriented; not a per-file API. Cite only. |
| **Corgea (BLAST), Aikido, Endor Labs, Amazon Q Developer** | Paid cloud products; not independently reproducible. Cite for the trend. |

## 6. What a 2026 benchmark is expected to do (methodology)

Drawn from PrimeVul, CASTLE, SecLLMHolmes, RealVuln, SecCodePLT,
SV-TrustEval-C:

1. **Evaluate all three tiers**: SAST, LLMs, and at least one
   hybrid/specialized system.
2. **Report at a constrained low false-positive rate**, not just F1
   (PrimeVul's VD-S is the false-negative rate at 0.5% FPR).
3. **Include false-positive traps**, safe-but-suspicious code (PyVulSev
   already has 65 hard negatives, aligned).
4. **De-duplicate and split to prevent leakage** (PyVulSev already does
   repo-grouped splitting, aligned).
5. **Run each detector at least 3 times and report variance.** LLMs are
   non-deterministic; this is a citable, expected finding.
6. **Pair-wise evaluation** on vulnerable/patched pairs, which tests
   whether a detector tracks security logic versus surface patterns.
7. **Ground the adversarial mutators** in SecLLMHolmes / SV-TrustEval-C /
   SecCodePLT / TrapEval, and **validate semantics preservation** of
   each mutant (PyVulSev does AST-level checks, aligned).
8. **Manually vet labels.** Automatic CVE labeling carries 40-75% noise
   (CleanVul); PyVulSev's diff-filter plus audit (26% FP) is the answer
   to this and should be foregrounded.

**Closest prior art:** **RealVuln** (arXiv 2604.13764, April 2026) is
also Python, also three-tier, also robustness-aware. PyVulSev should
cite it as both a model and a point of differentiation (PyVulSev adds
sink-validated labels, the four targeted mutators, and per-CWE
robustness-drop diagnosis).

## 7. Recommended evaluation slate for PyVulSev

Sequenced **cheapest-first**, so the benchmark can grow as budget allows.
The cost-free stages produce a complete, publishable three-tier table on
their own.

### Stage A: free, do now (no API spend)

| Detector | Tier | Status |
|---|---|---|
| Bandit | 1 | done, macro-F1 0.49 |
| Semgrep (3 rulesets) | 1 | done, macro-F1 0.32 |
| **CodeQL CLI** | 1 | Add; free for research; strongest pure SAST; needs DB-per-project harness work |
| **PyVulSev's own GraphCodeBERT model** | 3 | Already built (Phase 3); train it and run it as one row, the project's neuro-symbolic/specialized entry |
| **Opengrep** | 1 | Optional; free interprocedural taint; shows the taint-vs-pattern gap |

### Stage B: cheap LLM rows (under ~$10 total)

Add an open-weight / cheap-tier LLM sweep. Each is a new provider
backend in the harness but small.

| Detector | Full-run cost | Why |
|---|---|---|
| **Claude Haiku 4.5** | ~$2-3 | Harness-native already; cheapest Claude |
| **Gemini 3 Flash** | ~$2-3 | Topped a 2026 vuln-FP leaderboard; cheap |
| **DeepSeek V3/R1** | ~$0.5-5 | Open-weight; R1 isolates the reasoning effect |
| **Qwen3-Coder** | ~$0.5-3 | Strongest open-weight code family |

### Stage C: frontier LLM rows (when budget allows, ~$30-80 batched)

| Detector | Full-run cost | Why |
|---|---|---|
| **Claude Opus 4.7** | ~$9-18 | Frontier; named in the methodology; harness-native |
| **OpenAI GPT-5-class** | ~$5-25 | CASTLE's top performer was an OpenAI reasoning model |
| **Google Gemini 3 Pro** | ~$8-20 | Vendor diversity; frontier |

### Stage D: optional differentiators

- One **commercial SAST** (Snyk Code free tier, or Bearer), for breadth.
- A **hybrid LLM+SAST** row (IRIS-style: feed CodeQL findings to an LLM
  triage pass), which represents current real-world SOTA and pre-empts
  the "no specialized tier" objection.

### Minimum defensible table

Bandit + Semgrep + CodeQL (Tier 1), the project's GraphCodeBERT model
(Tier 3), and Claude Opus 4.7 + one OpenAI + one Gemini model (Tier 2).
Stages A and B alone already deliver this for **under $10**.

## 8. Harness work implied by this slate

| Item | Effort |
|---|---|
| CodeQL runner (`src/eval/detectors/codeql.py`) | Medium; build a DB per sample/project, parse SARIF; the deferred item in the methodology |
| Multi-provider LLM backends (OpenAI, Gemini, open-weight via OpenRouter/Together) | Small each; the prompt and parser are shared, only the API call differs |
| Wire the GraphCodeBERT model into `src/eval` as a `Detector` | Small; it already outputs CWE logits, so wrap `predict` |
| Batch-API support for the LLM detector (50% discount) | Medium; worth it before any frontier run |
| Repeated runs (3 or more) plus variance reporting | Small; a loop and stdev in `scoring.py` |

## 9. Sources

**Benchmarks and papers**
- CASTLE: arXiv:2503.09433
- SecLLMHolmes: arXiv:2312.12575 (IEEE S&P 2024)
- PrimeVul: arXiv:2403.18624 (ICSE 2025)
- SVEN: arXiv:2302.05319 (CCS 2023)
- CyberSecEval 1/2/3: arXiv:2312.04724, 2404.13161, 2408.01605
- SecVulEval: arXiv:2505.19828
- DiverseVul: arXiv:2304.00409. CVEfixes: PROMISE '21
- CWE-Bench-Java / IRIS: arXiv:2405.17238 (ICLR 2025)
- Steenhoek DL study: arXiv:2212.08109. LLM study: arXiv:2403.17218
- SecCodePLT: arXiv:2410.11096. SV-TrustEval-C: arXiv:2505.20630
- CleanVul: arXiv:2411.17274. TrapEval: arXiv:2601.22655
- RealVuln: arXiv:2604.13764 (closest prior art)
- Multi-language LLM vuln detection: arXiv:2503.01449
- Fine-tuned SLM for Python CWEs: arXiv:2504.16584

**Tools and models**
- Bandit: github.com/PyCQA/bandit
- Semgrep: semgrep.dev. Opengrep: github.com/opengrep/opengrep
- CodeQL: codeql.github.com/codeql-query-help/python-cwe
- Pysa/Pyre: pyre-check.org. Snyk Code: snyk.io/platform/deepcode-ai
- Bearer: github.com/Bearer/bearer
- Anthropic pricing: platform.claude.com/docs/en/about-claude/pricing
- OpenAI: openai.com/api/pricing. Gemini: ai.google.dev/gemini-api/docs/pricing
- DeepSeek: api-docs.deepseek.com. Qwen / Llama / Mistral: vendor docs
- HuggingFace: microsoft/graphcodebert-base, microsoft/unixcoder-base,
  Salesforce/codet5p-770m-py
- IRIS: github.com/iris-sast/iris
- VulnLLM-R: github.com/ucsb-mlsec/VulnLLM-R
- anthropics/claude-code-security-review

*Model versions and pricing in section 3 reflect May 2026 web research
and should be re-verified before any paid run.*
