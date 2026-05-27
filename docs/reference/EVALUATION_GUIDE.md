# Evaluation Guide

**For:** quick reference when working on the evaluation harness.
**Last updated:** 2026-05-22.
**Sibling docs:** [`EVALUATION_METHODOLOGY.md`](EVALUATION_METHODOLOGY.md) (formal, paper-aligned), [`EVALUATION_TOOLS_SURVEY.md`](EVALUATION_TOOLS_SURVEY.md) (landscape of every tool we considered, most of which we did not pick).

This guide covers only the tools and metrics we are actually running. Plain language; no jargon without an explanation in the same paragraph.

---

## 1. What the evaluation does, in one paragraph

We have a benchmark of 132 Python files. Each file is either a real vulnerable function (67 of them, spread across seven CWE classes) or a "safe" function that looks similar but is not vulnerable (65 of them, used as hard negatives). We feed each file to a detector (a security tool or an AI model). The detector returns a verdict: "this file is CWE-X" or "this file is safe." We compare the verdict to the ground truth and score the detector. Then we **rewrite** each vulnerable file in seven different ways that **do not change what the code actually does** — only what the code looks like. We re-run the detector on the rewritten files and see how much its accuracy drops. The drop tells us whether the detector understood the security flaw or was just matching surface patterns.

---

## 2. The seven CWE classes we cover

| CWE | Name | Plain-language example |
| --- | ---- | ---------------------- |
| CWE-22  | Path traversal | User input ends up inside `open()` and lets the attacker escape the intended directory with `../`. |
| CWE-78  | OS command injection | User input is passed to `os.system()` or `subprocess.run(..., shell=True)` so the attacker can chain shell commands. |
| CWE-79  | Cross-site scripting (XSS) | User input is rendered into HTML without escaping, so the attacker can inject `<script>` tags. |
| CWE-89  | SQL injection | User input is concatenated into a SQL query string instead of being passed as a parameter. |
| CWE-94  | Code injection | User input ends up inside `eval()`, `exec()`, or `compile()` and is executed as Python. |
| CWE-502 | Insecure deserialization | User input is passed to `pickle.loads()`, `yaml.load()`, or `marshal.loads()`, which can construct arbitrary objects. |
| CWE-918 | Server-side request forgery (SSRF) | User input is the URL passed to `requests.get()` so the attacker can scan internal services. |

All seven are **sink-shaped**: each one has a specific dangerous function (the "sink") that is what makes a sample exploitable. We deliberately exclude structural CWEs (missing auth checks, broken access control) because they cannot be detected by looking at one file in isolation.

---

## 3. The detectors

We score four detectors. Two are existing static-analysis tools, one is an AI model we trained ourselves, and one is a large language model (LLM) we send the code to.

### 3.1 Bandit  (static analyzer, pattern-based)

- **What it is.** A free Python security linter from the PyCQA group. Ships about 70 built-in rules.
- **How it works.** Parses the Python file into an AST, then matches the AST against a list of rule patterns. Each rule has a severity and a confidence. We map every Bandit rule ID to one of our seven CWE classes (mapping lives in `src/eval/detectors/bandit.py`).
- **Strengths.** Fast (sub-second per file). Predictable. Zero false negatives on patterns it knows.
- **Weaknesses.** No dataflow tracking. Cannot tell whether the data flowing into a sink is user-controlled or a literal. Token-level matching only — rename the sink and Bandit stops firing.
- **Why we include it.** Industry-standard baseline for Python SAST.

### 3.2 Semgrep  (static analyzer, pattern + light taint)

- **What it is.** A more flexible static analyzer that lets you write rules in YAML. We use three community rulesets: `p/python`, `p/security-audit`, and `p/owasp-top-ten`.
- **How it works.** Same pattern-match-the-AST idea as Bandit, but the pattern language is richer (you can match `f($X, ...)` where `$X` is a metavariable). Some rules use Semgrep's taint mode, which propagates user-input markers through a few hops.
- **Strengths.** Much larger rule ecosystem than Bandit. Limited dataflow.
- **Weaknesses.** Slower (a few seconds per file). Higher false-positive rate on safe code (it flagged many benign `requests.get(...)` calls in our hard negatives). Taint propagation is shallow.
- **Why we include it.** The most widely deployed open-source Python SAST tool.

### 3.3 GraphCodeBERT  (trained transformer, learned)

- **What it is.** A 126.6M-parameter transformer model from Microsoft. We fine-tuned it on our 607-sample training split with a three-phase schedule (contrastive warmup, then LDAM-margin loss, then deferred re-weighting with class-balanced sampling).
- **How it works.** Takes the source code as input, produces a probability distribution over the seven CWE classes plus `safe`. The training also includes a CVSS regression head, but we use only the classification output during evaluation.
- **Strengths.** Learns to ignore surface details that pattern-matching tools rely on. Catches SSRF (CWE-918), where both SAST tools score zero.
- **Weaknesses.** Trained on small data (607 samples) so generalization is limited. Black box: when it gets a sample wrong we cannot easily say why.
- **Why we include it.** The benchmark needs a learned detector to compare against pattern-matching SAST.

### 3.4 Claude (Anthropic LLM, pending)

- **What it is.** A general-purpose large language model accessed through the Anthropic API. We send the code, a fixed system prompt that lists the seven CWE classes, and parse the first line of the response as the prediction.
- **How it works.** Lives in `src/eval/detectors/llm.py`. The detector class is built and the dry-run cost projection works; we have not yet authorized a real run, which costs money and bills the Anthropic account.
- **Strengths.** Modern LLMs do well on code understanding tasks. Likely to catch flaws that the SAST tools miss.
- **Weaknesses.** Costs money per call. Non-deterministic at temperature > 0. Cannot be inspected.
- **Why we include it.** Modern security teams increasingly trial LLMs as detectors. Reviewers expect at least one represented in the evaluation.

Other detectors (CodeQL, UnixCoder, CodeT5+) are listed in [`EVALUATION_TOOLS_SURVEY.md`](EVALUATION_TOOLS_SURVEY.md) but were not selected for this round.

---

## 4. The seven adversarial mutators

A *mutator* takes a vulnerable Python file and rewrites it in a way that **does not change what the code actually does at runtime**, but changes what the code looks like. If the detector's accuracy drops sharply on the rewritten version, the detector was relying on the specific surface pattern the mutator targeted — and was not really understanding the vulnerability.

All mutators live under `src/red_team/mutators/` and are deterministic given a sample identifier and a random seed, so reruns produce identical outputs.

The seven mutators fall into three families.

### Family A — sink-preserving (four mutators)

These change the code **around** the sink but leave the sink call itself (the `os.system(...)`, the `cursor.execute(...)`, the `eval(...)`) unchanged.

| ID | Name | What it does |
| -- | ---- | ------------ |
| M1 | `dead_code_injection` | Adds unreachable statements like `if False: pass`, unused-variable assignments, and zero-iteration loops at random positions inside the function. Probes positional reasoning. |
| M2 | `string_split` | Takes a string literal and splits it into multiple pieces joined with `+`. The runtime value of the string is identical; the source-level substring is broken. Probes substring matching. |
| M3 | `variable_rename` | Renames local variables to synonyms (`user_id` → `account_no`, `query` → `command`). Probes identifier matching. |
| M4 | `wrapper_extraction` | Pulls the sink call out into a small helper function. The sink still runs, but now wrapped in one more frame. Probes single-function reasoning. |

**What we found:** all three detectors are invariant to this entire family (drop within ±0.05 macro-F1). This is the expected result for token-matching SAST and for a learned detector that was trained on similar augmentations.

### Family B — sink-targeted (two mutators)

These leave the surrounding code alone and rewrite **the sink call itself**, so the sink token (`system`, `execute`, `eval`) no longer appears as a bare identifier in the source.

| ID | Name | What it does |
| -- | ---- | ------------ |
| M5 | `sink_attr_obfuscate` | `os.system(cmd)` becomes `getattr(os, "system")(cmd)`. The sink name only appears inside a string literal. Covers CWE-78/89/918/502 attribute-style sinks. |
| M6 | `sink_via_globals` | `eval(x)` becomes `__import__("builtins").__dict__["eval"](x)`. Covers CWE-94 bare-builtin sinks. |

**What we found:** this is the main finding of the work. Bandit drops macro-F1 by 0.187 (47% loss in severity-weighted recall) under M5, and 0.143 under M6. Semgrep drops 0.109 and 0.132. GraphCodeBERT is essentially unaffected. The cliff replicates across both mutators, so it is a real property of pattern-matching SAST, not a single trick.

### Family C — dataflow (one mutator)

| ID | Name | What it does |
| -- | ---- | ------------ |
| M7 | `taint_through_dict` | `cursor.execute(query)` becomes `cursor.execute({"_a": query}["_a"])`. The sink identifier and the value reaching it are both unchanged; only the static lineage from the tainted variable to the sink argument now passes through a dict-construction/subscript pair. |

**What we found:** all three current detectors are invariant. This is **not** because the probe is weak — it is because none of our three detectors performs dataflow tracking. M7 is included to provide a measurement slot for future dataflow-aware detectors (CodeQL, Semgrep with taint mode enabled) that we expect to break here.

### The composed variant

In addition to the seven single-mutator variants, we also generate a `composed` variant where two or three mutators (drawn from all seven, randomly per sample, deterministically seeded) are applied to the same file. We report it as a column but rely on the single-mutator columns for the diagnostic story, because composition mixes shortcuts and makes per-mutator effects un-separable.

---

## 5. The test variants directory

After running `python scripts/build_mutator_variants.py --apply` the layout is:

```
data/test_variants/
├── clean/                 67 unmutated positives + their .meta.json labels
├── dead_code_injection/   67 files, M1 applied to each
├── string_split/          67 files, M2 applied to each
├── variable_rename/       67 files, M3 applied to each
├── wrapper_extraction/    67 files, M4 applied to each
├── sink_attr_obfuscate/   67 files, M5 applied to each
├── sink_via_globals/      67 files, M6 applied to each
├── taint_through_dict/    67 files, M7 applied to each
├── composed/              67 files, two-or-three random mutators each
└── manifest.json          per-sample record of which mutators applied
```

A given mutator does not apply to every sample (a `dead_code_injection` cannot mutate a file with no function, an `sink_via_globals` only applies to bare-builtin sinks). The manifest records which mutators actually fired on which samples. The "not applied" cases fall back to the unmutated source, so every variant directory has all 67 files.

The 65 `safe` hard negatives are **not** mutated. They appear only in the `clean` run, where they measure how many false positives the detector raises on benign code.

---

## 6. The metrics

We report five metrics. All are live as of 2026-05-22; an additional PR-AUC is listed in the methodology doc as a possible follow-up.

### 6.1 Macro-F1   *(primary, already in)*

Per CWE class, compute precision = TP / (TP + FP), recall = TP / (TP + FN), and F1 = 2 · P · R / (P + R) under one-vs-rest scoring. Average those seven F1 scores with equal weight (this is the "macro" in macro-F1). Result is a number in `[0, 1]` where 1 is perfect.

**Why macro and not micro:** the seven CWE classes are imbalanced (CWE-89 has 32 test positives, CWE-22 has 3). Micro-averaging would let the big classes dominate the score; macro-averaging treats each class as equally important.

**Caveat:** macro-F1 gives a wrong CWE prediction zero credit, even if the predicted CWE is a close sibling of the true one. HCMA below fixes that.

### 6.2 Detection MCC   *(primary, already in)*

MCC = Matthews Correlation Coefficient on the binary `vulnerable vs. safe` collapse of the predictions. Drop the CWE label and ask only "did the detector flag this file as vulnerable, yes or no?" Then compute:

```
MCC = (TP · TN − FP · FN) / sqrt((TP + FP)(TP + FN)(TN + FP)(TN + FN))
```

Result is in `[-1, +1]`. MCC = 0 is no better than chance, MCC = 1 is perfect, MCC < 0 is worse than chance.

**Why MCC and not accuracy:** the test set is approximately 50/50 vulnerable vs. safe so accuracy would technically work, but MCC is **chance-corrected** — a trivial "always say vulnerable" baseline scores 0, not 0.5. Accuracy can mislead under any class imbalance; MCC does not.

### 6.3 Severity-Weighted Recall (SWR)   *(primary, already in)*

Of the 67 positive samples, 27 have a CVSS base score (a numeric severity from 0.0 to 10.0 published with the original CVE advisory). SWR is **CVSS-weighted recall on that subset**:

```
SWR = sum of CVSS of vulnerabilities the detector caught
    / sum of CVSS of all vulnerabilities in the pool
```

Result is in `[0, 1]`. A detector that catches one critical CVSS-9.8 SSRF and misses three CVSS-3.0 path traversals scores higher than a detector that does the opposite.

**Why this metric exists:** for a real security team, missing a critical bug is much worse than missing a minor one. Plain recall treats every miss equally and does not reflect that.

**Pool size matters.** The 40 positives without a CVSS score (most of our `canonical` and `vudenc` samples) are excluded from the SWR calculation, not assigned a fallback score. We always report `SWR (n=27)` so the size of the pool is visible.

### 6.4 Hierarchical CWE Macro-Accuracy (HCMA)   *(primary, live)*

The fix for macro-F1's "zero credit for near-miss CWE" problem.

CWE is a tree. CWE-78 (OS command injection) and CWE-94 (code injection) are both children of CWE-74 (Injection). If the detector predicts CWE-94 when the truth is CWE-78, it got the family right — it just picked the wrong sibling. That should be worth more than predicting CWE-22 (path traversal), which is in a different part of the tree entirely.

We use Wu-Palmer similarity (1994):

```
sim(predicted, truth) = 2 · depth(LCA(predicted, truth))
                      / (depth(predicted) + depth(truth))
```

Where the **LCA** is the deepest CWE that is an ancestor of both, and **depth** is how far that node is from the root of the tree.

- Exact match → similarity 1.0
- Close sibling → roughly 0.6 – 0.8
- Distant cousin → roughly 0.3 – 0.5
- Unrelated → 0.0

For each true CWE class, we average similarity over all samples with that ground truth, then macro-average across classes. Result is in `[0, 1]`. Like macro-F1, but with partial credit.

**Why this matters for our paper.** Our detectors confuse adjacent CWEs noticeably (Bandit flags some CWE-94 samples as CWE-78 because both use sink-shaped calls). Macro-F1 reports these as flat misses. HCMA captures the "the detector understood it was injection, just not which kind."

### 6.5 Weighted Cohen's κ (kappa)   *(primary, live)*

The single-number summary, suitable for a headline column. Cohen's κ measures how much better a rater (the detector) agrees with the ground truth than chance alone would predict.

Standard κ formula:

```
κ = (observed_agreement − chance_agreement) / (1 − chance_agreement)
```

- κ = 1 → perfect agreement
- κ = 0 → no better than random guessing tuned to the prevalences
- κ < 0 → worse than chance

The **weighted** version generalizes by replacing "match / no-match" with a per-pair disagreement weight. We use:

- weight 0 between identical labels (no penalty)
- weight `1 − Wu-Palmer(p, g)` between two CWEs (partial penalty for near-misses)
- weight 1 between `safe` and any CWE (full penalty)

Result is in `[-1, +1]`. It is bounded, chance-corrected, gives partial credit through the same CWE tree as HCMA, and is a textbook statistic (Cohen 1968) — nothing invented for this paper.

**The κ-paradox caveat.** When one class is very rare, weighted κ can score lower than the raw agreement intuition suggests. We always report the raw observed agreement alongside κ so the comparison is honest.

### 6.6 Per-CWE F1   *(diagnostic)*

For every class we also report the per-CWE precision, recall, F1, support, TP, FP, FN. This is the table we use to diagnose where a detector's macro-F1 is coming from — e.g. Bandit's clean F1 of 0.491 looks middling but its per-CWE breakdown shows it is 0.857 on CWE-94 and 0.000 on CWE-22.

### Quick-reference card

| Metric | Range | What it answers | Status |
| ------ | ----- | --------------- | ------ |
| Macro-F1 | `[0, 1]` | "How accurate is the CWE prediction, treating all classes equally?" | live |
| Detection MCC | `[-1, +1]` | "How well does the detector distinguish vulnerable from safe, chance-corrected?" | live |
| SWR | `[0, 1]` | "What fraction of the CVSS-weighted danger did the detector catch?" | live |
| HCMA | `[0, 1]` | "When the CWE prediction is wrong, how close in the tree is it?" | live |
| Weighted κ | `[-1, +1]` | "Overall agreement with ground truth, partial credit, chance-corrected." | live |
| Per-CWE F1 | `[0, 1]` | "Where do the detector's right and wrong calls actually fall?" | live |

---

## 7. How the harness puts it together

Run from the project root:

```
python scripts/build_mutator_variants.py --apply    # only when mutators or test set change
python scripts/run_eval.py --tool all               # runs Bandit + Semgrep + GraphCodeBERT
```

The eval harness:

1. Loads CVSS scores from `data/raw/*.meta.json` for SWR weighting.
2. For each tool, loops over all variants (clean + seven single mutators + composed).
3. For each variant, loads the 67 positive samples (and on the clean run, the 65 safe negatives), runs the detector on each, and records `(ground_truth, predicted, raw_output, latency)` per sample.
4. Computes the metrics per variant (macro-F1, MCC, SWR, per-CWE F1; HCMA + weighted κ once added).
5. Computes the robustness drop = `metric(clean) − metric(mutator)`, restricted to the shared 67-sample set so the subtraction is apples-to-apples.
6. Writes two files per tool to `reports/eval/`:
   - `{tool}_predictions.jsonl` — one line per `(variant, sample)` with the full record
   - `{tool}_summary.json` — every metric per variant, robustness drops, per-CWE breakdown
7. Prints a console table summarising the run.

The summary JSON is the source of truth — the paper's tables are generated from it (or hand-transcribed from the printed table, currently).

---

## 8. What we report in the paper, where

| Paper section | Reports |
| ------------- | ------- |
| Evaluation §RQ1 (clean detection) | macro-F1, MCC, SWR, per-CWE F1 on the 132-sample clean set |
| Evaluation §RQ2 (robustness) | macro-F1 and SWR drop per mutator family, full 9-column F1 table |
| Evaluation §LLM detectors | reserved row in the headline table |
| Evaluation §Trained model | the three-phase training schedule and the per-mutator drops |
| Threats §Construct | mutator-strength discussion, M7 null-result caveat |
| Threats §External | benchmark size, framework bias, per-CWE confidence intervals |
| Threats §Summary of limitations | N=132 vs. PrimeVul scale, single-model evaluation caveat |

The HCMA and weighted κ rows will be added to the §RQ1 table and to a small dedicated paragraph in §RQ1 once the implementation lands.

---

## 9. Open items

1. **LLM detector run** — Claude detector is built but unauthorized. Run `python scripts/run_eval.py --tool claude --dry-run` to print the offline cost projection (currently ≈$11.45 total over 668 model calls with Claude Opus 4.7, paid per call to the Anthropic account). To execute a real run: `python scripts/run_eval.py --tool claude` after setting `ANTHROPIC_API_KEY`.
2. **Bib VERIFY notes** — five `note = { ... VERIFY ... }` entries in `paper/bib/references.bib` to resolve before submission (PrimeVul page range, RealVuln citation details, etc.).
3. **Overfull hboxes** — a few long monospace strings (`__import__("builtins").__dict__["eval"](x)` etc.) overflow the column in `evaluation.tex`. Cosmetic, not blocking.

That's the whole evaluation. The methodology doc explains *why* we chose each piece; this guide explains *what we are running.*
