# Evaluation Methodology

**Project:** Sink-validated Python vulnerability benchmark
**Audience:** authors, reviewers, anyone replicating the evaluation
**Last updated:** 2026-05-13

This document defines what the evaluation measures, which tools we run,
how each tool gets called, and how the results are reported. The
emphasis is on a free, reproducible setup that anyone can replicate.

---

## 1. What we evaluate, in one sentence

> *For each detector (SAST tool or LLM), how often does it correctly
> identify the CWE class of a labeled Python file, and how much does
> that accuracy drop when the file is rewritten in a way that
> preserves its runtime behavior?*

Two numbers per detector. Both matter. The first (clean accuracy) is
what CASTLE measures for C/C++. The second (robustness drop under
semantics-preserving rewriting) is the dimension we add.

---

## 2. The three evaluation axes

Every reported number comes from a fully crossed grid of:

| Axis | Values | What it tells us |
|---|---|---|
| **Tool** | Bandit, Semgrep, CodeQL, Pyre/Pysa, Pylint-security, Claude Opus, Gemini Pro | Per-detector performance |
| **CWE class** | CWE-89, CWE-79, CWE-22, CWE-78, CWE-94, CWE-918, CWE-502 | Where each detector is strong / weak |
| **Variant** | clean, dead_code, string_split, variable_rename, wrapper_extraction, composed | Which detection shortcut each tool relies on |

The headline table is **tool × variant**, aggregated across CWE
classes (macro-averaged). The per-CWE breakdown is a follow-on
table. The per-framework breakdown (Flask / Django / FastAPI) is a
third.

---

## 3. The metrics, defined

Every metric is computed *per (tool, variant, CWE)* cell first, then
aggregated.

### 3.1 Cell-level: TP / TN / FP / FN

For a given (tool, variant, CWE) cell, every test sample contributes
one outcome:

| Sample's label | Tool's prediction | Outcome |
|---|---|---|
| The CWE under test | Predicts that CWE | **TP** (true positive) |
| Some other CWE | Predicts the CWE under test | **FP** (false positive) |
| The CWE under test | Predicts a different CWE or "safe" | **FN** (false negative) |
| Some other CWE / safe | Predicts a different CWE / safe | **TN** (true negative) |

This is the standard one-vs-rest binarization. A tool that says
"this file looks like CWE-89" on a sample labeled CWE-79 counts as
one FP for CWE-89 and one FN for CWE-79 — both per-CWE cells get
updated.

The `safe` hard negatives only contribute to the TN/FP buckets.
A tool that flags any CWE on a `safe` sample increments FP for
that CWE; a tool that says `safe` correctly increments TN
across the board.

### 3.2 Per-cell scalar metrics

From the four cell-level counts:

| Metric | Formula | Range |
|---|---|---|
| **Precision** | TP / (TP + FP) | 0–1 |
| **Recall** | TP / (TP + FN) | 0–1 |
| **F1** | 2·P·R / (P + R) | 0–1 |
| **Accuracy** | (TP + TN) / total | 0–1 |

F1 is the headline number per cell. Precision and recall are kept in
the reporting tables because they decompose F1 in a way reviewers
expect.

### 3.3 Aggregated metrics

For the headline table, F1 is **macro-averaged across CWE classes**
(equal weight per class regardless of sample count). This is the same
choice CASTLE makes and is appropriate when class sizes differ by
more than 10x (our smallest class, CWE-22, has 15 samples; the
largest, CWE-89, has 212).

The single number per tool per variant is therefore:

```
macro_F1(tool, variant) = mean over CWE of F1(tool, variant, CWE)
```

### 3.4 Robustness drop

The key derived metric. For each tool, robustness drop measures how
much F1 falls when the input is rewritten by a specific mutator:

```
drop(tool, mutator) = macro_F1(tool, clean) - macro_F1(tool, mutator)
```

A tool with a small drop on `string_split` is robust to substring
matching breakdowns. A tool with a large drop on `wrapper_extraction`
relies on single-function analysis. The per-mutator drop is the
*diagnostic* signal: it explains *why* a tool's overall robustness
score is what it is.

The **aggregate robustness** number for a tool is the mean drop
across the four single-mutator variants:

```
robustness(tool) = mean over m in {dead_code, string_split, variable_rename, wrapper_extraction} of drop(tool, m)
```

Lower is better. A robustness of 0 means the tool is invariant to
the mutators we tested. A robustness of 50 means the tool loses 50
F1 points on average under semantics-preserving rewriting.

### 3.5 Confidence intervals for small-$n$ classes

Three classes have $n_{\text{test}} \le 7$: CWE-22 (3), CWE-78 (4),
CWE-918 (3), CWE-94 (6), CWE-79 (7). On these, a single mis-prediction
swings F1 by 14–33 points. We report 95% confidence intervals using
the Wilson interval for precision and recall and propagate to F1
via Monte Carlo (1{,}000 resamples). The reporting tables flag any
cell where the CI exceeds ±10 F1 points with an asterisk.

For the larger classes (CWE-89 at $n=32$, CWE-79 at $n=7$ but
recovers because of the test count, CWE-502 at $n=12$, CWE-22 at 3
which gets the asterisk), the CIs are tight enough that the
headline F1 numbers are reliable.

---

## 4. What makes our evaluation different from CASTLE

CASTLE~\cite{castle2025} sets the most directly comparable bar.
Five concrete differences:

### 4.1 Sink-validated labels (we do, CASTLE doesn't)

CASTLE inherits CVE/advisory labels directly. We validate every
positive sample through a three-layer filter: sink-presence (Phase 2B
filter), independent audit (three rounds, 6 failure-pattern
taxonomy), and a diff-based filter requiring the sink line itself to
be modified in the fix commit. Our audited FP rate is 26%; the rate
on the raw CVE-feed data we started from was 52%. CASTLE does not
report a measured label-quality number.

### 4.2 Adversarial robustness (we do, CASTLE doesn't)

CASTLE measures detection on the clean test set only. We measure
detection on six variants per sample (clean + four single-mutator +
composed). The mutators are semantics-preserving by AST-level
construction and target one detection shortcut each. The per-mutator
F1 drop is what lets us argue "tool X relies on substring matching"
or "tool Y is doing single-function analysis."

### 4.3 Python-native, not C/C++ (we are, CASTLE isn't)

CASTLE's 250 programs are in C and C++. Vulnerability classes shift
significantly between the two language families: C-CWE patterns
center on memory safety (CWE-787, 416, 119); Python-CWE patterns
center on sink-shaped injection (CWE-89, 79, 22, 78, 94, 918, 502)
and structural defenses (CWE-352, 862, etc.). The free SAST tools
available for the two languages also differ — Bandit and Semgrep
target Python specifically, where CASTLE used C-specific tools like
ESBMC and Clang Analyzer.

### 4.4 Label confidence tiers (we do, CASTLE doesn't)

Our samples carry three confidence tiers:
- **HIGH (provable)** — advisory-sourced *and* the diff filter saw the
  sink line change in the fix. About 442 of 871 positives.
- **HIGH (curated)** — hand-written textbook canonicals. 20 samples.
- **MEDIUM (curator)** — `vudenc`-sourced samples without a paired
  `code_after`; cannot be diff-validated but were human-labeled by the
  vudenc curators. 209 samples, all CWE-89.

The evaluation reports macro-F1 stratified by tier so a reviewer can
distinguish "this tool does well on HIGH samples but degrades on
MEDIUM" from "uniform performance across tiers." CASTLE has no such
distinction.

### 4.5 Per-framework breakdown (we do, CASTLE doesn't)

Every sample carries a `framework` field (Flask / Django / FastAPI /
unknown). Python SAST tools and LLMs vary noticeably across
frameworks — a Bandit rule for `os.system` is framework-agnostic but
a Semgrep rule for `request.args` is Flask-specific. We report
per-framework F1 to expose these gaps. C doesn't have an equivalent
dimension (framework distinctions there are at the project level, not
the language level), so CASTLE doesn't address this.

### 4.6 We don't compute a CASTLE Score

CASTLE has a custom composite score formula combining TP, TN, FP, FN
into a single 0–1{,}250 number, with a 200-point baseline for
"reports no issues" to avoid penalizing silent tools. We don't
replicate this. The reasons:
- Per-CWE F1 + robustness drop is more interpretable than a single
  composite.
- The CASTLE Score's weighting was tuned for C/C++ — the rebalance for
  Python isn't obvious and would invite reviewer questions.
- F1 + robustness is the format readers of vulnerability-detection
  papers expect.

---

## 5. Tools — free-tools-only list

### 5.1 Static analysis (SAST)

All four are free, open-source, installable from `pip` or with a
single binary download.

#### Bandit

| Field | Value |
|---|---|
| Install | `pip install bandit` |
| Invocation | `bandit -f json -r {sample.py}` |
| Output | JSON with `results[].test_id` (B-codes like `B608` for SQLi) |
| Mapping to our CWEs | Bandit's `test_id` → CWE via the documented mapping table (`B608` → CWE-89, `B602/B603/B607` → CWE-78, etc.) |
| Strengths | Fast (single-file analyzer), good Python coverage, 80+ rules |
| Weaknesses | No interprocedural reasoning, no taint flow, rule-based |
| Rule list | <https://bandit.readthedocs.io/en/latest/plugins/index.html> |

#### Semgrep

| Field | Value |
|---|---|
| Install | `pip install semgrep` |
| Invocation | `semgrep --config p/python --json {sample.py}` |
| Output | JSON with `results[].check_id` (rule names like `python.django.security.audit.unvalidated-password-hash`) |
| Mapping | Each Semgrep rule lists CWE in metadata; map via `extra.metadata.cwe` |
| Strengths | Pattern-based with framework awareness (separate Flask / Django / FastAPI rulesets), large community ruleset |
| Weaknesses | Pattern-based only (no real dataflow), some rules over-trigger |
| Rulesets to use | `p/python`, `p/security-audit`, `p/owasp-top-ten` |

#### CodeQL (CLI, free for research and open source)

| Field | Value |
|---|---|
| Install | Download the CLI from GitHub (free for OSS / research) |
| Invocation | Build a database per sample, run `codeql database analyze` against the security queries |
| Output | SARIF |
| Strengths | Proper dataflow analysis (taint tracking, interprocedural), the most thorough free SAST for Python |
| Weaknesses | Higher setup cost (DB build per sample), slower (minutes per sample) |
| Setup notes | The free license covers research use and OSS analysis. For non-OSS use the CLI is still free as long as the analyzed code is not used commercially. |

#### Pyre / Pysa (Meta, OSS)

| Field | Value |
|---|---|
| Install | `pip install pyre-check` |
| Invocation | `pyre analyze` after configuring with `pyre init` |
| Output | JSON with taint-flow traces |
| Strengths | True interprocedural taint analysis. The strongest Python SAST technically — what Meta uses internally. |
| Weaknesses | Documentation thin outside Facebook's stack, setup learning curve |
| When to include | If we have time for one more SAST tool and want to make the strong-SAST argument. Otherwise CodeQL is the safer single choice. |

#### Pylint (with `pylint-security` plugin)

| Field | Value |
|---|---|
| Install | `pip install pylint pylint-security` |
| Invocation | `pylint --load-plugins=pylint_security --output-format=json {sample.py}` |
| Output | JSON |
| Strengths | Widely deployed, free |
| Weaknesses | Security-rule coverage is thin compared to Bandit and Semgrep |
| Recommendation | Include only if rounding out a "code-quality vs security" comparison. Otherwise skip. |

### 5.2 LLMs

You have access to two production-grade LLMs through your accounts.

#### Claude Opus 4.7

| Field | Value |
|---|---|
| Access | Anthropic API (via your existing API key) |
| Why include | Top-tier reasoning; current state of the art on code understanding tasks |
| Cost | Pay-per-use; budget ~$50-100 for the full benchmark including all 6 variant conditions across 67 test positives + the 65 safe samples ≈ 132 base samples × 6 variants × ~1-2K tokens per call ≈ $30-80 depending on output verbosity |
| Prompting | Standardized system prompt + user-content template (see §6.2) |

#### Gemini 2.5 Pro

| Field | Value |
|---|---|
| Access | Google AI Studio (free tier with rate limits) or Vertex AI (paid) |
| Why include | Different model family from Anthropic; gives the LLM-vs-LLM comparison broader coverage |
| Cost | Free tier: 1M tokens/day at time of writing (check current Google AI Studio quota). Likely sufficient for the full eval at the volumes involved. |
| Prompting | Same template as Claude Opus, minor adjustments for Google's API surface |

#### Optional additions (also free)

| Tool | Access | Why |
|---|---|---|
| **DeepSeek V3 / R1** | Open API with generous free quotas | Open-weights model; reports show competitive code performance; lets you include an "open" row |
| **Claude Sonnet 4.6** | Anthropic API | Smaller / cheaper Claude; useful for cost-vs-accuracy comparison |
| **Open-weights local** (Llama 3.3 70B, Qwen 2.5 Coder) | Free, runs locally on a GPU | Lets you report on locally-deployable models, important for any reviewer who cares about offline use |

For the first complete evaluation pass, **Bandit + Semgrep + CodeQL +
Claude Opus + Gemini Pro** is the minimum to publish. Five tools, all
free, covering rule-based SAST, dataflow SAST, and two strong LLMs.

---

## 6. Tool evaluation protocols

### 6.1 SAST tools

For each SAST tool we run:

```
for variant in {clean, dead_code, string_split, variable_rename, wrapper_extraction, composed}:
    for sample in test_split:
        result = tool.scan(data/test_variants/{variant}/{sample.id}.py)
        cwe_predictions = map_tool_output_to_cwe(result, tool)
        record(tool, variant, sample, cwe_predictions)
```

**Prediction policy:** a sample is "predicted as CWE-X" if the tool's
output contains *any* finding mapped to CWE-X. Multiple findings on the
same file produce multiple predictions; the per-CWE TP/TN/FP/FN
accounting handles this correctly via the one-vs-rest model.

**Rule-to-CWE mapping:** every SAST tool ships rule IDs that map to
CWEs. We use the documented mapping for each tool. A few rules don't
map cleanly to our 7 CWEs (Bandit `B404` "Consider possible security
implications of subprocess import" is a soft warning, not a true CWE
positive). Those map to no CWE and contribute nothing to the
predictions.

### 6.2 LLMs

Each LLM receives a standardized prompt:

```
SYSTEM:
You are a security code reviewer. Given a Python source file, identify
whether it contains a vulnerability in one of these CWE classes:

  CWE-89  : SQL Injection
  CWE-79  : Cross-site Scripting
  CWE-22  : Path Traversal
  CWE-78  : OS Command Injection
  CWE-94  : Code Injection
  CWE-918 : Server-Side Request Forgery
  CWE-502 : Insecure Deserialization

If the file is safe, respond with "safe". If it contains one of these
vulnerabilities, respond with the CWE identifier. Respond with a single
line containing only the CWE identifier or "safe", followed by an
optional one-sentence justification.

USER:
<file contents>
```

**Parsing:** we read the first non-empty line of the response. If it
starts with `CWE-` followed by digits, we extract that as the
prediction. Otherwise we look for the word "safe" as a fallback. If
neither matches we score the response as "no answer" — counted as a
miss (not a positive prediction on any CWE).

**Temperature and seeding:** we run LLMs at `temperature=0` (or the
provider's lowest equivalent) and capture each provider's response ID
in the eval log. This is the closest we can get to deterministic LLM
output. Each provider's API has its own seed parameter; we use it
where available.

**Cost control:** each prompt is ≤2K tokens of source + system prompt
overhead, and the LLM response is constrained to ~50 tokens. Total
volume per LLM: 132 samples × 6 variants ≈ 800 calls. With Claude
Opus pricing roughly $0.005 per 1K input + $0.025 per 1K output, the
full pass is well under $20 per LLM.

### 6.3 Output schema

Each tool produces a per-sample prediction record:

```json
{
  "tool":           "bandit | semgrep | codeql | claude_opus | gemini_pro",
  "variant":        "clean | dead_code | string_split | variable_rename | wrapper_extraction | composed",
  "sample_id":      "...",
  "ground_truth":   "CWE-89",
  "predicted":      ["CWE-89"],     // possibly empty, possibly multi-CWE
  "raw_output":     "...",          // for audit
  "latency_ms":     1234,
  "tool_version":   "1.7.10"
}
```

These records aggregate into the cell-level TP/TN/FP/FN counters.

---

## 7. Reporting structure

### 7.1 Headline table

The single table that goes on page 1 of the results section:

```
Tool             | Clean | DC   | SS   | VR   | WE   | Comp | Robustness drop
-----------------|-------|------|------|------|------|------|-----------------
Bandit           | ...   | ...  | ...  | ...  | ...  | ...  | ...
Semgrep          | ...   | ...  | ...  | ...  | ...  | ...  | ...
CodeQL           | ...   | ...  | ...  | ...  | ...  | ...  | ...
Claude Opus 4.7  | ...   | ...  | ...  | ...  | ...  | ...  | ...
Gemini 2.5 Pro   | ...   | ...  | ...  | ...  | ...  | ...  | ...
```

All cells are macro-F1 across the 7 CWE classes. Each row's
"Robustness drop" is the mean F1 reduction across the four
single-mutator variants (i.e., excluding `composed`).

### 7.2 Per-CWE breakdown

A second table showing per-CWE F1 on the clean test set:

```
Tool             | C-89  | C-79  | C-22  | C-78  | C-94  | C-918 | C-502 | Macro
-----------------|-------|-------|-------|-------|-------|-------|-------|------
Bandit           | ...   | ...   | ...*  | ...   | ...   | ...*  | ...   | ...
...
```

The asterisk marks cells where the 95% CI exceeds ±10 F1 points
(small-$n$ classes).

### 7.3 Per-mutator breakdown

A third table that drills into *which* shortcut breaks each tool.
Identical layout to the headline table but showing F1 (not drop).
Diagnostic, not the headline metric.

### 7.4 Per-confidence-tier breakdown

A fourth table showing the macro-F1 separately for HIGH-provable,
HIGH-curated, and MEDIUM-curator samples. Tells the reader whether a
tool degrades on the lower-confidence tier.

### 7.5 Per-framework breakdown

Optional, depending on page budget. Macro-F1 sliced by Flask /
Django / FastAPI / unknown.

---

## 8. Reproducibility

Everything in this evaluation is fully reproducible from the released
artifacts:

1. **Dataset:** hash-pinned tagged release; every sample has stable
   ID and content hash.
2. **Mutator variants:** generated by
   `scripts/build_mutator_variants.py`, seeded by sample ID. Re-run
   produces byte-identical variants.
3. **Tool invocations:** captured per-tool in the eval harness
   (`scripts/eval_harness/`, to be built). Each tool version is
   recorded with its predictions.
4. **LLM seeds:** temperature 0 and response ID captured. Where the
   provider allows a seed parameter, the same seed is used across
   runs.
5. **Aggregation:** macro-F1 aggregation is the canonical one
   (un-weighted mean across CWE classes). No bespoke composite scores.

---

## 9. What we explicitly do not measure

To avoid scope creep and reviewer questions, we explicitly state the
following are out of scope for the headline eval:

1. **Latency at scale.** We capture per-sample latency for diagnostic
   purposes but don't optimize for it.
2. **The CASTLE Score formula.** See §4.6.
3. **Structural CWEs** (CWE-352, 862, 863, 284, 306, 639, 200) — see
   `STRUCTURAL_CWES_DEFERRED.md`. These would need a different
   evaluation methodology entirely.
4. **Multi-file vulnerabilities.** The benchmark is file-level. A
   vulnerability that spans two files (a tainted source in `views.py`
   reaching a sink in `db.py`) is out of scope.
5. **Patch-level evaluation** ("did the tool suggest the right fix?").
   We measure detection, not remediation.
6. **Real-world deployment performance.** Bandit running on a 100k-LOC
   codebase will perform differently than Bandit on our 132 isolated
   test files. We don't claim our numbers transfer.
7. **Adversarial inputs other than our four mutators.** We don't claim
   our four mutators cover every possible code transformation. We
   claim they cover four common detection shortcuts (positional,
   substring, identifier, single-function).

---

## 10. Concrete next steps

1. **Build `scripts/eval_harness/`** with separate runner scripts per
   tool. Each runner emits the JSON schema from §6.3.
2. **Run Bandit and Semgrep first** (local, free, fast). First numbers
   in <2 hours.
3. **Run CodeQL** (more setup, slower). First numbers in 1–2 days
   depending on database-build throughput.
4. **Build the LLM harness** with a dry-run cost estimate before
   authorizing the full pass.
5. **Run Claude Opus and Gemini Pro** (background; 1–2 hours of
   wall-clock).
6. **Aggregate into the headline + per-CWE + per-mutator tables.**
   Drop the numbers into the paper's evaluation section.

That sequence gets us a defensible benchmark result, all from
free tools, in three to five focused work sessions.
