# Progress report — 2026-05-28

**Session focus:** finish the LLM eval sweeps started yesterday (resume DeepSeek R1 from checkpoint, add a third LLM row), expand the SAST baseline with two whole-project tools (CodeQL, Snyk Code), and rewrite the paper end-to-end for the new 7-detector landscape.

**Session outcome:** four commits pushed to `origin/main` (laptop is no longer the single point of failure). DeepSeek R1 and Snyk Code sweeps both completed; CodeQL was attempted, returned zero findings, and is documented as an external-validity limit. Paper now reports seven detectors across four tiers with the new leadership pattern; abstract is still untouched. **3 working days remain** until the 2026-06-01 deadline.

---

## What landed (4 commits pushed to `origin/main`)

```
4b8bb7c  Docs: progress report for 2026-05-27
29b3515  Paper: 7-detector evaluation results across four tiers
a6b7421  Eval: 129-sample sweep results across seven detectors
0b4db8e  Eval: add CodeQL + Snyk Code detectors, exclude 3 oversized hardnegs
```

Branch was 39 commits ahead of `origin/main` at session start, 43 ahead after commits, now **up to date with origin** after the push.

---

## New detectors written this session

| Path | Detector | Outcome |
|---|---|---|
| `src/eval/detectors/codeql.py` | CodeQLDetector (database create + analyze, SARIF parse) | Returned 0 findings on the benchmark format. Documented as `§7.2` external-validity limit. Code kept in tree for future framework-aware benchmarks. |
| `src/eval/detectors/snyk_code.py` | SnykCodeDetector (batch mode via `snyk code test --json`, CWE tags from rule metadata) | Full sweep in 3 min. macro-F1 0.063 — the snippet-format ceiling on whole-project dataflow analysis. Appears in Table 1 as an outlier row that anchors the methodology argument empirically. |

`src/eval/samples.py` gained an `EXCLUDED_SAMPLE_IDS` frozenset that filters three hardnegs whose source files exceed 25K tokens (one is a 1.79 MB bundled artifact from docassemble). All seven detectors now score the same 129-sample test set (67 positives + 62 hardnegs).

`src/eval/detectors/openrouter_llm.py` switched DeepSeekR1Detector to the paid `deepseek/deepseek-r1` endpoint (the `:free` variant was deprecated by OpenRouter) and gained per-sample try/except so one bad call doesn't abort a 665-call sweep.

---

## Eval sweeps completed

| Detector | n_calls | wall time | macro-F1 (clean) | Cost |
|---|---:|---:|---:|---:|
| Bandit (re-score) | — | <1 min | 0.510 | $0 |
| Semgrep (re-score) | — | <1 min | 0.315 | $0 |
| Snyk Code | 665 | 3 min | 0.063 | $0 (free tier) |
| GraphCodeBERT (re-score) | — | <1 min | 0.524 | $0 |
| DeepSeek R1 (resume) | 268 (+397 from yesterday) | ~6 hours | 0.596 | ~$4.50 |
| Claude Sonnet 4.6 | (committed yesterday) | — | 0.585 | — |
| GPT-4o | (committed yesterday) | — | 0.356 | — |

Total Snyk + DeepSeek today: **~$4.50 in API spend** (well under the $10 OpenRouter credits added at start of session).

---

## What the numbers look like now (Table 1, 7-detector landscape)

| Detector | macro-F1 | MCC | SWR | HCMA | κ_w | Comp. | ΔF1* |
|---|---:|---:|---:|---:|---:|---:|---:|
| Bandit | 0.510 | +0.478 | 0.745 | 0.564 | **+0.567** | 0.589 | +0.187 |
| Semgrep | 0.315 | +0.157 | 0.634 | 0.353 | +0.227 | 0.375 | +0.132 |
| Snyk Code | 0.063 | −0.235 | 0.143 | 0.069 | −0.097 | 0.088 | +0.036 |
| Claude Sonnet 4.6 | 0.585 | +0.117 | **0.903** | **0.805** | +0.396 | 0.867 | 0.000 |
| GPT-4o | 0.356 | +0.047 | 0.420 | 0.419 | +0.295 | 0.565 | +0.026 |
| DeepSeek R1 | **0.596** | +0.410 | 0.691 | 0.646 | +0.539 | 0.567 | +0.068 |
| GraphCodeBERT (ours) | 0.524 | **+0.556** | 0.870 | 0.547 | +0.548 | 0.603 | 0.000 |

**No single detector dominates.** macro-F1 → DeepSeek R1. MCC → GraphCodeBERT. SWR + HCMA → Sonnet 4.6. κ_w → Bandit. This scattered-leadership pattern is now the framing in §6.3 and the conclusion.

---

## Key findings worth recording

1. **CodeQL on snippet benchmarks: 0 findings, every suite.** Tried `python-security-extended.qls` (54 queries), `python-code-scanning.qls` (the GitHub default), `python-lgtm-full.qls` (169 rules), and direct invocation of `Security/CWE-078/CommandInjection.ql`. Even with Flask/Django pip-installed so imports resolve, CodeQL's source model needs application-level entry points (route handlers, view functions) that are absent from function extracts. The result is unchanged after every documented workaround. **Documented in `§7.2` as a benchmark format limit** — single-file extracts cannot fairly score detectors whose semantics require whole-application context.

2. **Pyt (`python-taint`) is broken on Python 3.9+.** Installs fine, works on a textbook 1-file Flask sample, but crashes on real benchmark samples with `AttributeError: 'str' object has no attribute '_fields'`. Root cause: Python 3.9 changed `Subscript.slice` to be the slice expression directly instead of being wrapped in `Index`/`Slice`/`ExtSlice`; Pyt's last release (2019) predates this. Other AST nodes likely break too — not worth chasing. Skipped.

3. **Snyk Code as the "outlier row" in Table 1.** macro-F1 0.063, MCC −0.235 (negative, worse than chance). Per-CWE: catches 1/32 CWE-89, 0/12 CWE-502, 0/4 CWE-78 — and produces 32+ false positives across the safe class. Same shape-fit issue as CodeQL, but unlike CodeQL's silent zero Snyk returns low-confidence guesses. Includes the row in the table because the empirical visible bound is stronger paper material than an argumentative one. The CodeQL attempt is cross-referenced from the Snyk discussion in `§6.6` to the threats paragraph in `§7.2`.

4. **DeepSeek R1 is the strongest LLM detector.** macro-F1 0.596 (top of the table), MCC +0.410 (best-calibrated LLM by far — Sonnet is +0.117, GPT-4o +0.047). CWE-89 F1 0.935 — highest of any detector, ahead of GPT-4o's 0.915 and GraphCodeBERT's 0.625. Like the other LLMs it over-flags hard negatives as CWE-22 (10 FPs) and CWE-918 (10 FPs), which costs it MCC; treating those two classes as conditional labels would close most of the gap to GraphCodeBERT. The reasoning-model parser fallback added yesterday is what made this run work — R1 leaks `<think>` blocks intermittently and ends with the verdict line.

5. **OpenAI Tier 1 has a per-request 30K-token ceiling.** Discovered when GPT-4o crashed on the first call of yesterday's attempt — one hardneg sample is 42K tokens (chars/4 estimate). The fix is the `EXCLUDED_SAMPLE_IDS` filter from this morning, not a per-detector hack: the 3 oversized samples are now excluded from every detector's view so the eval set is the same 129 samples for all of them.

---

## Paper changes this session

End-to-end rewrite for the 7-detector / 4-tier landscape. Hitlist of sections touched in `paper/sections/`:

- **`introduction.tex`** — contribution bullet rewritten as "seven detectors across four tiers" with the new leadership pattern (DeepSeek macro-F1, Sonnet SWR/HCMA, GraphCodeBERT MCC, Bandit κ_w). Snyk Code framed as external-validity bound.
- **`dataset.tex` `§3 Final composition`** — added the 3-hardneg exclusion footnote (1.79 MB bundled artifact, 25K+/42K-token files). Clarifies that the active eval set is 129 (67 positives + 62 hardnegs) while the underlying split stays at 132.
- **`evaluation.tex` `§6.2 Setup`** — Detectors paragraph rewritten for 7 detectors across 4 tiers. Test-set count updated to 129. LLM call total updated to 665 (was 668).
- **`evaluation.tex` `§6.3 Headline`** — Table 1 has all 7 rows with real numbers. Caption updated with tool versions for Snyk Code 1.1305.0 and the three LLM model IDs. Headline prose rewritten: "The seven detectors separate on different axes; no single tool leads on every measure."
- **`evaluation.tex` `§6.4 Detection on clean (RQ1)`** — per-CWE Table 2 updated for the new 129-sample numbers (Bandit CWE-94 0.92, CWE-502 0.83, macro 0.51). Prose updated for "two pattern-matching SAST tools + GraphCodeBERT" framing; LLMs and Snyk get their own subsections.
- **`evaluation.tex` `§6.6` (new)** — `Whole-project dataflow detectors` subsection covering Snyk Code with a cross-reference to the CodeQL `§7.2` paragraph.
- **`evaluation.tex` `§6.7 LLM detectors`** — added DeepSeek R1 paragraph. Robustness paragraph rewritten for 3 LLMs (Sonnet 0.000, GPT-4o +0.026, DeepSeek R1 +0.068).
- **`evaluation.tex` `§6.8 Trained-model detector`** — GraphCodeBERT now leads on MCC only; macro-F1 and SWR leads went to DeepSeek and Sonnet respectively. Prose updated.
- **`evaluation.tex` `§6.9 Per-framework breakdown`** — converted from "we will report this" to "artifact-level breakdown available in released JSONL files."
- **`threats.tex` `§7.2 External validity`** — detector-shape-limit paragraph extended to cover both Snyk Code (in the table) and CodeQL (omitted, zero findings), framing both as snippet-format limitations rather than tool weaknesses. Single-run / determinism caveats rewritten now that the LLM runs are real.
- **`conclusion.tex`** — "seven detectors across four tiers" framing; scattered leadership pattern.

---

## What didn't happen (carried to tomorrow)

1. **Abstract update.** Still says "two SAST baselines + one trained detector" or similar — the only paper section that hasn't seen today's rewrite. Likely 10–15 min of work.
2. **Paper compile-check.** No `latexmk` run today — any LaTeX errors from cross-references or `\paragraph` formatting in the new subsections would surface here. Should be the first thing tomorrow.
3. **Final read-through.** Now that abstract / table / prose all need to agree, a top-to-bottom pass is overdue. Likely a 30 min job.
4. **Qwen + DeepSeek local Ollama rows** are not in Table 1. The `_predictions.jsonl` and `_summary.json` for both `deepseek_local` and `qwen_local` are committed (yesterday's runs), but no decision has been made on whether to add 2 more rows to the table for the local-LLM comparison. Open question for tomorrow.

---

## Decisions worth recording

- **Benchmark-level exclusion over detector-level workarounds** for publication-grade evals. The 3 oversized hardnegs are excluded at load time (`EXCLUDED_SAMPLE_IDS`) so all seven detectors see the same 129 samples. Saved as a memory: `feedback_benchmark_level_exclusion.md`.
- **Snyk Code's poor numbers ARE the result.** Including the row with the weak numbers + 1 paragraph of methodology framing (`§6.6`) is more defensible than omitting it. Reviewers see exactly what was measured and why the snippet format is unfair to this detector class.
- **CodeQL detector code stays in the harness** for downstream benchmarks that preserve entry points. The `§7.2` paragraph specifically states this so reviewers don't ask "where's the CodeQL impl?"
- **Paid DeepSeek R1 endpoint within $10 OpenRouter budget.** Actual spend was ~$4.50 for the full 665-call sweep. The `:free` variants are no longer reliable on OpenRouter; for publication-quality numbers, paying is the right move.

---

## Repo health snapshot

```
$ git log --oneline -4
4b8bb7c  Docs: progress report for 2026-05-27
29b3515  Paper: 7-detector evaluation results across four tiers
a6b7421  Eval: 129-sample sweep results across seven detectors
0b4db8e  Eval: add CodeQL + Snyk Code detectors, exclude 3 oversized hardnegs

$ git status
On branch main
Your branch is up to date with 'origin/main'.

Untracked (intentionally):
  reports/eval/claude_opus_*       superseded 5-sample smoke test
  runs/                            training checkpoints, large
  sec_code_train_bundle.zip        11MB training bundle
```

All today's work is committed and pushed. The deadline is **2026-06-01** — three working days left (Friday May 29, weekend if needed, Sunday May 31).
