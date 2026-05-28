# Progress report — 2026-05-27

**Session focus:** extend the evaluation harness to cover cloud LLMs (Anthropic Sonnet 4.6, OpenAI GPT-4o) and **truly-free local LLMs** (DeepSeek R1 7B, Qwen Coder 7B via Ollama), add interrupt-tolerant checkpoint/resume so multi-hour eval sweeps survive partial crashes, and reorganize the project's 40 scattered top-level markdown files into a discoverable `docs/` tree.

**Session outcome:** one commit on `main` (the doc reorg). A second commit is staged for the LLM-detector work — held back so the reorg lands in isolation. Two cloud LLM sweeps (Claude Sonnet 4.6 + GPT-4o) are running in the background as of this writing; the two local Ollama sweeps are queued for tonight via a scheduled reminder.

---

## What landed (1 commit on `main`)

```
9b2ac1b Docs: reorganize 40 markdown files into docs/{progress,audits,design,reference,training}
```

### Doc reorganization

Root had 33 scattered `.md` files with inconsistent naming (`PROGRESS_REPORT_YYYY-MM-DD` vs `project_progress_report_YYYY_MM_DD`, versioned `BENCHMARK_AUDIT_*` files, design + progress + reference all intermixed). Grouped them by purpose:

| Directory | Files | Contents |
|---|---:|---|
| `docs/progress/` | 10 | dated progress reports (this one + the 9 prior) |
| `docs/audits/` | 6 | `BENCHMARK_AUDIT_{REPORT,SAMPLES}_*` v1/v2/v3 |
| `docs/design/` | 7 | phase designs, rescopes, deferrals, open questions |
| `docs/reference/` | 14 | methodology, surveys, schema, guides |
| `docs/training/` | 3 | GPU / JupyterLab / Kaggle handoffs |

Also moved 7 `.md` files out of `reports/` into the new tree so `reports/` is now what its name implies — pure code output (`eval/`, `logs/`, `health_report.json`).

Filenames preserved during the move so any docstring grep still resolves. The 14 cross-references in code/README to top-level `.md` paths were updated to `docs/X/Y.md` in the same commit. Added a `docs/README.md` index for navigation.

All renames done with `git mv` so history follows each file. **114/114 eval tests still pass.**

---

## What's staged for the next commit (uncommitted, this session)

Held back deliberately so the reorg has a clean isolated commit.

### New files

| Path | Purpose |
|---|---|
| `src/eval/detectors/ollama_llm.py` | Ollama-backed local LLM detector. Base class + `DeepSeekR1LocalDetector` (`deepseek-r1:7b`) + `QwenCoderLocalDetector` (`qwen2.5-coder:7b`). Hits the OpenAI-compatible endpoint at `localhost:11434/v1`. |
| `src/eval/detectors/openrouter_llm.py` | OpenRouter cloud detector for the same two models (`deepseek/deepseek-r1:free`, `qwen/qwen3-coder:free`). Built first, then de-prioritized when the free-tier daily caps proved too tight for a 792-call sweep — kept for future use. |
| `tests/eval/test_ollama_llm.py` | 6 offline tests: metadata, daemon-unreachable guard, `$0` cost projection. |
| `tests/eval/test_openrouter_llm.py` | 8 offline tests for the OpenRouter detector and its `<think>` stripper. |
| `docs/progress/PROGRESS_REPORT_2026-05-27.md` | This file. |

### Modified files

| Path | Change |
|---|---|
| `src/eval/detectors/llm.py` | `parse_llm_response` got a **reasoning-model fallback**: when the first non-empty line is neither a CWE nor "safe" (a chain-of-thought model leading with prose), scan from the end for the last verdict-shaped line. R1's correct CWE-79 verdict on a smoke-test sample was being silently dropped before this fix; instruction-following models (Claude, GPT) are bit-for-bit unaffected — their first line is still the verdict. |
| `src/eval/detectors/__init__.py` | Registered four new LLM keys: `deepseek`, `qwen` (OpenRouter), `deepseek_local`, `qwen_local` (Ollama). All four stay opt-in — `--tool all` is still SAST-only. |
| `scripts/run_eval.py` | (1) Plumbed the Ollama/OpenRouter detectors into dry-run and the unavailability hints. (2) **Per-variant checkpoint** — the predictions JSONL is now rewritten after each variant completes inside `run_tool`, so an 11-hour DeepSeek sweep that crashes at hour 8 keeps the first 4–5 variants on disk. (3) **`--resume` flag** — on restart, variants already complete in the existing JSONL are skipped without an API call; partial variants are re-run from scratch (partial sample interleaving isn't worth the complexity). |
| `tests/eval/test_llm.py` | Added 4 tests for the reasoning-model fallback: end-of-response CWE verdict, end-of-response "safe", multi-CWE enumeration picks the last one, first-line-wins is still preserved. **42/42 LLM-parser tests pass.** |

### Test totals after the session's changes

```
$ python -m pytest tests/eval/ -q
114 passed in 0.4s
```

---

## Eval runs in flight (background, started before this session by the user)

| Tool | Model | Status | Notes |
|---|---|---|---|
| `claude` | claude-sonnet-4-6 | running (PID 60396) | Anthropic API; user-tracked task in the morning's plan |
| `gpt` | gpt-4o | running (PID 61730) | OpenAI API; same |

Both write to `reports/eval/claude_sonnet_*` and `reports/eval/gpt_4o_*` respectively. Cloud-API calls only, low local CPU.

## Eval runs queued for tonight (scheduled reminder)

A one-time remote routine fires at **21:00 Europe/Berlin** today via `claude.ai/code/routines` to remind the user to kick off:

```
python scripts/run_eval.py --tool qwen_local --resume   # ~2.2h
python scripts/run_eval.py --tool deepseek_local --resume   # ~11h, split across nights if needed
```

These were initially queued back-to-back via `caffeinate -i` earlier today but stopped after ~75 min because the machine was overheating from running 3 LLM evals (Claude + GPT + Qwen) in parallel. The new `--resume` flag means an interrupted run loses only the in-flight variant going forward.

---

## Key smoke-test findings (local Ollama, before the long runs)

Both findings are *reportable contributions* for the paper, not bugs:

1. **Qwen-Coder-7B has a capability ceiling for this task.** Across 5 smoke-test samples (all genuinely vulnerable, CWE-79/22), the model output `safe` on every one. Not a parser issue — the raw responses are bare `safe` tokens or text like "The provided code does not contain any of the specified vulnerabilities." A code-specialized 7B model fails to detect XSS and path-traversal patterns even with the 7-CWE shortlist visible in the system prompt. This is the *negative result* worth featuring in the practitioner section of the paper.

2. **DeepSeek-R1 7B detects but verdicts at the end.** On the same 5 samples, R1 produced lengthy chain-of-thought traces. Sample 2 ended with `CWE-79  : Cross-site Scripting` — the correct verdict — but on the *last* line, after the reasoning. The original "first non-empty line is the verdict" parser silently scored this as no-prediction. The reasoning-model fallback added in `parse_llm_response` recovers it. **This is a parser-methodology contribution**, not just an implementation fix: reasoning models genuinely require a different parsing rule.

---

## Re-parse of existing predictions (no extra API calls)

To verify the parser change wasn't lossy for instruction-following models, re-parsed the existing `claude_opus_predictions.jsonl` (5-sample smoke test) with the new rule: identical predictions. The fallback path only activates when the first line isn't a verdict, which never happened for Claude.

---

## Open work (for tomorrow)

1. **Commit the LLM-detector + checkpoint/resume work** as a second commit (intentionally held back to keep the reorg diff focused).
2. **Run Qwen + DeepSeek locally tonight** (Qwen first, ~2.2h; R1 across two nights if needed).
3. **Wire all six detector rows into paper Table 1** once Sonnet 4.6 and GPT-4o sweeps complete. The headline columns (Clean, DC, SS, VR, WE, SAO, SVG, TTD, Comp) are already shaped by `build_summary` in `scripts/run_eval.py` — just need the numbers.
4. **Stretch:** if R1 7B's results are intriguing, smoke-test `deepseek-r1:14b` (~9GB, still fits in 24GB RAM) before committing to a larger sweep — could materially change the local-LLM column of the headline table.

Hard deadline is **2026-06-01** (4 working days from today). Qwen finishing tonight + R1 finishing tomorrow night gives a one-night buffer for re-runs.

---

## Decisions worth recording

- **OpenRouter free tier is not viable for this benchmark.** Free models cap at ~50 req/day without funding, ~1000/day with $10+ in credit; 132×6 = 792 calls per model puts a full sweep out of reach on the unfunded tier and exactly at the edge on the funded one. Local Ollama (truly $0, no caps, ~24GB RAM headroom on the host) is the right choice for this project's constraints. OpenRouter detectors are kept in the codebase for future projects that have funded accounts.
- **Detector keys stay opt-in.** `--tool all` runs only SAST tools (bandit, semgrep, graphcodebert). LLM-backed detectors (`claude`, `gpt`, `deepseek`, `qwen`, `deepseek_local`, `qwen_local`) must be named explicitly, to avoid an accidental run that hits a paid API or stalls on a rate limit.
- **Methodology, not workaround.** The reasoning-model parser fallback is documented as a methodology choice in the `parse_llm_response` docstring — not a per-detector hack. Reasoning models really do produce a different output shape; the parser handles both shapes uniformly.

---

## Repo health snapshot

```
$ python -m pytest tests/ -q       # full suite (eval subset run during session)
tests/eval/ — 114 passed
$ git status
On branch main; 36 commits ahead of origin/main
  staged for next commit: 5 new files + 4 modified
  unrelated (paper edits, eval-output files): 5 paper .tex + 9 eval JSONL/JSON
```

Eval-output files in `reports/eval/` (the `claude_sonnet_*`, `gpt_4o_*`, `bandit_predictions.jsonl` etc.) are intentionally not committed — they're generated artifacts, regeneratable from the harness.
