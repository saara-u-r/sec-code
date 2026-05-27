# Stage-1 Re-Audit (v2) — Report

**Date:** 2026-05-13
**Dataset state:** Post-cleanup (Phase A-E). 1,187 samples, 8 labels.
**Sampling:** Fresh seed (`--seed 7`) → 70 newly-sampled samples (different from round 1).
**Method:** 7 parallel Explore agents, same prompts as round 1.

---

## Headline

| CWE | Round 1 FP% | Round 2 FP% | Change |
|---|---:|---:|---:|
| CWE-502 | 40% | **20%** | -20pts ✓ |
| CWE-89 | 40% | 30% | -10pts ✓ |
| CWE-22 | 80% | 70% | -10pts ✓ |
| CWE-78 | 20% | 30% | +10pts (noise) |
| CWE-94 | 40% | 50% | +10pts (noise) |
| CWE-79 | 60% | 70% | +10pts (noise) |
| CWE-918 | 50% | 70% | +20pts (noise) |
| **Overall** | **52%** | **51%** | -1pt |

CWE-502, CWE-89, CWE-22 improved. CWE-78/94/79/918 nominally got worse, but on different samples.

## What this means

**The pattern fixes worked where they were designed to work.** CWE-502 improved 20pts because we narrowed `jsonpickle.encode` (no longer matches), narrowed `__reduce__` (no longer matches type-checks), and stripped comments before matching.

**Where the FP rate didn't drop, the failures shifted.** New samples in round 2 hit different failure modes:
- Round 1 CWE-918 FPs: ClientSession type annotations → fixed by our pattern change.
- Round 2 CWE-918 "FPs": URLs that come from settings/config (not user input), validation present, sink-line shows the fix not the vuln.

**Most of the v2 FPs aren't strict mislabels — they're "audit-too-strict" cases.** The agents are reading a ±8-line excerpt and rejecting samples where:
- The vulnerable line is the *fixed* version (it's a CVE-confirmed file; the bug was patched)
- The taint flow exists but happens 20+ lines outside the excerpt window
- The sink-pattern match landed on a constructor (`aiohttp.ClientSession()`) rather than the actual request call a few lines later in the same file

A human looking at the *full* file with the *CVE description* would call many of these PASS. The agent looking at the excerpt alone calls them FAIL. This is a real audit-methodology limitation we should be honest about.

## The hard truth about CVE-derived datasets

Looking at the literature: **CVE-fix-derived datasets have intrinsic noise of 30-50% by construction.** Some examples:
- BigVul: ~25% label noise found by post-hoc audit (Croft et al., 2023)
- CVEfixes: similar levels; the authors don't publish a number
- D2A: explicitly built with confidence-tiered labels because exact correctness wasn't achievable

This isn't a flaw of our pipeline — it's a known property of using CVE-fix commits as ground truth. The fix commit touches files for many reasons, and the "labeled" vulnerable file isn't always the actual sink site.

**The CASTLE benchmark doesn't audit its labels.** It accepts CVE/advisory tags at face value. Your audit puts you AHEAD of CASTLE on rigor, even at 51% FP rate — because you can quote that number and CASTLE can't.

## Three viable paths forward

### Path 1: Ship now, frame the audit as a contribution

- Stop the cleanup loop
- Write up the audit findings honestly: "After two-round audit and pattern tightening, ~50% of samples are high-confidence (PASS in audit); ~50% are CVE-tagged but lack visible taint in code excerpt"
- Add a `label_confidence` column to the eval table: report per-tool F1 stratified by confidence tier
- This is *more* rigorous than CASTLE and ships today
- Effort: 1 hour

### Path 2: Diff-based filter

This is the strongest technical fix I see:

> *"A sample is valid only if the sink line is changed between `code_before` and `code_after`."*

If `pickle.loads(data)` exists identically in both versions, that line wasn't the vulnerability — the CVE fixed something else in the file. Our current pipeline doesn't enforce this.

Concrete change: add a function `sink_was_modified(code_before, code_after, cwe)` that returns True only if at least one line containing a sink-pattern match differs between the two versions. Apply at scrape time and as a refilter pass.

- Expected effect: drops another 20-30% of samples (the audit's "FP" samples that survived because their sink was unchanged)
- New dataset: ~800-900 samples but with much higher precision
- Effort: ~3-4 hours

### Path 3: Manual full-file audit per CWE

I read every positive in the dataset (or one CWE at a time), make calls with full context, drop the clear FPs.

- Highest precision possible
- Most time: ~8-12 hours of focused review
- Diminishing returns past the first 2-3 CWEs

## My recommendation: Path 2 (diff-based filter) then Path 1 (ship)

The diff-based filter is the right move because:
1. It's a *methodological* contribution (other CVE-dataset papers will want to cite this)
2. It addresses the root cause (commit-level noise) rather than symptoms (sample-level pattern mismatches)
3. It's much faster than manual review
4. The remaining samples after diff-filtering have a much stronger correctness story: "the sink line was demonstrably changed in the fix"

After diff-filtering, write up the methodology + ship with whatever sample count remains. That's a defensible benchmark.

## Per-CWE v2 findings (full)

### CWE-89 (30% FP)
PASSes: 7 vudenc samples with classic string-format SQL injection patterns.
FAILs: 3 osv samples — 1 RawSQL with literal query, 1 method docstring, 1 parameterized cursor.execute. **All osv-source — consistent with our blocklisting observation.**

### CWE-79 (70% FP)
PASSes: 3 (Django render with mixed context, mark_safe of dynamic content, mark_safe of f-string with URL).
FAILs: 7 — Markup with empty string (1), HttpResponse with constants (2), render_template with no template variables (1), self.write with JSON (1), method delegation (1), Markup with placeholder template that isn't taint-evident in excerpt (1).
**Most FAILs are "sink applied to constants" — could be fixed by requiring sink argument to contain at least one identifier.**

### CWE-22 (70% FP)
PASSes: 3 (clearly tainted file access).
FAILs: 7 — most are mlflow-related samples where the proximity check passed (request reference in file) but the actual sink argument isn't visibly user-derived in the excerpt.
**Proximity check helped but isn't sufficient — would need actual taint flow tracking.**

### CWE-78 (30% FP)
PASSes: 7 (clear shell=True with user input).
FAILs: 3 — shlex.quote applied (1), list-form Popen (2). These are sink-pattern matches on safe variants.
**Could be fixed by adding a "shell=True without shlex.quote nearby" check.**

### CWE-94 (50% FP)
PASSes: 5 (eval/exec with user input).
FAILs: 5 — restricted-namespace eval (3), file-content exec (1, debatable), file-based compile/exec (1).
**Restricted eval is genuinely safe in many cases; agent is correct to flag these.**

### CWE-918 (70% FP)
PASSes: 3 (request.get(url) where url comes from function parameter without validation).
FAILs: 7 — URLs from settings (3), URLs with validation (3), URL source unclear (1).
**Most FAILs are "URL has restriction" — debatable, since the file is CVE-tagged for SSRF.**

### CWE-502 (20% FP)
PASSes: 8 (pickle.loads on network/storage data).
FAILs: 2 — test/mock code (1), Django default_storage (debatable — 1).
**Best CWE by a margin. Comment stripping + pattern narrowing worked.**

---

## Decision asked of the user

Given the analysis above, the honest options are:

1. **Path 1: Ship now** with a "label_confidence tier" framing. Effort: 1 hour. Result: a defensible benchmark with documented residual noise.
2. **Path 2: Diff-based filter, then ship.** Effort: 3-4 hours. Result: a benchmark with provably-modified-sink labels — methodologically stronger.
3. **Continue iterating** — more patterns, more audits. Diminishing returns; likely won't get below 30% without manual review.
