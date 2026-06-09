# Final Presentation — Slide Outline

**Format:** Google Slides (paste one block per slide). Each slide has a **Title**, **Bullets** (what goes on the slide — keep these short on-screen), and **Speaker notes** (what you actually say — paste into the notes pane).

**Story arc:** the field ignored Python → existing data is noisy → we picked sink-shaped CWEs → we read code by hand to learn what a "sink" really looks like → we scraped at scale → our first audit failed (52% wrong) → we diagnosed *why* and added a diff filter → we got to 26% → we built negatives + adversarial tests → we benchmarked 10 detectors → what we learned.

---

## Slide 1 — Title

**Bullets**
- An Audit-Validated Benchmark for Python Vulnerability Detection
- [Your name], [Guide name], [Department / Institution]
- Final Project Presentation — June 2026

**Speaker notes**
Good [morning/afternoon]. My project builds a clean, hand-checked benchmark for detecting security vulnerabilities in Python code, and uses it to measure how well today's tools — both static analyzers and large language models — actually find those bugs. The headline contribution is the *label quality*: I'll show how I cut the mislabeling rate in the raw data from 52% down to 26% through a layered validation method, and what that revealed about how detectors really behave.

---

## Slide 2 — The one-sentence version

**Bullets**
- A 869-sample Python benchmark across 7 vulnerability classes
- Every positive label hand-audited, not just inherited from CVE commits
- Used to benchmark 10 detectors — static tools vs. LLMs — on clean *and* adversarial code

**Speaker notes**
If you remember one slide, it's this one. Most vulnerability datasets trust the labels that come out of bug-fix commits. I didn't. I built a benchmark where every "vulnerable" label was checked against the actual code, and then I used it to ask a sharper question: do detectors really *reason* about code, or do they just pattern-match the surface? Everything else is how I got here.

---

## Slide 3 — The problem, part 1: the field skipped Python

**Bullets**
- 5 years of vuln-detection research is overwhelmingly **C / C++**
- Major datasets: BigVul, Devign, ReVeal, DiverseVul — all C-centric
- Yet Python runs ML pipelines, web back-ends, automation, cloud infra
- No curated, audit-validated Python benchmark exists (cf. CASTLE for C)

**Speaker notes**
Here's the gap I started from. Almost all the influential work — the datasets everyone benchmarks on — is C and C++. That made sense historically: memory-safety bugs, big open-source kernels. But the software that processes our personal data, financial records, and ML pipelines today is largely *Python*, and Python gets a fraction of the attention. There is no Python equivalent of the well-curated C benchmarks. That absence is the hole this project fills.

---

## Slide 4 — The problem, part 2: the labels are noisy

**Bullets**
- Standard practice: inherit "vulnerable" labels from CVE fix commits
- Commits touch many files; the labeled file often isn't the real sink
- Known noise: ~25% in audited BigVul
- **My own audit of raw CVE-feed data: 52% mislabeled positives**

**Speaker notes**
The second problem is deeper and it's the one I spent most of my time on. When people build Python datasets, they take a CVE, find its fix commit, and label the changed files as "vulnerable." The trouble is a fix commit cuts across many files — tests, docs, refactors, the actual fix — and the CVE rarely tells you which *line* was the bug. So you inherit a lot of garbage. The literature pegs this around 25% for BigVul. When I audited a raw, unfiltered CVE feed myself, more than half — 52% — of the "vulnerable" samples were not actually vulnerable at the labeled site. You cannot benchmark detectors on data that's wrong half the time. That became the central engineering problem.

---

## Slide 5 — The goal

**Bullets**
- Build an **audit-validated** Python benchmark across sink-shaped CWE classes
- A **label-validation method** that measurably reduces inherited noise
- Measure detector **accuracy AND adversarial robustness** together
- Goal: separate detectors that *reason* from detectors that *pattern-match*

**Speaker notes**
So the goal statement, precisely. Three things. One: a Python benchmark where I trust the labels. Two: a repeatable method for *getting* to trustworthy labels — not a one-off cleanup, a pipeline. Three: measure not just "does it score well on clean code" but "does it still work when I rewrite the code in a behavior-preserving way." That last part matters because a tool that only recognizes the exact surface form it was trained on isn't really detecting vulnerabilities — it's memorizing.

---

## Slide 6 — Why Python (and why these bugs)

**Bullets**
- Python = dominant language for security-critical infra (ML, web, cloud, automation)
- Its vulnerability classes are **sink-anchored** and language-specific:
  - SQL injection via DB-API / ORM string-building
  - Deserialization of `pickle` / `yaml`
  - Code injection via `eval` / `exec`
  - SSRF in webhook / fetch endpoints
- One missed injection or deserialization flaw can expose an entire user base

**Speaker notes**
Why Python specifically, beyond "it's popular." The vulnerabilities that matter in Python are *different in shape* from the C literature. C work is dominated by memory safety. Python's dangerous bugs are about untrusted data reaching a dangerous function — a *sink*. `pickle.loads` on attacker data. `eval` on a request parameter. An f-string built into a SQL query. These are injection and deserialization flaws, and they're "sink-anchored": there's a specific call that's the danger point. That property — that the bug lives at an identifiable sink — is what makes a clean benchmark even possible, and it shaped every design decision after this.

---

## Slide 7 — Literature survey: the datasets I reviewed

**Bullets**
| Dataset | Languages | Why it didn't fit |
|---|---|---|
| BigVul | C/C++ | 264 CVEs, C/C++ only; ~25% label noise |
| CVEfixes | Multi | C-dominant; Python a tiny fraction |
| CrossVul | 40 langs | Per-language counts too small for per-class eval |
| DiverseVul | C/C++ | Dedup study; found ~18% duplication across sources |
| Devign / ReVeal | C only | Tell us nothing about Python |
| Juliet (NIST) | Synthetic | Hand-made; transfers poorly to real code |
| **vudenc** | **Python** | **Closest fit — but no paired `code_after`** |

**Speaker notes**
This is the survey that justified the whole direction. I went through the standard datasets one by one. BigVul, Devign, ReVeal — C only. CVEfixes and CrossVul are multi-language on paper, but when you filter to Python the counts collapse and you can't do per-class evaluation. DiverseVul is interesting because it's a dedup study — it found ~18% of records are duplicates when you naively merge sources, which is a warning about data hygiene I took seriously. Juliet is synthetic, so models that learn it don't transfer to real code. The closest thing to what I needed was vudenc — real, human-annotated Python across seven CWEs. But it has a critical limitation for me.

---

## Slide 8 — Why even the best existing option fell short

**Bullets**
- vudenc is high-quality at the **file level**
- But it has **no paired `code_after`** (the fixed version)
- Without a before/after pair, you can't run a diff-based label check
- Decision: **include vudenc as a separate label-confidence tier**, build the rest myself

**Speaker notes**
vudenc labels files, but it doesn't give you the *fixed* version of each file. That matters because — as you'll see — my strongest validation trick is comparing the vulnerable code against the fix and checking that the dangerous line actually *changed*. No fix version, no diff check. So I made a deliberate call: I kept vudenc but quarantined it as its own lower-confidence tier, and I built the rest of the benchmark from sources that *do* carry fix commits, so I could validate them properly. This is the first of several "the clean thing was worth the extra work" decisions.

---

## Slide 9 — The pipeline at a glance

**Bullets**
- **Phase 1** — Scrape & ingest from CVE/advisory sources
- **Phase 2** — Stratified, leak-free train/val/test split
- **Phase 2B** — 3-layer label validation (the heart of the project)
- **Phase 2.5** — Hard negatives + adversarial mutators
- **Eval** — 10 detectors on clean + mutated test sets

**Speaker notes**
Here's the map of the whole system so you can place each piece I'm about to describe. Scrape the raw data. Split it carefully so there's no leakage. Then the part that took the most work: three layers of validation that take the data from 52% wrong to 26% wrong. Then build the negative examples and the adversarial stress tests. Then benchmark everyone. I'll walk these in order, and I'll be honest about where things broke along the way.

---

## Slide 10 — Choosing CWEs: the "sink-shaped" idea

**Bullets**
- Started from MITRE Top-25, filtered to Python-relevant classes
- Key criterion: is the bug **sink-shaped**?
  - Sink-shaped = a specific dangerous call defines the flaw (e.g., `eval(taint)`)
  - Structural = the flaw is the *absence* of something (e.g., missing auth check)
- Sink-shaped bugs are *findable at the file level*; structural ones need app-wide context

**Speaker notes**
The selection criterion is the cleverest design choice, so let me dwell on it. Vulnerabilities come in two shapes. "Sink-shaped" ones have a smoking gun — a specific call like `eval` or `pickle.loads` where untrusted data does damage. "Structural" ones are about something *missing* — there's no authorization check, no CSRF token. The structural ones are real bugs, but you can't find them by looking at one file; you need to understand the whole application's auth model. The sink-shaped ones you *can* anchor to a line. Since my whole validation method depends on locating the sink line, I scoped the benchmark to sink-shaped CWEs. This was a scoping decision that made everything downstream tractable.

---

## Slide 11 — The 7 CWEs we kept

**Bullets**
- **CWE-89** SQL Injection — `cursor.execute(f"...")` → parameterized
- **CWE-79** XSS — `Markup(user_input)` → `escape(...)`
- **CWE-22** Path Traversal — `open(taint)` → `safe_join(BASE, taint)`
- **CWE-78** OS Command Injection — `os.system(f"...")` → `subprocess.run([...], shell=False)`
- **CWE-94** Code Injection — `eval(taint)` → `ast.literal_eval`
- **CWE-918** SSRF — `requests.get(url)` → hostname allowlist
- **CWE-502** Insecure Deserialization — `pickle.loads(taint)` → `yaml.safe_load` / signed

**Speaker notes**
These are the seven survivors. Notice the pattern in the right column: each one has a recognizable unsafe form *and* a small, well-known set of safe fixes. That's exactly the property I wanted — a bug with a clear sink and a clear remediation, because that gives me both the "before" and a predictable "after." These seven span the most common and most damaging Python web and data-pipeline flaws: injection, XSS, traversal, command exec, code exec, SSRF, and unsafe deserialization.

---

## Slide 12 — The CWEs we had to remove (and why)

**Bullets**
- **CWE-798** Hardcoded Credentials — single-source bias (all from one miner); fix alphabet didn't fit
- **CWE-434** Unrestricted File Upload — **100% false-positive rate in audit**; structural, not sink-shaped
- **CWE-77** Command Injection — **merged into CWE-78** (same sinks in Python; distinction was bureaucratic)
- **CWE-611 / 330 / 400** — dropped: **not in MITRE Top-25** after re-scope
- Structural CWEs deferred: CSRF (352), authz (862/863), authn (306), IDOR (639)…

**Speaker notes**
And here's where I'll be candid about the cuts — this is part of the story, not a footnote. CWE-798, hardcoded credentials: all my samples came from a single static miner, so it was biased, and the fix shape didn't match the others. Cut it. CWE-434, file upload: this one's instructive. When I audited it, *every single sample* was a false positive — my patterns were matching Django's own framework source, field declarations, imports, not actual vulnerable upload handlers. File upload is genuinely structural — the bug is spread across upload, validation, and save — so file-level sink matching just can't catch it honestly. I dropped it rather than ship noise. CWE-77 I merged into CWE-78 because in Python they fire on the identical set of sinks; keeping them separate was bureaucratic. And a few others I dropped simply to stay within the MITRE Top-25 scope. Knowing what to *exclude* turned out to be as important as what to include.

---

## Slide 13 — Turning point: reading SQL injection by hand

**Bullets**
- Before automating anything, I took **~10 CWE-89 (SQLi) samples** and read every line
- Goal: learn what a *real* sink looks like vs. what merely mentions one
- Found the distinctions that no keyword search captures:
  - `cursor.execute(f"...{x}...")` — vulnerable
  - `cursor.execute("...", params)` — safe (parameterized)
  - `# cursor.execute is dangerous` — a comment, not a sink
  - `re.compile(...)` — matches "compile" but is unrelated

**Speaker notes**
This is my favorite part of the project and, honestly, the most important. Before I wrote a single regex, I sat down with about ten real SQL-injection samples and read the code by hand — line by line — to understand what actually makes them vulnerable. That manual reading is where the real insight came from. I learned that `cursor.execute` with an f-string is the bug, but `cursor.execute` with a parameter tuple is *safe* — same function, opposite security. I saw the sink appear in comments and docstrings, where it's just prose. I saw `re.compile` get caught by a naive "compile" pattern even though it has nothing to do with code injection. None of this is visible from a keyword search. You only learn it by reading. This hand analysis is what every automated pattern downstream is built on.

---

## Slide 14 — From hand-reading to sink patterns

**Bullets**
- The manual read produced a **curated regex set per CWE** (`src/utils/cwe_taxonomy.py`)
- Patterns encode the *dangerous form*, not just the function name
- Refinements that came straight out of reading code:
  - CWE-94: drop bare `compile(` (was catching `re.compile`)
  - CWE-502: `jsonpickle.(decode|loads)` only — `jsonpickle.encode` is safe
  - CWE-79: keep only escape-bypass sinks (`mark_safe`, `|safe`, `render_template_string`)
  - **Global:** strip comments + docstrings before matching

**Speaker notes**
The hand analysis turned into a concrete artifact: a curated set of sink regexes, one group per CWE. But the key is they encode the *dangerous form*. Let me give real examples of fixes that came directly from reading code. For code injection I removed the bare `compile(` pattern because it kept matching `re.compile` — regex compilation, totally benign. For deserialization I narrowed `jsonpickle` to only the decode and loads calls, because `jsonpickle.encode` is the *safe* direction. For XSS I threw out a broad "request plus render" heuristic and kept only the sinks that explicitly bypass auto-escaping. And globally, I strip comments and docstrings first, so a warning *about* `pickle.loads` in a comment doesn't get flagged as a use of it. Every one of these is a lesson from manual reading, encoded.

---

## Slide 15 — Layer 1: the sink-presence filter

**Bullets**
- Rule: a sample labeled CWE *c* survives only if its `code_before` matches a sink pattern for *c*
- Comments/docstrings stripped first; CWE-22 also needs an HTTP request within ±20 lines
- Effect: **1,982 raw → 1,233 samples** (dropped 749 ≈ 38%)
- First cut at noise — *before* anything enters the dataset

**Speaker notes**
The patterns become Layer 1, the first automated gate. The rule is simple: if you claim to be a SQL injection, you'd better contain something that looks like a SQL sink, in dangerous form, in actual code — not a comment. For path traversal I added an extra condition: the file-open sink has to be near an HTTP request, within twenty lines, because otherwise test fixtures with hardcoded paths flood you with false positives. This first filter alone dropped 38% of the raw feed. That's a lot — but as the audit will show, it was nowhere near enough on its own.

---

## Slide 16 — Scraping at scale

**Bullets**
- Sources (with fix commits, so they're diff-validatable):
  - **GHSA Advisory DB** — 384 (local 1.5 GB clone; per-advisory commit fetch)
  - **vudenc** — 209 (pre-labeled tier, no pairs)
  - **CVEfixes** — 58 (local 23 GB SQLite query)
  - **NVD-targeted** — 33 · **OSV/GHSA GraphQL** — 54 · **Canonical hand-written** — 20
- Scope: ~80 Python packages (Flask, Django, FastAPI, Ansible, Transformers, lxml, requests…)

**Speaker notes**
With the patterns in hand, I scraped at scale. The dominant source is the GitHub Security Advisory database — I cloned it locally, about 1.5 gigs, because it indexes advisories *with explicit fix commits and CWE IDs*, which is exactly what I need for per-CWE scraping and diff validation. CVEfixes I queried from a 23-gig local SQLite database. I pulled targeted samples from NVD and OSV, hand-wrote 20 canonical textbook examples for coverage, and kept vudenc as its own tier. The scope is around 80 Python packages across web frameworks, devops tooling, and ML libraries — so the benchmark reflects real, diverse Python, not one ecosystem.

---

## Slide 17 — The sample schema

**Bullets**
- **26 fields per sample** (schema v3.0), e.g.:
  - Identity & provenance: `id`, `source`, `cve_id`, `ghsa_id`, `repo`, `fix_commit`
  - Label: `cwe`, `label_source`, `label_confidence`
  - Code: `code_before`, `code_after`, `sink_pattern`, `framework`
  - Pairing: `pair_id`, `is_hard_negative`, `parent_sample_id`, `sanitization_transform`
  - Management: `split`, `content_hash`, `cvss_*`

**Speaker notes**
Every sample carries 26 fields. I won't read them all, but the design point is that each sample is *self-documenting and auditable*. It records where it came from, which commit fixed it, the exact sink pattern that matched, both the vulnerable and fixed code, and — for negatives — which positive it was derived from and what transformation made it safe. That provenance is what makes the audit and the diff filter possible in the first place. A sample you can't trace, you can't validate.

---

## Slide 18 — A leak-free split

**Bullets**
- Stratified-Group-Shuffle with two hard constraints:
  - **Group by repo** — all samples from one repository stay in one split
  - **Stratify by CWE** — each class appears proportionally in train/val/test
- Final: **610 train / 127 val / 132 test**
- **0 repository leakage** across splits (verified)

**Speaker notes**
Before evaluating anyone, I had to split the data correctly, because the easiest way to get a fake-good result is data leakage. If the same repository shows up in both train and test, a model can just memorize that project's coding style and look brilliant. So I group by repository — an entire repo lands in exactly one split — and I stratify by CWE so a rare class like path traversal doesn't end up entirely in training. The result is a clean 610/127/132 split with zero repo overlap across splits, verified. This is unglamorous but it's the difference between an honest number and a misleading one.

---

## Slide 19 — The validation crisis: first audit failed

**Bullets**
- Layer 2 = adversarial manual audit, 3 independent rounds
- **Round 1: 77 samples, 8 CWEs → 52% false-positive rate**
- Layer 1 filtering alone did **not** fix the label problem
- This was the low point — and the most useful result

**Speaker notes**
Now the hard part, and I want to tell it honestly because the failure is the most instructive part of the whole project. After Layer 1 filtering, I ran a real audit — randomly sampled the surviving "vulnerable" examples and checked each one against the actual code, adversarially, trying to *break* the label. Round one, 77 samples: 52% were false positives. After all that pattern work, the noise rate was essentially unchanged from the raw feed. That was a genuinely demoralizing moment. But it was also the most valuable measurement I made, because instead of guessing, I now had 40 concrete wrong labels to dissect.

---

## Slide 20 — Why it failed: six recurring patterns

**Bullets**
- I clustered the 40 failures into **6 root causes**:
  1. **Sink-too-broad** (15+) — matched framework source / type hints / imports
  2. **Co-changed-file noise** (12+) — sink present but already in *safe* form
  3. **Documentation matches** (8+) — matched comments / docstrings
  4. **Pattern conflation** (3) — `re.compile` → CWE-94
  5. **Inverted operation** (1) — `jsonpickle.encode` → CWE-502
  6. **Wrapper abstraction** (2) — sink hidden in a helper

**Speaker notes**
So I read all 40 failures and asked: *why* is each one wrong? They clustered into six causes. Some I could fix with better patterns — the too-broad matches, the comment matches, the conflations like `re.compile`. But look at cause number two, co-changed-file noise: twelve-plus cases where the sink *is* present but it's already in safe, parameterized form. The file got changed in the fix commit for some *unrelated* reason, and it carried a stale label. No pattern refinement can fix that, because the code looks fine — it *is* fine. That diagnosis is what pointed me at the real solution.

---

## Slide 21 — Round 2: patterns alone weren't enough

**Bullets**
- Tightened 5 sink-pattern groups based on Round 1 failures
- **Round 2: 70 samples → 51% FP** (basically flat)
- Targeted CWEs improved (CWE-502: 40%→20%)…
- …but co-changed-file noise was untouched — it's not a pattern problem

**Speaker notes**
I did the obvious thing first: tightened the five worst pattern groups and re-audited. Round two: 51%. Barely moved. And this is an important lesson — the targeted CWEs *did* improve, deserialization halved — but the aggregate stayed flat because a different failure mode, the co-changed-file noise, was now dominant. I was treating symptoms. The real disease was that "the sink appears in this changed file" is just too weak a signal. I needed to require something stronger.

---

## Slide 22 — The fix: Layer 3, a diff-based filter

**Bullets**
- New rule: a positive is valid only if a **sink line actually changed** between `code_before` and `code_after`
- If every sink line is identical before/after → it's commit-level noise → drop it
- Removed **316 of 738 positives (43%)** — aggressive but principled
- **Round 3: 78 samples → 26% FP** (the aggregate halved)

**Speaker notes**
Here's the insight that fixed it. If a file is *genuinely* the site of a vulnerability, then the fix commit must have *changed the sink line* — that's what fixing it means. So Layer 3 requires exactly that: at least one line containing a sink pattern has to differ between the vulnerable and fixed versions. If every sink line is byte-for-byte identical before and after, the bug was somewhere else and this label is co-changed noise. I drop it. This removed 43% of positives — that's aggressive, and I made the deliberate choice to prefer a smaller clean benchmark over a larger noisy one. The payoff: Round 3 came in at 26%. The diff filter did what no amount of pattern-tuning could.

---

## Slide 23 — The result of validation: 52% → 26%

**Bullets**
| CWE | Round 1 | Round 2 | Round 3 (final) |
|---|---|---|---|
| CWE-502 | 40% | 20% | **0%** |
| CWE-94 | 40% | 50% | **0%** |
| CWE-78 | 20% | 30% | **12%** |
| CWE-22 | 80% | 70% | **27%** |
| CWE-918 | 50% | 70% | **36%** |
| **Aggregate** | **52%** | **51%** | **26%** |

**Speaker notes**
This table is the quantitative payoff of the whole validation effort. Aggregate false-positive rate halved, from 52 to 26 percent — putting the benchmark in the same quality range as hand-curated datasets, and far cleaner than the raw CVE feeds everyone else uses. Look at deserialization and code injection: zero percent false positives in the final audit. Path traversal went from a brutal 80% down to 27% — that was the request-proximity gate plus the diff filter working together. A couple of classes still carry residual noise, and I'll be upfront that some of it comes from the vudenc tier that can't be diff-validated. But the trajectory is the contribution: a repeatable method that measurably cleans inherited labels.

---

## Slide 24 — Building the negatives: minimal pairs

**Bullets**
- For every vulnerable sample, synthesize a **safe twin** by applying the canonical fix
  - `yaml.load` → `yaml.safe_load` · `pickle.loads` → `json.loads`
  - string SQL → parameterized · `os.system` → `subprocess.run(..., shell=False)`
- Same imports, names, control flow — **only the security behavior changes**
- Hard negatives synthesized (not scraped) → isolates the real signal
- ~429 negatives → balanced 869-sample benchmark

**Speaker notes**
A detector that flags everything as vulnerable would score perfectly on a positives-only set, so I need negatives — and not easy ones. For each vulnerable sample I synthesize a *minimal pair*: apply the standard remediation to produce a safe version that's identical in every way *except* the security behavior. Same variable names, same imports, same control flow, just `yaml.load` becomes `yaml.safe_load`. These are deliberately synthesized rather than scraped, because that's the only way to hold everything constant and isolate the one thing that matters. If a detector can tell the twin apart, it's reasoning about the sink; if it can't, it was keying on something irrelevant. That gives the balanced 869-sample benchmark: 440 audited positives, 429 hard negatives.

---

## Slide 25 — Stress-testing for robustness

**Bullets**
- 7 behavior-preserving **mutators** (rewrites that don't change what the code does)
  - Dead-code injection · string-literal splitting · identifier renaming · wrapper extraction
  - Held-out (test-only): `getattr` obfuscation · `__import__` indirection · taint-through-dict
- Question: does a detector survive a trivial rewrite, or was it surface-matching?

**Speaker notes**
The last piece of the benchmark is adversarial robustness. I built seven mutators that rewrite code without changing its behavior — splitting a SQL string into pieces, renaming variables, hiding the sink inside a helper, or routing it through `getattr`. A `SELECT` string split across three concatenations is still the same injection; a human sees that instantly. The question is whether the detector does. I hold three of the nastiest mutators out for test time only, so I'm measuring genuine generalization, not something the model could have adapted to. This is how you distinguish reasoning from pattern-matching.

---

## Slide 26 — Final benchmark composition

**Bullets**
- **869 samples** = **440 audited positives** + **429 synthesized hard negatives**
- 7 sink-shaped CWE classes + a `safe` label
- Per-CWE positives: CWE-89 (213), CWE-502 (75), CWE-79 (54), CWE-94 (35), CWE-78 (26), CWE-918 (22), CWE-22 (15)
- Leak-free 610 / 127 / 132 split · final audited FP ≈ 26%

**Speaker notes**
Putting it together, here's the finished benchmark. 869 samples: 440 positives that survived three layers of validation, and 429 hard negatives that are minimal pairs of those positives. Seven sink-shaped classes plus a safe label. SQL injection is the largest class at 213, reflecting both its real-world prevalence and the strong vudenc agreement; path traversal is the smallest and hardest. Clean leak-free splits, and a documented ~26% residual false-positive rate that I report honestly rather than hide. That transparency is itself part of the contribution.

---

## Slide 27 — Evaluation: who I tested

**Bullets**
- 10 detectors across 3 families, all on the same n=129 clean test set:
  - **Static analyzers:** Bandit, Semgrep, Snyk Code
  - **Frontier LLMs:** Claude Sonnet, GPT-4o, DeepSeek-R1
  - **Fine-tuned model:** GraphCodeBERT
- Each scored on clean code **and** under the held-out mutators
- Metrics: Macro-F1, detection MCC, severity-weighted recall, robustness drop

**Speaker notes**
With the benchmark built, I evaluated ten detectors on equal footing — same clean test set of 129 samples. Three families: classic static analyzers like Bandit and Semgrep, frontier LLMs like Claude Sonnet and DeepSeek-R1, and a fine-tuned code model, GraphCodeBERT. Everyone gets scored two ways: on clean code, and on the adversarially mutated versions, so I can report not just accuracy but how much each tool *degrades* under a behavior-preserving rewrite. I report Macro-F1, Matthews correlation for the binary decision, severity-weighted recall — because missing a critical bug is worse than missing a minor one — and the robustness drop.

---

## Slide 28 — Results

**Bullets**
| Detector | Macro-F1 | Det. MCC | Sev-wtd Recall | Robustness |
|---|---|---|---|---|
| DeepSeek-R1 | **0.596** | 0.410 | 0.691 | +0.003 (stable) |
| Claude Sonnet | 0.585 | 0.117 | **0.903** | −0.013 (stable) |
| GraphCodeBERT | 0.524 | **0.556** | 0.870 | −0.030 |
| Bandit | 0.510 | 0.478 | 0.745 | — |
| GPT-4o | 0.356 | 0.047 | 0.420 | — |
| Semgrep | 0.315 | 0.157 | 0.634 | — |
| Snyk Code | 0.063 | −0.235 | 0.143 | — |

*(n = 129 clean test samples)*

**Speaker notes**
Here are the headline results. A few stories in this table. DeepSeek-R1 and Claude Sonnet lead on F1, around 0.59 — and notice they're *stable* under mutation, which is the good sign: they're reasoning, not surface-matching. Claude Sonnet has the standout severity-weighted recall at 0.90 — it rarely misses a serious bug, though it over-flags, which is why its MCC is lower. GraphCodeBERT, the fine-tuned model, has the best binary decision quality by MCC. Bandit, the free static analyzer, is a genuinely strong baseline — MCC 0.48, beating both frontier LLMs there. And at the bottom, Snyk Code scores below random on this set — a reminder that a commercial price tag doesn't guarantee Python coverage. The big picture: no detector cracks 0.60 F1. Python vulnerability detection is far from solved.

---

## Slide 29 — What I learned: failures and successes

**Bullets**
- **Failures I'll own:**
  - First audit was 52% wrong — patterns alone couldn't fix it
  - CWE-434 had 100% FP → cut it; local 7B models (DeepSeek/Qwen) failed to run usably
  - Claude Opus eval incomplete (n=5) → excluded from headline
- **Successes:**
  - Repeatable method: **52% → 26%** label noise
  - First audit-validated, leak-free, adversarially-tested Python benchmark
  - Evidence that no current detector exceeds ~0.60 F1 — the field is open

**Speaker notes**
Let me close the loop honestly on both sides. The failures: my first audit was a coin-flip, and I had to invent the diff filter to recover. I cut an entire CWE because it was 100% noise. My local 7-billion-parameter models never produced usable predictions, and my Claude Opus run only covered five samples, so I excluded it from the headline rather than report a misleading number. I'd rather show you the holes than paper over them. The successes are real too: a *repeatable* validation method that cut label noise in half, the first Python benchmark that's audit-validated, leak-free, *and* adversarially tested, and a clear empirical finding — nobody's above 0.60 F1, so this is wide-open research territory.

---

## Slide 30 — Conclusion

**Bullets**
- Built an audit-validated Python vulnerability benchmark — 869 samples, 7 CWEs
- Contribution is **method, not just data**: 3-layer validation, 52% → 26% noise
- Detectors leak under adversarial rewrites; static tools remain competitive baselines
- **Next:** extend to structural CWEs, scale positives, AST-level taint for harder classes
- Thank you — questions?

**Speaker notes**
To wrap up. I built a clean, hand-validated benchmark for Python vulnerability detection across seven sink-shaped classes. But the real contribution is the *method* — a three-layer validation pipeline, grounded in reading code by hand, that cut inherited label noise from 52% to 26% and is repeatable on new data. Using it, I showed that today's best detectors top out near 0.60 F1 and that even strong tools have blind spots under trivial rewrites. The natural next steps are tackling the structural CWEs I deferred, growing the positive set, and adding AST-level taint tracking for the harder classes like file upload. Thank you — I'm happy to take questions.

---

## Appendix slides (optional — keep in back pocket for Q&A)

### A1 — Sink pattern examples (live the detail)
- `src/utils/cwe_taxonomy.py` — full per-CWE regex set
- Show CWE-89: f-string/`%`/`.format` into `execute(`; CWE-502: `pickle.loads`, `yaml.load(...)` w/o `SafeLoader`
- **Notes:** Have this ready if a reviewer asks "show me an actual pattern." Open the file live if allowed.

### A2 — The diff filter, concretely
- Show a co-changed-file example: sink line identical before/after → dropped
- **Notes:** This is the most likely deep-dive question. Be ready to walk one real before/after pair.

### A3 — Per-CWE dataset counts + leakage verification
- Full per-class train/val/test breakdown; 0 repo overlap proof
- **Notes:** For the "is it big enough / is it leaking" question.

### A4 — Why minimal-pair negatives, not random safe code
- Random safe code makes the task too easy (different distribution); minimal pairs force true discrimination
- **Notes:** Common methodology challenge — have the justification crisp.
