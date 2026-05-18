# Phase 2.5 — Hard Negative Mining and Targeted Augmentation: Design Document

**Project:** PyVulSev — Python Vulnerability Severity Dataset
**Date:** 2026-05-04
**Phase:** 2.5 (between Phase 2 dataset prep and Phase 3 model training)
**Status:** Design — implementation pending approval

---

## 0. Document Purpose

Phase 2 prepares the dataset for training. Phase 3 trains the model.
This document specifies an intermediate phase whose purpose is to **make
the dataset itself a stronger training signal** by adding two new sample
types:

1. **Hard negatives** — code that *looks* vulnerable (uses the same
   risky API) but is actually safe due to proper sanitization. Forces
   the model to learn semantic patterns instead of surface keywords.
2. **Targeted augmentations** — semantics-preserving mutations applied
   aggressively to under-represented CWE classes (especially CWE-502 with
   53 samples) to inflate the effective training set without synthesizing
   labels.

Phase 2.5 is what turns this from "an empirical model trained on what
exists" into "a model trained on what *needs* to be learned" — the
single most defensible methodology contribution we can add.

---

## 1. Why This Phase Exists

### 1.1 The CASTLE Critique

The CASTLE benchmark (Dubniczky et al. 2025, arXiv:2503.09433) — which
was the original motivation for this whole project — found that current
vulnerability detection models are **pattern-matching, not understanding**.
Their evidence:

- A model that flags `os.system(user_input)` as CWE-78 will *also* flag
  `os.system(shlex.quote(user_input))` as CWE-78, even though the second
  is properly sanitized
- Performance drops 20–40 F1 points when vulnerable patterns are wrapped
  in safe-but-similar surface forms
- The models have learned "if substring `os.system(` appears, predict
  CWE-78" rather than "if untrusted input flows into a shell call without
  sanitization, predict CWE-78"

If our model has the same failure mode, **the CASTLE-addressing claim in
our motivation report collapses.** Reviewers at TDSC will absolutely run
this test.

### 1.2 Hard Negative Mining Is The Antidote

A hard negative is a sample that:
- Contains the same risky API as a vulnerable sample
- Has been transformed by adding canonical sanitization
- Is therefore actually safe and should be classified as `CWE-other` /
  not vulnerable

Training on hard negatives forces the model to look at **how** the API
is called, not **whether** it appears. This is the core methodological
contribution of Phase 2.5.

### 1.3 The CWE-502 Data Scarcity Reality

After exhausting NVD, ghsa_db, cvefixes, osv, and pypa for CWE-502, we
have **53 unique vulnerable Python deserialization samples**. This is a
data-source ceiling, not an engineering bottleneck — the global supply
of GitHub-attributable Python deserialization CVEs is roughly this size.

Augmentation is the standard methodology for this exact problem. Done
correctly, it inflates effective training count by 5–10× without
introducing label noise. Done poorly, it teaches the model to memorize
mutated patterns. Section 3 of this document specifies the mutations
that have been shown empirically to preserve semantics.

---

## 2. Hard Negative Mining

### 2.1 Generation Strategy

For each vulnerable sample, we apply a **canonical sanitization
transform** to produce a paired safe version. The transform depends on
the CWE:

| CWE | Vulnerable pattern | Sanitization transform |
|---|---|---|
| CWE-89 (SQLi) | `cursor.execute(f"SELECT * FROM x WHERE id = {uid}")` | `cursor.execute("SELECT * FROM x WHERE id = ?", (uid,))` |
| CWE-78 (Cmd Injection) | `os.system(f"ping {host}")` | `subprocess.run(["ping", host], shell=False, check=True)` |
| CWE-22 (Path Traversal) | `open(os.path.join(BASE, user_path))` | `open(os.path.join(BASE, secure_filename(user_path)))` (with `..` rejection) |
| CWE-79 (XSS) | `Markup(user_input)` | `escape(user_input)` |
| CWE-94 (Code Injection) | `eval(expr)` | `ast.literal_eval(expr)` (or refuse) |
| CWE-918 (SSRF) | `requests.get(user_url)` | `requests.get(user_url)` after URL-allowlist check |
| CWE-502 (Deserialization) | `pickle.loads(blob)` | `json.loads(blob)` (or `pickle.loads` after HMAC verify) |

Each transform is **deterministic** and **well-documented in the Python
security literature** (Bandit, Semgrep, OWASP cheat sheets). The
sanitization is not invented; it is the canonical fix.

### 2.2 Implementation

For each rule, an AST-based transformer:

1. Parses the original `code_before` (the vulnerable version)
2. Locates the vulnerable AST node (e.g., `Call(func=Attribute(value=Name(id='os'), attr='system'), args=[FormattedValue(...)])`)
3. Replaces it with the sanitized form
4. Validates the transformed code parses cleanly
5. Saves as a **new sample** with:
   - `code_before` = the sanitized code
   - `cwe` = `"CWE-other"` (or a new label `"safe"` — see Section 5)
   - `is_vulnerable` = `False`
   - `pair_id` = original sample's `pair_id` + `"_hardneg"`
   - `source` = `"hardneg_<original_source>"`
   - `parent_sample_id` = original sample's `id` (for traceability)

### 2.3 Quality Controls

Not every vulnerable sample yields a useful hard negative. Filters:

- **AST-parseable both before and after the transform.** Drop if either fails.
- **Transformation actually changed the code.** If our regex/AST rule
  didn't match, skip.
- **Sanitized code does not still contain another vulnerable pattern.**
  Don't generate "fixed SQLi" code that still has an `eval(...)` elsewhere.
- **Length sanity.** Sanitized sample length within ±20% of original.

### 2.4 Expected Yield

Conservative estimate: **30–50% of vulnerable samples generate a usable
hard negative** (some have non-trivial control flow that our deterministic
transforms can't safely modify). For our 2,929 vulnerable samples → 880
to 1,460 hard negatives.

This roughly **doubles the dataset size** with samples that test exactly
the property we care about: "did the model learn semantics, or just
syntax?"

### 2.5 Per-CWE Yield Targets

| CWE | Vulnerable count | Estimated hard-neg yield (40%) |
|---|---:|---:|
| CWE-89 | 1,219 | 487 |
| CWE-79 | 534 | 213 |
| CWE-22 | 510 | 204 |
| CWE-78 | 269 | 107 |
| CWE-918 | 189 | 75 |
| CWE-94 | 155 | 62 |
| **CWE-502** | **53** | **21** |
| **Total** | **2,929** | **~1,170** |

---

## 3. Targeted Augmentation (Mutation-Based)

### 3.1 Mutation Types

Each mutation is a **semantics-preserving** transformation. We use four
canonical types, all with strong precedent in the code-augmentation
literature (Yefet et al. 2020, Yu et al. 2022, Patra & Pradel 2021):

#### M1 — Variable Rename

Replace user-defined identifiers with semantically-equivalent alternatives:

```python
# Before
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)

# After
def fetch_account(account_pk):
    raw_sql = f"SELECT * FROM users WHERE id = {account_pk}"
    return cursor.execute(raw_sql)
```

**Implementation:** AST traversal renames `Name` and `arg` nodes whose
ID is locally defined. Built-ins, library identifiers, and literals are
preserved. Renames are drawn from a curated synonym dictionary
(`get→fetch→retrieve`, `user→account→customer`, etc.).

**Vulnerability preservation:** Variable rename is provably semantics-
preserving — the AST evaluation is identical.

#### M2 — Dead Code Injection

Insert syntactically valid, side-effect-free code into the function body
at random points outside the vulnerable line:

```python
# Before
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)

# After
def get_user(user_id):
    _unused = sum(range(0))         # <-- injected
    if False:                        # <-- injected
        log("never reached")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)
```

**Why this matters:** Tests whether the model relies on token *position*
or actual *data flow*. A model that trips up here is pattern-matching.

#### M3 — String Literal Splitting

Concatenate string literals from multiple parts:

```python
# Before
query = f"SELECT * FROM users WHERE id = {user_id}"

# After
query = "SELECT" + " * FROM users " + f"WHERE id = {user_id}"
```

**Why this matters:** Many vulnerability scanners pattern-match on the
literal string `"SELECT * FROM"`. String splitting evades surface-level
matching while preserving the runtime SQL.

#### M4 — Wrapper Function Extraction

Wrap the vulnerable call in an inline-defined function:

```python
# Before
return cursor.execute(query)

# After
def _execute_inner(q):
    return cursor.execute(q)
return _execute_inner(query)
```

**Why this matters:** Tests cross-function data-flow tracking. A model
that loses the vulnerability after this transform is doing single-
function pattern matching.

### 3.2 Per-CWE Multipliers (Targeted Augmentation)

The augmentation budget is **proportional to class scarcity**:

```json
{
  "rare_class_multipliers": {
    "CWE-502": 8,
    "CWE-918": 4,
    "CWE-94":  4,
    "CWE-78":  2,
    "CWE-22":  1,
    "CWE-79":  1,
    "CWE-89":  1
  },
  "mutations_per_pass": [
    "variable_rename",
    "dead_code_injection",
    "string_split",
    "wrapper_extraction"
  ]
}
```

Each pass applies **all four mutation types** (composed in random order)
to produce one augmented sample. The multiplier is the number of passes
per original sample.

### 3.3 Expected Yield After Augmentation

Combining hard negatives + augmentations:

| CWE | Real | Hard-neg | Aug | **Effective Total** |
|---|---:|---:|---:|---:|
| CWE-89 | 1,219 | 487 | 1,219 | 2,925 |
| CWE-79 | 534 | 213 | 534 | 1,281 |
| CWE-22 | 510 | 204 | 510 | 1,224 |
| CWE-78 | 269 | 107 | 538 | 914 |
| CWE-918 | 189 | 75 | 756 | 1,020 |
| CWE-94 | 155 | 62 | 620 | 837 |
| **CWE-502** | **53** | **21** | **424** | **498** |
| **Total** | **2,929** | **~1,170** | **~4,600** | **~8,700** |

**The CWE-502 row is the headline:** 53 → 498 effective samples.
Imbalance ratio drops from 23× to 6×. This is what makes per-class F1
on CWE-502 a credible reportable result.

### 3.4 Augmentation Hygiene

To prevent the model from "memorizing the mutator":

1. **Apply augmentations on-the-fly each epoch**, not pre-baked into
   MongoDB. Each epoch sees a different mutation.
2. **Fix the random seed per-sample-per-epoch** for reproducibility, but
   vary across epochs.
3. **Hold one mutation type out as a test-time augmentation control.**
   E.g., never apply M3 (string splitting) during training; use it at
   test time to measure robustness to surface-form variation. This
   becomes the "robustness evaluation" in Section 6 of the paper.
4. **Cap total augmented count per sample at 10** — beyond that, samples
   become near-duplicates of each other.

---

## 4. Training Pipeline Integration

Phase 2.5 outputs are consumed by Phase 3 as follows:

```
                    Phase 2 split (real samples)
                              │
                ┌─────────────┼─────────────┐
                ▼             ▼             ▼
           train (1,805)   val (387)    test (387)
                │
                ▼
       ┌──────────────────────────────┐
       │  Phase 2.5: Pre-generate     │
       │  hard negatives offline      │
       │  (deterministic AST transforms)
       └──────────┬───────────────────┘
                  │
                  ▼
        train_with_negatives (1,805 + 720 hardneg)
                  │
                  ▼
       ┌──────────────────────────────┐
       │  Phase 3 dataloader:         │
       │  • on-the-fly mutations      │
       │  • per-CWE multipliers       │
       │  • epoch-deterministic seeds │
       └──────────┬───────────────────┘
                  │
                  ▼
              GraphCodeBERT
              dual-task model
```

**Important:** hard negatives are pre-generated offline (deterministic
sanitization), but mutations happen online (need diversity per epoch).
This is the same split that ContraCode (Jain 2021) and CodeRetriever
(Li 2022) use, which is the standard.

---

## 5. Schema Additions

The MongoDB document schema gets three new optional fields:

```python
{
  ... existing 21 fields ...,
  "is_hard_negative": false,             # default; set True for hardneg samples
  "parent_sample_id": null,              # source sample if is_hard_negative=True
  "sanitization_transform": null,        # e.g. "f_string_to_parameterized" for hardneg
}
```

For **augmented** samples we do NOT add new MongoDB documents — they
exist only at training time inside the dataloader. This keeps the
persistent dataset size bounded and reproducible.

The CWE label for hard negatives uses the existing schema:
- `cwe` = `"CWE-other"` (already present in `data_prep.LABEL_MAP`)
- `is_vulnerable` = `False`

---

## 6. Files to Create

```
src/red_team/
  ├── __init__.py
  ├── sanitization_rules.py     # CWE → AST transform mapping
  ├── hard_negative_miner.py    # offline batch generator
  ├── mutators/
  │   ├── __init__.py
  │   ├── variable_rename.py
  │   ├── dead_code.py
  │   ├── string_split.py
  │   └── wrapper_extraction.py
  └── augmenter.py              # online dataloader integration

scripts/
  └── run_phase2_5.py           # CLI: generate hard negatives, write to Mongo

configs/
  ├── augmentation_config.json  # per-CWE multipliers, mutation types
  └── sanitization_rules.json   # the CWE→transform mapping (data, not code)

data/
  └── phase2_5_report.json      # hard-neg yield per CWE, mutation stats
```

---

## 7. Implementation Plan

### 7.1 Sequencing

1. **Implement the four mutators first** (~2 days)
   - Each is independently testable on synthetic functions
   - Unit tests verify AST equivalence (after mutation, parse + execute
     produces same output for safe inputs)

2. **Implement sanitization rules** (~2 days)
   - One rule per CWE
   - Test on a few hand-picked vulnerable samples per CWE first
   - Then run on full dataset and inspect output quality manually

3. **Generate hard negatives** (~1 hour runtime)
   - Run `scripts/run_phase2_5.py` on training split only
   - Manually spot-check 20 samples per CWE
   - Save to MongoDB with `is_hard_negative=True`

4. **Integrate online augmenter into Phase 3 dataloader** (~1 day)
   - Hook into `__getitem__` of the training Dataset class
   - Apply mutations based on per-CWE multiplier
   - Add seed control for reproducibility

### 7.2 Manual Quality Review

This is the **single most important** part. Bad mutations / bad
sanitizations silently corrupt training data.

**For each CWE, manually review:**
- 10 vulnerable → hard-negative pairs (verify the sanitization is
  semantically correct and removes the vulnerability)
- 10 augmented samples (verify they parse, run, and preserve the
  vulnerable behavior)

If any rule produces broken output more than 20% of the time, fix the
rule before using its output for training.

### 7.3 Validation Tests

Phase 2.5 ships with an automated test suite:

```python
# tests/test_phase2_5/

def test_sql_sanitization_removes_fstring():
    """Hard negative for SQLi must not contain f-string in execute()."""
    ...

def test_variable_rename_preserves_ast_structure():
    """After rename, AST node count must match (modulo Name nodes)."""
    ...

def test_dead_code_does_not_change_function_output():
    """Function called with same args produces same output before/after."""
    ...

def test_no_double_vulnerabilities_in_hardneg():
    """Sanitized SQLi sample must not contain eval/exec/os.system."""
    ...

def test_cwe502_yield_at_least_15():
    """We need ≥ 15 hard negatives for CWE-502 for the test split to be useful."""
    ...
```

CI runs these tests on every commit — broken mutations get caught early.

---

## 8. What the Paper Will Report

### 8.1 Tables

**Hard Negative Mining Yield (Table 4 in paper):**

| CWE | Vulnerable | Hard-Neg Generated | Yield Rate | Manual Pass Rate |
|---|---:|---:|---:|---:|
| CWE-89 | 1,219 | — | — | — |
| ... | | | | |

**Augmentation Multipliers (Table 5):**

| CWE | Real | × Multiplier | = Effective | Imbalance Ratio (vs CWE-89) |
|---|---:|---:|---:|---:|
| CWE-89 | 1,219 | 1× | 1,219 | 1.0 |
| CWE-502 | 53 | 8× | 424 | 2.9 |

### 8.2 Robustness Evaluation (Section 6.3 in paper)

Run the trained model on three test sets:

1. **Standard test set** — held-out real samples
2. **Hard-negative test set** — sanitized versions of training samples
3. **Mutated test set** — held-out mutation type (e.g., string splits)

Report F1 on all three. If F1 drops sharply on (2) or (3), the model is
pattern-matching. **A small drop (≤ 3 F1 points) is the success
criterion** — that's what proves the model learned semantics.

This single experiment is the strongest answer to the CASTLE critique
and likely the most-cited result in our paper.

---

## 9. Phase 2.5 Deliverables

After Phase 2.5 completes, the following must exist:

- ✅ MongoDB has all hard negatives marked with `is_hard_negative=True`
  and proper `parent_sample_id` linkage
- ✅ `configs/augmentation_config.json` with per-CWE multipliers
- ✅ `configs/sanitization_rules.json` with CWE → transform mapping
- ✅ `data/phase2_5_report.json` with yield statistics
- ✅ Mutator unit test suite passing in CI
- ✅ Manual quality review log (`data/phase2_5_quality_log.md`)

---

## 10. Open Questions for Discussion

1. **Hard negatives in val/test or train only?**
   Recommend train only. Putting hard negatives in val/test would inflate
   numbers (they're algorithmically generated; the model learns the
   generator). Use a separate held-out hand-curated test set if we want
   to evaluate on hard negatives.

2. **Mutation diversity vs reproducibility tension.**
   On-the-fly mutations are more diverse but harder to reproduce.
   Recommend per-(sample, epoch) deterministic seed → diverse across
   epochs, exactly reproducible across runs.

3. **Augmentation budget for Phase 2.5 development.**
   Estimated 5–7 days of focused work. Worth it for the methodology
   contribution; not optional for a Q1 paper.

4. **Should hard negatives have their own CWE label `"safe"` instead of
   collapsing to `"CWE-other"`?**
   Recommend a new label `"safe"` to distinguish "no vulnerability we
   target" from "explicitly sanitized version of a target CWE." This
   gives the classifier a clearer training signal.

---

**End of Phase 2.5 design document. Awaiting approval to begin
implementation.**
