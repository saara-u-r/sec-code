# The Four Mutators — A Plain-English Guide

**Project:** PyVulSev — Python Vulnerability Severity Dataset
**Module:** `src/red_team/mutators/`
**Date:** 2026-05-04

---

## Why this document exists

When you're explaining your project to a thesis committee, professor, or
job interviewer, you want to be able to talk about *why* these mutators
matter without diving into AST internals. This document gives you both
levels — the simple version first, then the technical version.

---

## The Big Picture (in plain English)

### What's the problem we're solving?

Imagine you train a vulnerability-detection model on a million SQL
injection examples. The model gets really good at one thing: spotting
the word "SELECT" right next to the word "execute" in the same function.
Show it a thousand new files — it works great.

Then a real attacker writes:

```python
sql_part_1 = "SEL"
sql_part_2 = "ECT * FROM "
my_query = sql_part_1 + sql_part_2 + "users WHERE id = " + bad_user_input
db_handle.execute(my_query)
```

The runtime SQL is **identical** to the training examples — but the
model fails to flag it because:

* The word "SELECT" never appears as a single token
* The variable isn't called "query", it's called "my_query"
* `execute` isn't on `cursor`, it's on `db_handle`
* The vulnerable string is built across multiple lines

This is what the CASTLE benchmark paper showed: **modern vulnerability
models pattern-match surface tokens, they don't understand security
semantics.** A good attacker (or honestly, any LLM-generated code) will
break them.

### What do the mutators do?

The four mutators are tools that take a vulnerable Python function and
**change how it looks without changing what it does**. We use them to:

1. **Stress-test our model.** If our model still flags a function as
   vulnerable after we mutate it, we've proved it learned semantics. If
   the prediction collapses, we caught a pattern-matcher.
2. **Augment training data.** Each real vulnerable sample becomes
   8–10 mutated copies, fighting the rare-class scarcity problem
   (especially for CWE-502 with only 53 samples).
3. **Generate hard negatives.** With sanitization rules layered on top,
   each vulnerable sample also produces a "safe twin" that looks
   similar but isn't — forcing the model to look at *what* the code
   does, not *how* it looks.

The four mutators target four different "cheats" a lazy model might use:

| Mutator | The cheat it kills | Plain-English summary |
|---|---|---|
| **Dead Code Injection** | "Vulnerabilities live on line 3" | Adds harmless filler lines |
| **String Splitting** | "I'll grep for the word 'SELECT'" | Breaks strings into pieces |
| **Variable Rename** | "If I see `user_id`, it's SQLi" | Renames variables to synonyms |
| **Wrapper Extraction** | "I look at `execute()`, that's it" | Hides calls behind a wrapper function |

---

## Mutator 1 — Dead Code Injection

### What it does (simple)

Sticks pointless lines of code into your function. Lines that do
nothing — like `_unused = 0`, `if False: pass`, or `for _ in range(0):
pass`. The function still runs the same way, just with extra noise
between the real lines.

### Example

**Before:**
```python
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)
```

**After:**
```python
def get_user(user_id):
    _unused_var = sum([])              # ← injected
    query = f"SELECT * FROM users WHERE id = {user_id}"
    if False:                           # ← injected
        pass
    return cursor.execute(query)
```

### What attack on the model does it stop?

A surprising number of models learn things like *"if a string with
`SELECT` is followed by an `execute()` call within 2 lines, predict
SQLi."* By shifting line numbers around with dead code, we break that
positional shortcut. The model has to actually trace the data flow
(does the `query` variable get filled with untrusted input? does it
flow into `execute()`?) instead of relying on "they're close together
on the page."

### Why it helps the project

* **Catches attention-sink bugs.** Modern transformers sometimes assign
  spuriously high attention to specific token positions. Shifting
  everything around shows whether the model's attention is anchored to
  positions or to actual code.
* **Cheap data augmentation.** Each sample becomes many slightly-shifted
  variants — useful for fighting overfitting on the 35-sample CWE-502
  class, where every original sample has to count many times over.
* **The injected code is provably side-effect-free** — `if False: pass`
  is statically unreachable, `_unused_var = 0` only writes a never-read
  name. No risk of accidentally changing the behavior we're testing.

---

## Mutator 2 — String Literal Splitting

### What it does (simple)

Takes a long string in your code, like `"SELECT * FROM users"`, and
breaks it into smaller chunks glued back with `+`:
`"SEL" + "ECT * FROM" + " users"`. Same final string at runtime — but
to a tool that searches the source code for the word "SELECT," that
word has vanished.

### Example

**Before:**
```python
def get_users(uid):
    return cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
```

**After:**
```python
def get_users(uid):
    return cursor.execute(
        "SEL" + "ECT * FROM" + " users WHERE id = " + f"{uid}"
    )
```

The `cursor.execute(...)` still gets the same SQL string when the
function runs — Python just builds it from pieces.

### What attack on the model does it stop?

Many static analysis tools (Bandit, Semgrep, even some ML-based
detectors) match against literal substrings:

* `"SELECT "` → flag as SQL
* `"DELETE FROM "` → flag as SQL
* `"<script>"` → flag as XSS
* `"os.system"` → flag as command injection

After string splitting, *none of those substrings exist as a single
token in the source*. The runtime behavior is byte-identical — but the
surface form has been shattered.

### Why it helps the project

This is **the most important mutator for the CASTLE-paper rebuttal**.
The CASTLE paper explicitly tested this kind of evasion ("can you fool
the detector by simply splitting the string?") and found that most
existing models lose 20–40 F1 points. If our trained model survives
this mutation with only a small F1 drop, we've directly answered the
CASTLE critique — and that's the headline result of our paper.

**Notable subtleties handled correctly:**

* **Docstrings are NOT split** — they're documentation, splitting them
  would mangle `help()` output.
* **Type-hint strings are NOT split** — strings like `"int"` in type
  annotations might be evaluated by tools like `typing.get_type_hints()`.
* **F-string interpolation expressions are NOT split** — only the
  literal text parts (the bits *between* the `{...}` parts) get split.
* **Bytes literals (`b"..."`) are NOT split** — different node type,
  irrelevant to text-based vulnerabilities.

---

## Mutator 3 — Variable Rename

### What it does (simple)

Goes through your function and replaces variable names with their
synonyms. `user` becomes `account`, `query` becomes `sql`, `result`
becomes `outcome`. The function does exactly the same thing — Python
doesn't care what you call your variables — but every identifier that
was `user_id` is now (say) `account_pk`.

### Example

**Before:**
```python
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)
```

**After:**
```python
def get_user(account_pk):
    sql = f"SELECT * FROM users WHERE id = {account_pk}"
    return cursor.execute(sql)
```

### What attack on the model does it stop?

Models trained on labeled data can latch onto *specific identifier
names* as features. If 90% of the SQL injection examples in the
training set use a parameter called `user_id` or `id`, the model can
shortcut: *"see `user_id` flow into `execute()`? predict SQLi."* But a
real attacker (or any reasonable developer) might call that parameter
`pk`, `account_id`, `customer_pk`, or `target_user`. The model's
shortcut breaks.

The mutator forces the model to learn a more general lesson: it's not
the *name* of the variable that matters, it's the *role* — does
untrusted input get interpolated into a SQL string? — regardless of
whether the variable is named `query`, `sql`, `q`, or `raw_sql`.

### Why it helps the project

* **Defeats identifier memorization.** A common failure mode of
  vulnerability classifiers — they learn that `user_input`, `payload`,
  `query` are vulnerability indicators per se, not because of what's
  done with them.
* **Adversarial-realistic.** Real attacker code (or LLM-generated code)
  often uses different naming conventions than your training set. This
  mutator simulates that distribution shift.
* **Works synergistically with Variable Rename's intensity control.**
  Per your guidance, we rename 50–100% of locals each pass. At 50%, you
  get a mild perturbation. At 100%, every renameable name is changed —
  the lexical shock is total, and only a model that's genuinely tracking
  data flow can survive.

**Notable subtleties handled correctly:**

* **Builtins are never renamed** — `len`, `range`, `print`, `eval`, etc.
* **`self` and `cls` are never renamed** — would break OOP code silently.
* **Imported names are never renamed** — `os`, `requests`, etc.
* **Attribute names are never renamed** — `obj.foo`, `cursor.execute`
  (the `execute` part is an attribute access, not a name binding).
* **Names declared `global` or `nonlocal` are never renamed** — would
  break the connection to outer-scope state.
* **Strings containing the variable name are not modified** — the
  substring `"user_id"` inside `"Looking up user_id: 42"` stays as is,
  because strings are data, not code.
* **Nested functions' arguments are not renamed** — they have their own
  scope, mixing up names across scopes would silently change semantics.
* **The function's own name is not renamed** — would break recursive
  calls and external references.

---

## Mutator 4 — Wrapper Extraction

### What it does (simple)

Takes a "vulnerability-relevant" call (like `cursor.execute(query)`) and
hides it inside a tiny helper function defined at the top of your
function. So instead of calling `cursor.execute(query)` directly, your
code now calls `_helper(query)`, and `_helper` is the one that calls
`cursor.execute`.

The vulnerability still executes the same way — just one extra hop.

### Example

**Before:**
```python
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)
```

**After:**
```python
def get_user(user_id):
    def _wrapped_execute_138(*_a, **_kw):
        return cursor.execute(*_a, **_kw)

    query = f"SELECT * FROM users WHERE id = {user_id}"
    return _wrapped_execute_138(query)
```

The `_wrapped_execute_138` function is just a passthrough — it accepts
whatever arguments you give it and forwards them all to
`cursor.execute`. Functionally identical. But to a tool that looks at
the outer function and lists its calls, it now sees a call to
`_wrapped_execute_138`, not `execute`.

### What attack on the model does it stop?

Many models do their analysis at the **single-function level**. They
look at one function, list the dangerous calls inside it (like
`execute`, `eval`, `system`, `pickle.loads`), and decide if the function
is vulnerable. This is fast but shallow.

After wrapper extraction, the dangerous call (`execute`) lives inside
a *nested* function. A model that only looks at the outer function's
call sites will see `_wrapped_execute_138(query)` — a totally innocent-
looking call to a user-defined helper. To find the real vulnerability,
it has to *follow the call into the wrapper*, which requires
**inter-procedural data flow analysis**.

GraphCodeBERT, our chosen architecture, has the ability to do this
because of its data-flow pre-training — but it's not guaranteed. This
mutator tells us whether the model is actually using that capability.

### Why it helps the project

* **The "deepest" robustness test.** This is the single most challenging
  perturbation in the suite. A model that survives this is doing real
  inter-procedural reasoning, not pattern matching.
* **Realistic threat model.** Real codebases have tons of helper
  functions. Production code doesn't call `cursor.execute` directly —
  it calls a `Database.run_query()` method that internally calls
  `cursor.execute`. Our mutator simulates this naturally.
* **Hard for transformer models specifically.** Transformer models often
  struggle with "follow this call to find what it does" because of
  attention's quadratic cost. Including this mutator in our evaluation
  surfaces this weakness if our model has it, so we can address it
  explicitly.

**Notable subtleties handled correctly:**

* **Sink calls are preferred.** When a function has both `len(items)`
  and `cursor.execute(query)`, we wrap `execute` (the security-relevant
  one), not `len`. We have a curated list of 30+ "sink" function names
  spanning all 7 target CWEs (`execute`, `system`, `eval`, `loads`,
  `open`, `get`, `Markup`, etc.).
* **Async-aware.** If the original call is `await db.execute(...)`,
  the wrapper is generated as `async def` with `return await ...`.
* **Correct argument forwarding.** The wrapper uses `*_a, **_kw`
  forwarding — provably semantics-preserving for any call, no matter
  how complex the original arguments (positional, keyword, defaults,
  starred unpacking, etc.).
* **Wrapper name uniqueness.** A random suffix prevents collision with
  any existing local name in the function.
* **Wrapper inserted after docstring.** If the function has a docstring
  at `body[0]`, the wrapper goes at `body[1]` — keeps the docstring
  visible to `help()`.

---

## How the Four Work Together

Each mutator alone tests one specific weakness. **Composed, they test
robustness across every common shortcut** a lazy classifier might take.

A real call to the pipeline looks like this:

```python
from src.red_team import apply_mutators
from src.red_team.mutators.dead_code import DEAD_CODE_INJECTOR
from src.red_team.mutators.string_split import STRING_SPLITTER
from src.red_team.mutators.variable_rename import VARIABLE_RENAMER
from src.red_team.mutators.wrapper_extraction import WRAPPER_EXTRACTOR

mutated_source, results = apply_mutators(
    source,
    mutators=[DEAD_CODE_INJECTOR, STRING_SPLITTER,
              VARIABLE_RENAMER, WRAPPER_EXTRACTOR],
    rng=random.Random(epoch_seed + sample_id),
    min_per_pass=2,
    max_per_pass=3,
)
```

* **Per your guidance**, the pipeline picks 2–3 mutators randomly per
  pass (not all 4 at once — that risks "over-mangling").
* The order of application is randomized per pass.
* Same seed → same output (reproducibility for the paper's appendix).

### End-to-end example

**Original (vulnerable to SQL injection):**
```python
def fetch_user_orders(user_id, limit):
    """Get the most recent orders for a user."""
    query = f"SELECT id, total FROM orders WHERE user_id = {user_id} LIMIT {limit}"
    rows = cursor.execute(query)
    return rows
```

**After all 4 mutators:**
```python
def fetch_user_orders(user_id, ceil):
    """Get the most recent orders for a user."""

    def _wrapped_execute_138(*_a, **_kw):       # ← wrapper extraction
        return cursor.execute(*_a, **_kw)

    query = (                                   # ← string split
        "SELECT "
        + "id, total FROM or"
        + "ders WHERE use"
        + "r_id = "
        + f"{user_id}"
        + " LIMI"
        + "T "
        + f"{ceil}"                              # ← variable rename: limit → ceil
    )
    records = _wrapped_execute_138(query)        # ← rename: rows → records
    if 0:                                        # ← dead code
        pass
    return records
```

A pattern-matching SAST tool will:
* Not find `"SELECT id"` (split)
* Not find `"WHERE user_id"` (split)
* Not find a call to `cursor.execute` in the visible body (wrapper)
* Not find a parameter named `limit` (renamed)

A model trained with proper data flow analysis will still flag this
correctly, because the `f-string` interpolation of untrusted parameters
into a string passed to `_wrapped_execute_138 → cursor.execute` is
preserved.

**This single example, run through the paper's evaluation framework,
becomes the headline empirical result.**

---

## How They Help the Project — A Summary Table

| Goal | Which mutator(s) help | How |
|---|---|---|
| Answer the CASTLE critique | All 4, especially string_split | Prove the model isn't pattern-matching |
| Augment rare CWE classes | All 4 | Each CWE-502 sample → 8 mutated variants |
| Generate hard negatives | All 4 + sanitization | Mutate, then sanitize to make safe twins |
| Test inter-procedural reasoning | wrapper_extraction | Forces the model to follow calls |
| Test positional independence | dead_code_injection | Shifts line numbers without semantic change |
| Test surface-form independence | string_split | Removes literal substrings from source |
| Test identifier independence | variable_rename | Removes specific variable names |
| Reproducibility for paper appendix | All 4 | Seeded RNG, deterministic output |

---

## How They Help in the Paper

The four mutators give us a **dedicated section in the experimental
evaluation** of the paper. Specifically:

### Section 6.3 — Robustness Evaluation

Run the trained model on three test sets:

1. **Standard test set** — held-out real samples
2. **Mutated test set** — same samples after a randomized 2-mutator pass
3. **Hard-negative test set** — sanitized versions of vulnerable samples

Report F1 on all three. The success criterion (drawn from the CASTLE
paper) is:

> A model that pattern-matches loses 20–40 F1 points on the mutated
> test set. A model that does proper semantic reasoning loses ≤ 3
> F1 points.

If our model loses ≤ 3 F1 points across all 4 mutator types, **that's
the headline result** of the paper. It's a direct empirical answer to
the CASTLE critique that motivated this entire project.

### Section 6.4 — Augmentation Ablation

Train the same model architecture three times:

1. On 2,929 real samples only (baseline)
2. On 2,929 real + 4,600 mutated samples (with augmentation)
3. On 2,929 real + 4,600 mutated + 1,170 hard negatives (full pipeline)

Report macro-F1 and per-class F1 (especially CWE-502). Each row should
beat the previous one — that's the augmentation ablation table.

---

## What Got Built — Final Inventory

```
src/red_team/
├── __init__.py                 # Public API
├── base.py                     # Mutator Protocol, MutationResult, pipeline (~190 lines)
├── mutators/
│   ├── __init__.py             # Registry hub
│   ├── dead_code.py            # M2 — ~110 lines
│   ├── string_split.py         # M3 — ~210 lines
│   ├── variable_rename.py      # M1 — ~280 lines
│   └── wrapper_extraction.py   # M4 — ~230 lines

tests/red_team/
├── __init__.py
├── conftest.py                 # Shared fixtures: synthetic + 50 real-world samples
├── test_base.py                # 13 tests — pipeline / parse / unparse
├── test_dead_code.py           # 18 tests
├── test_string_split.py        # 21 tests
├── test_variable_rename.py     # 34 tests
└── test_wrapper_extraction.py  # 29 tests
```

**Total: ~1,020 lines of mutator code, ~1,200 lines of tests, 115 tests
passing, 0 failing.**

The infrastructure is ready to be used by:

* **Phase 2.5 hard negative miner** — uses `apply_mutators` to generate
  paired safe-twin samples
* **Phase 3 dataloader** — calls `apply_mutators` on-the-fly per epoch
  to inflate training data
* **Phase 6 robustness evaluation** — runs all 4 mutators against the
  test set to measure adversarial F1 drop

---

## In One Sentence

> The four mutators take a vulnerable Python function and produce
> visually-different but semantically-identical versions, letting us
> stress-test our model and prove it learned security semantics rather
> than surface patterns — which is exactly the empirical result our
> Q1 paper needs to be publishable.
