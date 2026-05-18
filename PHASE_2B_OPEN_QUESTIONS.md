# Phase 2B — open questions to resolve tomorrow

**Date created:** 2026-05-11
**Status:** Local Phase 2B work paused mid-session. One decision blocks Day 4 training.

---

## The CWE-330 quality issue (BLOCKING)

The `weak_random_miner` (Move 3) added **128 CWE-330 samples** to the dataset in one run. Spot-checking 2 random samples revealed both were **false positives**:

### Spot-check #1 — `openstack/swift/swift/obj/replicator.py`

```python
146:    self.ring_check_interval = float(conf.get('ring_check_interval', 15))
147:    self.next_check = time.time() + self.ring_check_interval
148:    self.replication_cycle = random.randint(0, 9)        ← matched
149:    self.partition_times = []
```

Verdict: **not CWE-330.** `random.randint` is being used for replication-cycle jitter (a scheduling concern, not a security one). The file contains the word "auth" elsewhere, which is what passed the security-context check — but the `random.randint` call has nothing to do with that.

### Spot-check #2 — `apache/superset/superset/utils/mock_data.py`

```python
69:  ) -> Callable[[], Any]:
70:      if isinstance(sqltype, sqlalchemy.dialects.mysql.types.TINYINT):
71:          return lambda: random.choice([0, 1])  # noqa: S311      ← matched
72:
73:      if isinstance(
```

Verdict: **not CWE-330.** This is **mock-data generation**, and the developer literally wrote `# noqa: S311` to suppress the weak-randomness linter rule — meaning they explicitly marked this as a non-issue. Yet it still matched our filter.

### Root cause

`has_cwe_sink('CWE-330', ...)` currently does:

1. Does the file contain `random.(random|choice|randint|...)\\s*\\(`? → yes
2. Does the file contain ANY of `auth|password|token|session|...` ANYWHERE in the file? → yes

The file-presence check is too coarse. A 500-line file might call `random.choice` for non-security reasons in one function and have `auth` mentioned 200 lines away in a separate function. The two are unrelated.

### Two paths forward

**Path A — Roll back and tighten the filter (recommended, ~20 min)**

1. Move all 128 `weak_random_*` samples to `data/raw_rejected/`. Cleanly reversible via the existing manifest pattern.
2. Modify `file_utils.has_cwe_sink` so CWE-330 (and possibly CWE-798, by symmetry) require the security-context keyword **within ±10 lines** of the sink call, not just "somewhere in the file."
3. Re-run `weak_random_miner` with the line-proximity filter.
4. Expected yield: 5–20 high-precision samples instead of 128 low-precision ones.

**Path B — Accept and document (~5 min)**

1. Keep the 128 as-is.
2. Document in `PHASE_2B_RESULTS.md` that CWE-330 mining has ~50–70% FP rate and the model's per-class F1 on this class is not directly comparable to the CVE-confirmed classes.
3. Move on to training.

### Recommendation

**Path A.** The audit you applied to CWE-94 / CWE-502 / CWE-798 has been the strongest methodology contribution of this work — your committee will respect precision-over-recall every time. Shipping 128 noisy CWE-330 samples after the careful audit pattern you set on the other classes would be inconsistent with that story.

The trade-off — having ~10 verified CWE-330 samples instead of 128 noisy ones — is worth it for the writeup integrity.

### Implementation sketch for Path A

In `src/utils/file_utils.py`, add a helper `has_security_context_near(code, line_no, window=10)` that checks the security keyword only in lines `[line_no - window, line_no + window]`. Then in `has_cwe_sink`, after finding the sink match, compute its line number and call the proximity-bound check instead of the file-wide one.

```python
def has_security_context_near(code: str, sink_line_no: int, window: int = 10) -> bool:
    lines = code.splitlines()
    start = max(0, sink_line_no - window - 1)
    end   = min(len(lines), sink_line_no + window)
    context_block = "\n".join(lines[start:end])
    return bool(_SECURITY_CONTEXT.search(context_block))
```

Then in `has_cwe_sink`:

```python
if cwe in CWES_REQUIRING_SECURITY_CONTEXT:
    line_no = code[:matched_pos].count("\n") + 1
    if not has_security_context_near(code, line_no):
        return False, None
```

This changes the check from "file mentions security keyword" → "the function/block around the sink mentions security keyword." Much higher precision.

Apply the same proximity rule to CWE-798 by symmetry. Audit the existing 35 CWE-798 samples afterward — most should still pass since they're config-file style with the keyword on the same line.

---

## Other open items (lower priority)

1. **Move 2 results.** `nvd_targeted` rerun (broader Python heuristic) was still running when the session ended. Check `logs/phase2b_nvd_rerun_*.log` tomorrow morning for final counts. Expected: +CWE-918, +CWE-611, +CWE-77, +CWE-400 samples (the broader heuristic admitted 2–10x more Python-relevant CVEs).

2. **CWE-78 stays at 16.** Underrepresented. Could add a CWE-78 targeted scrape (specific to `subprocess.Popen(shell=True)` patterns) but probably not worth the effort given the existing 16 are CVE-confirmed.

3. **`runs/phase3_v4/` not yet trained.** Day 4 work — on the V100 box.

4. **Field justification document** (`FIELD_JUSTIFICATION.md`) untouched. Purely a writing task; should be done while Day 4 training runs.

---

## Quick-start for tomorrow

```bash
# 1. Check Move 2 final results
tail -50 logs/phase2b_nvd_rerun_*.log

# 2. Run final dataset audit
source .venv/bin/activate
python3 -c "
from collections import Counter
from src.model.dataset import load_samples_from_disk
s = load_samples_from_disk('data/raw', apply_sink_filter=True)
c = Counter(x['cwe'] for x in s)
for cwe in sorted(c): print(f'{cwe}: {c[cwe]}')
"

# 3. Decide Path A or Path B for CWE-330. If Path A:
#    - implement has_security_context_near in src/utils/file_utils.py
#    - move existing weak_random_*.py to data/raw_rejected/ via a new manifest
#    - re-run: python scripts/run_generator.py --sources weak_random

# 4. After CWE-330 decision, run the per-CVE cap + split:
python scripts/build_split.py --apply

# 5. Update PHASE_2B_RESULTS.md with final per-CWE counts and splits.

# 6. Sync to the V100 box and run phase3_v4 training (Day 4).
```
