"""
labeler/stratified_splitter.py — Phase 2 splitter.

Performs a 70/15/15 train/val/test split with two correctness requirements:

  1. **Anti-leakage**: every sample from the same `repo` lands in the
     same split. Without this, the model can memorize repo-specific
     conventions (decorator names, helper-function patterns) that
     appear in both train and test, inflating accuracy by 15–30 F1
     points (PrimeVul / DiverseVul finding).

  2. **Stratification**: each CWE appears in train/val/test in roughly
     the same proportion as the overall dataset. Without this, rare
     CWEs (like CWE-502 with 53 samples) can land entirely in train
     and leave test with zero, making per-class F1 uncomputable.

Algorithm
---------

Stratified-Group-Shuffle in three steps:

  Step 1.  Group samples by ``group_key`` — typically ``repo``. Samples
           without a `repo` field (e.g., VUDENC functions extracted with
           no provenance) get ``group_key = sample["id"]`` so each is
           its own group of size 1, with no leakage risk.

  Step 2.  Compute each group's *dominant CWE* — the most common CWE
           label among the group's samples (typically all samples in a
           repo share a CWE since they were caused by the same fix).

  Step 3.  Shuffle and assign groups to splits while tracking per-CWE
           running counts. A greedy fill: for each shuffled group, pick
           the split whose deficit (target_count − current_count) for
           the group's CWE is highest. This is more accurate than
           sklearn's StratifiedShuffleSplit when group sizes vary
           widely (some repos have 60+ samples, others have 1).

The result satisfies both leakage AND stratification constraints
deterministically given a seed.

Hard negatives
--------------

Hard-negative samples (``is_hard_negative=True``) are co-located with
their parents — if the parent vulnerable sample is in train, its
hard-neg twin is also in train. This is enforced by giving the hard-neg
the same ``group_key`` as its parent (via ``parent_sample_id`` lookup).
A model that sees the parent in test but the hardneg in train would
trivially overfit on the (parent, hardneg) shape pair.
"""

from __future__ import annotations

import random
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from src.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class SplitAssignment:
    """One sample's split assignment."""

    sample_id: str
    split: str        # "train" | "val" | "test"
    cwe: str
    group_key: str


@dataclass
class SplitReport:
    """Full split report for the paper's reproducibility appendix."""

    seed: int
    fractions: dict[str, float]                # train/val/test target ratios
    totals: dict[str, int]                     # train/val/test actual sample counts
    per_cwe: dict[str, dict[str, int]]         # cwe → {train, val, test}
    per_framework: dict[str, dict[str, int]]
    per_source: dict[str, dict[str, int]]
    leakage_check: dict[str, int]              # train_val_repo_overlap, etc.
    n_groups: int                              # how many groups (repos + singletons)
    n_singleton_groups: int                    # how many groups had only 1 sample
    assignments: list[SplitAssignment] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "seed":               self.seed,
            "fractions":          self.fractions,
            "totals":             self.totals,
            "per_cwe":            self.per_cwe,
            "per_framework":      self.per_framework,
            "per_source":         self.per_source,
            "leakage_check":      self.leakage_check,
            "n_groups":           self.n_groups,
            "n_singleton_groups": self.n_singleton_groups,
        }


# ---------------------------------------------------------------------------
# Core splitter
# ---------------------------------------------------------------------------

def stratified_group_split(
    samples: list[dict],
    seed: int = 42,
    train_frac: float = 0.70,
    val_frac: float = 0.15,
    test_frac: float = 0.15,
) -> SplitReport:
    """
    Assign each sample to train/val/test honoring repo-grouping and
    CWE-stratification.

    Each input sample dict must have:
      • ``id``         — sample identifier (str)
      • ``cwe``        — CWE label (str)
      • ``repo``       — repository identifier or None
      • ``framework``  — framework name (used for reporting only)
      • ``source``     — scraper source (used for reporting only)

    Hard-negative co-location is enforced if a sample carries:
      • ``is_hard_negative`` (bool, optional, default False)
      • ``parent_sample_id`` (str, optional)
    """
    if not samples:
        raise ValueError("No samples to split")
    if abs(train_frac + val_frac + test_frac - 1.0) > 1e-6:
        raise ValueError(
            f"Fractions must sum to 1.0; got {train_frac + val_frac + test_frac}"
        )

    # ---- Step 1: Build groups ------------------------------------------------
    # The group key is the parent's group key for hard-negatives, otherwise
    # the sample's own repo (or own id if no repo).
    sample_by_id = {s["id"]: s for s in samples}

    def _group_key(sample: dict) -> str:
        if sample.get("is_hard_negative") and sample.get("parent_sample_id"):
            parent = sample_by_id.get(sample["parent_sample_id"])
            if parent is not None:
                return _group_key(parent)
        repo = sample.get("repo")
        if repo:
            return f"repo::{repo}"
        return f"sample::{sample['id']}"

    sample_groups: dict[str, list[dict]] = defaultdict(list)
    for s in samples:
        sample_groups[_group_key(s)].append(s)

    n_groups = len(sample_groups)
    n_singletons = sum(1 for g in sample_groups.values() if len(g) == 1)
    logger.info(
        f"Built {n_groups} groups from {len(samples)} samples "
        f"({n_singletons} singletons, "
        f"largest group size: {max(len(g) for g in sample_groups.values())})"
    )

    # ---- Step 2: Compute dominant CWE per group ------------------------------
    group_cwe: dict[str, str] = {}
    for gkey, members in sample_groups.items():
        ctr = Counter(m.get("cwe", "unknown") for m in members)
        group_cwe[gkey] = ctr.most_common(1)[0][0]

    # ---- Step 3: Compute target counts per (split, CWE) ----------------------
    cwe_counts = Counter(s.get("cwe", "unknown") for s in samples)
    targets: dict[str, dict[str, int]] = {
        "train": {},
        "val":   {},
        "test":  {},
    }
    for cwe, n in cwe_counts.items():
        targets["train"][cwe] = round(n * train_frac)
        targets["val"][cwe]   = round(n * val_frac)
        # Test gets whatever's left so the rounding error doesn't compound
        targets["test"][cwe]  = n - targets["train"][cwe] - targets["val"][cwe]

    # ---- Step 4: Shuffle groups and greedily fill splits ---------------------
    rng = random.Random(seed)
    shuffled_groups = list(sample_groups.keys())
    rng.shuffle(shuffled_groups)

    # Sort by group size descending — large groups dominate stratification,
    # so place them first when buckets are still empty
    shuffled_groups.sort(key=lambda g: -len(sample_groups[g]))

    current: dict[str, dict[str, int]] = {
        "train": Counter(),
        "val":   Counter(),
        "test":  Counter(),
    }
    group_to_split: dict[str, str] = {}

    for gkey in shuffled_groups:
        members = sample_groups[gkey]
        cwe = group_cwe[gkey]

        # Choose the split with the largest deficit for this CWE
        deficits = {
            split: targets[split].get(cwe, 0) - current[split].get(cwe, 0)
            for split in ("train", "val", "test")
        }
        # Tie-break by preferring train (largest pool) → val → test
        chosen = max(
            ("train", "val", "test"),
            key=lambda s: (deficits[s], {"train": 2, "val": 1, "test": 0}[s]),
        )

        group_to_split[gkey] = chosen
        for m in members:
            current[chosen][m.get("cwe", "unknown")] += 1

    # ---- Step 5: Build the assignment list -----------------------------------
    assignments: list[SplitAssignment] = []
    for gkey, split in group_to_split.items():
        for m in sample_groups[gkey]:
            assignments.append(SplitAssignment(
                sample_id=m["id"],
                split=split,
                cwe=m.get("cwe", "unknown"),
                group_key=gkey,
            ))

    # ---- Step 6: Build the report --------------------------------------------
    totals = {s: sum(current[s].values()) for s in ("train", "val", "test")}

    per_cwe: dict[str, dict[str, int]] = defaultdict(
        lambda: {"train": 0, "val": 0, "test": 0}
    )
    per_framework: dict[str, dict[str, int]] = defaultdict(
        lambda: {"train": 0, "val": 0, "test": 0}
    )
    per_source: dict[str, dict[str, int]] = defaultdict(
        lambda: {"train": 0, "val": 0, "test": 0}
    )
    for sa in assignments:
        sample = sample_by_id[sa.sample_id]
        per_cwe[sa.cwe][sa.split] += 1
        per_framework[sample.get("framework") or "unknown"][sa.split] += 1
        per_source[sample.get("source") or "unknown"][sa.split] += 1

    # ---- Step 7: Leakage check -----------------------------------------------
    # Every group lands in exactly one split → repo overlap should be 0.
    # We verify this explicitly to guard against bugs in the assignment loop.
    repos_per_split: dict[str, set[str]] = {"train": set(), "val": set(), "test": set()}
    for sa in assignments:
        if sa.group_key.startswith("repo::"):
            repos_per_split[sa.split].add(sa.group_key)

    leakage = {
        "train_val_repo_overlap":   len(repos_per_split["train"] & repos_per_split["val"]),
        "train_test_repo_overlap":  len(repos_per_split["train"] & repos_per_split["test"]),
        "val_test_repo_overlap":    len(repos_per_split["val"] & repos_per_split["test"]),
    }

    return SplitReport(
        seed=seed,
        fractions={"train": train_frac, "val": val_frac, "test": test_frac},
        totals=totals,
        per_cwe=dict(per_cwe),
        per_framework=dict(per_framework),
        per_source=dict(per_source),
        leakage_check=leakage,
        n_groups=n_groups,
        n_singleton_groups=n_singletons,
        assignments=assignments,
    )
