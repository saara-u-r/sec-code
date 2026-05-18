"""
red_team/augmenter.py — Online (per-epoch) augmentation for the Phase 3 trainer.

The dataloader calls ``OnlineAugmenter.augment(source, sample_id, epoch)``
during ``__getitem__`` and gets back a (possibly) mutated source string.

Design contract
---------------
1. **Determinism per (sample, epoch).** Same sample seen on the same
   epoch always produces the same mutation, so a re-run of training
   gives identical batches. Different epochs produce different
   mutations — feeds the model fresh adversarial views.

2. **Per-CWE multipliers.** Rare CWEs (CWE-502, CWE-918) need to be
   oversampled. Multipliers are returned as per-sample weights —
   the trainer plugs them into ``torch.utils.data.WeightedRandomSampler``.
   We don't import torch here (keeps the package light); just emit
   weights as a plain list.

3. **Hold-out mutators for test-time evaluation.** One or more mutators
   can be reserved as a *robustness probe* — they're never applied
   during training but are applied to the held-out test set to measure
   how much F1 drops. The standard adversarial-ML setup.

4. **Hard-negative samples are not mutated.** Hard negatives are already
   the result of a deterministic transform (sanitization). Re-mutating
   risks turning a safe sample back into something the model would
   plausibly call vulnerable. The augmenter detects them and short-
   circuits.

5. **No torch dependency.** Plain Python. Phase 3's trainer wraps the
   augmenter and the weights into a torch DataLoader.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from src.red_team.base import Mutator, apply_mutators

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Stable seed derivation (cross-session reproducible)
# ---------------------------------------------------------------------------

def stable_seed(sample_id: str, epoch: int) -> int:
    """
    Return a 32-bit seed deterministic in (sample_id, epoch).

    Uses SHA-256 instead of Python's ``hash()`` because the latter is
    PYTHONHASHSEED-randomized across sessions. We need cross-session
    reproducibility for the paper's appendix.
    """
    h = hashlib.sha256(f"{sample_id}:{epoch}".encode("utf-8")).hexdigest()
    return int(h[:8], 16)


# ---------------------------------------------------------------------------
# AugmentationConfig
# ---------------------------------------------------------------------------

@dataclass
class AugmentationConfig:
    """Knobs controlling augmentation intensity and class re-weighting."""

    # How many mutators to apply per pass (drawn uniformly in this range)
    min_per_pass: int = 1
    max_per_pass: int = 3

    # Whether to format output through `black` after mutation
    format_output: bool = True

    # Rare-class multipliers used by ``compute_sample_weights``.
    # Sample from a CWE not in this dict gets `multipliers["default"]`.
    multipliers: dict[str, float] = field(default_factory=lambda: {
        "CWE-502": 8.0,
        "CWE-918": 4.0,
        "CWE-94":  4.0,
        "CWE-78":  2.0,
        "CWE-22":  1.0,
        "CWE-79":  1.0,
        "CWE-89":  1.0,
        "safe":    1.0,
        "default": 1.0,
    })

    # If True, do not apply mutations to hard-negative samples
    skip_hard_negatives: bool = True

    @classmethod
    def from_json_file(cls, path: str | Path) -> "AugmentationConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            min_per_pass=data.get("min_per_pass", 1),
            max_per_pass=data.get("max_per_pass", 3),
            format_output=data.get("format_output", True),
            multipliers=data.get("multipliers", cls().multipliers),
            skip_hard_negatives=data.get("skip_hard_negatives", True),
        )

    def to_dict(self) -> dict:
        return {
            "min_per_pass":         self.min_per_pass,
            "max_per_pass":         self.max_per_pass,
            "format_output":        self.format_output,
            "multipliers":          self.multipliers,
            "skip_hard_negatives":  self.skip_hard_negatives,
        }


# ---------------------------------------------------------------------------
# OnlineAugmenter
# ---------------------------------------------------------------------------

class OnlineAugmenter:
    """
    Wraps ``apply_mutators`` with stable seeding and skip-rules.

    Usage in a Phase 3 dataset::

        from src.red_team import all_mutators
        from src.red_team.augmenter import OnlineAugmenter, AugmentationConfig
        from src.red_team.mutators.string_split import STRING_SPLITTER

        # Train: use all mutators EXCEPT string_split (held out as a
        # test-time robustness probe)
        train_aug = OnlineAugmenter(
            mutators=[m for m in all_mutators() if m is not STRING_SPLITTER],
            holdout_mutators=[STRING_SPLITTER],
            config=AugmentationConfig(),
        )

        # Inside Dataset.__getitem__:
        source = train_aug.augment(
            source=sample["code_before"],
            sample_id=sample["id"],
            epoch=current_epoch,
            is_hard_negative=sample.get("is_hard_negative", False),
        )
    """

    def __init__(
        self,
        mutators: Sequence[Mutator],
        config: AugmentationConfig | None = None,
        holdout_mutators: Sequence[Mutator] | None = None,
    ):
        self.mutators: list[Mutator] = list(mutators)
        self.holdout_mutators: list[Mutator] = list(holdout_mutators or [])
        self.config = config or AugmentationConfig()

        if not self.mutators:
            logger.warning(
                "OnlineAugmenter created with empty mutator list — augment() "
                "will be a no-op."
            )

        # Defensively avoid overlap: a mutator should not appear in both
        # train and hold-out lists. Holdout wins.
        holdout_names = {m.name for m in self.holdout_mutators}
        self.mutators = [m for m in self.mutators if m.name not in holdout_names]

    # ----- core entry point -------------------------------------------

    def augment(
        self,
        source: str,
        sample_id: str,
        epoch: int = 0,
        is_hard_negative: bool = False,
    ) -> str:
        """
        Return a mutated copy of `source`. May return `source` unchanged
        if skip-rules apply (empty mutator list, hard negative, etc.).
        """
        if not self.mutators:
            return source
        if is_hard_negative and self.config.skip_hard_negatives:
            return source

        seed = stable_seed(sample_id, epoch)
        rng = random.Random(seed)

        out, _results = apply_mutators(
            source,
            mutators=self.mutators,
            rng=rng,
            min_per_pass=self.config.min_per_pass,
            max_per_pass=self.config.max_per_pass,
            format_output=self.config.format_output,
        )
        return out

    # ----- test-time hold-out probe -----------------------------------

    def augment_test(self, source: str, sample_id: str) -> str:
        """
        Apply *only* the held-out mutators. Used at test time to measure
        adversarial robustness. Returns ``source`` unchanged if no
        hold-out mutators are configured.
        """
        if not self.holdout_mutators:
            return source

        seed = stable_seed(sample_id, -1)  # negative epoch → "test" namespace
        rng = random.Random(seed)
        out, _ = apply_mutators(
            source,
            mutators=self.holdout_mutators,
            rng=rng,
            min_per_pass=1,
            max_per_pass=len(self.holdout_mutators),
            format_output=self.config.format_output,
        )
        return out


# ---------------------------------------------------------------------------
# Class-balanced sampling weights (no torch dependency)
# ---------------------------------------------------------------------------

def compute_sample_weights(
    cwes: Sequence[str],
    multipliers: dict[str, float] | AugmentationConfig | None = None,
) -> list[float]:
    """
    Return one weight per sample, suitable for
    ``torch.utils.data.WeightedRandomSampler``.

    Each sample's weight is the multiplier for its CWE, with fallback
    to ``multipliers["default"]`` for unknown labels. Weights are NOT
    normalized — WeightedRandomSampler handles normalization internally.

    Parameters
    ----------
    cwes
        Sequence of CWE labels, one per training sample (in dataset order).
    multipliers
        Either a raw dict, an ``AugmentationConfig``, or None (uses
        ``AugmentationConfig()`` defaults).
    """
    if multipliers is None:
        multipliers = AugmentationConfig().multipliers
    elif isinstance(multipliers, AugmentationConfig):
        multipliers = multipliers.multipliers

    default = multipliers.get("default", 1.0)
    return [float(multipliers.get(cwe, default)) for cwe in cwes]


def expanded_index_list(
    cwes: Sequence[str],
    multipliers: dict[str, float] | AugmentationConfig | None = None,
    seed: int = 0,
) -> list[int]:
    """
    Alternative to WeightedRandomSampler: return a flat list of dataset
    indices where each index is repeated ``multiplier`` times. Useful for
    a simple oversampling scheme that doesn't require torch.

    The output is shuffled with the given seed for batch diversity.
    """
    if multipliers is None:
        multipliers = AugmentationConfig().multipliers
    elif isinstance(multipliers, AugmentationConfig):
        multipliers = multipliers.multipliers

    default = multipliers.get("default", 1.0)
    out: list[int] = []
    for i, cwe in enumerate(cwes):
        repeats = max(1, int(multipliers.get(cwe, default)))
        out.extend([i] * repeats)

    rng = random.Random(seed)
    rng.shuffle(out)
    return out
