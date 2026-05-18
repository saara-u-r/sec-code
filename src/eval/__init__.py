"""Evaluation harness — benchmark SAST tools and LLMs against the labeled
test set and its adversarial mutator variants.

Public surface:
  TARGET_CWES               the 7 sink-shaped CWE classes under test
  VARIANTS                  the 6 test-set variants (clean + 4 mutators + composed)
  EvalSample, load_variant  test-sample loading
  Detector, BanditDetector, SemgrepDetector
  PredictionRecord, score_variant, robustness_drop
"""

from src.eval.cwe_map import TARGET_CWES
from src.eval.samples import VARIANTS, EvalSample, load_variant
from src.eval.scoring import (
    PredictionRecord,
    macro_f1,
    robustness_drop,
    score_variant,
)

__all__ = [
    "TARGET_CWES",
    "VARIANTS",
    "EvalSample",
    "load_variant",
    "PredictionRecord",
    "macro_f1",
    "robustness_drop",
    "score_variant",
]
