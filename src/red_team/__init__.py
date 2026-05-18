"""
red_team — semantics-preserving code mutators for adversarial robustness
testing of vulnerability detection models. See PHASE2_5_AUGMENTATION_DESIGN.md.
"""

from src.red_team.base import (
    Mutator,
    MutationResult,
    all_mutators,
    apply_mutators,
    get_mutator,
    parse_function_source,
    register,
    unparse_clean,
    validate_round_trip,
)

# Importing this package triggers registration of mutator instances.
from src.red_team import mutators  # noqa: F401

from src.red_team.augmenter import (
    AugmentationConfig,
    OnlineAugmenter,
    compute_sample_weights,
    expanded_index_list,
    stable_seed,
)

__all__ = [
    "AugmentationConfig",
    "Mutator",
    "MutationResult",
    "OnlineAugmenter",
    "all_mutators",
    "apply_mutators",
    "compute_sample_weights",
    "expanded_index_list",
    "get_mutator",
    "parse_function_source",
    "register",
    "stable_seed",
    "unparse_clean",
    "validate_round_trip",
]
