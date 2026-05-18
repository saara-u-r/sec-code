"""
src.model — Phase 3 model architecture and PyTorch Dataset.

Public API:
  • GraphCodeBERTDualTask, ModelConfig — the dual-task model
  • DualTaskDataset, build_dataset, collate_dual_task — data pipeline
  • CWE_TO_INDEX, INDEX_TO_CWE, SUBVECTOR_CODE_TO_INDEX — label mappings
"""

from src.model.dataset import (
    CWE_TO_INDEX,
    INDEX_TO_CWE,
    IGNORE_INDEX,
    SUBVECTOR_CODE_TO_INDEX,
    DualTaskDataset,
    build_dataset,
    collate_dual_task,
    load_cvss_targets,
    load_samples_from_disk,
    per_split_stats,
)
from src.model.graphcodebert_dualtask import (
    SUBVECTOR_HEAD_CONFIG,
    GraphCodeBERTDualTask,
    ModelConfig,
    build_model,
    compose_score_from_logits,
)
from src.model.losses import (
    DualTaskLoss,
    DualTaskLossConfig,
    HeteroscedasticRegressionLoss,
    LDAMLoss,
    SupervisedContrastiveLoss,
)
from src.model.sam_optimizer import SAM, make_sam_adamw
from src.model.trainer import (
    Trainer,
    TrainerConfig,
    compute_cvss_metrics,
    compute_cwe_metrics,
    compute_subvector_metrics,
)

__all__ = [
    "CWE_TO_INDEX",
    "DualTaskDataset",
    "DualTaskLoss",
    "DualTaskLossConfig",
    "GraphCodeBERTDualTask",
    "HeteroscedasticRegressionLoss",
    "IGNORE_INDEX",
    "INDEX_TO_CWE",
    "LDAMLoss",
    "ModelConfig",
    "SAM",
    "SUBVECTOR_CODE_TO_INDEX",
    "SUBVECTOR_HEAD_CONFIG",
    "SupervisedContrastiveLoss",
    "Trainer",
    "TrainerConfig",
    "build_dataset",
    "build_model",
    "collate_dual_task",
    "compose_score_from_logits",
    "compute_cvss_metrics",
    "compute_cwe_metrics",
    "compute_subvector_metrics",
    "load_cvss_targets",
    "load_samples_from_disk",
    "make_sam_adamw",
    "per_split_stats",
]
