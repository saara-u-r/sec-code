#!/usr/bin/env python3
"""
run_phase3_train.py — Phase 3 training entry point.

Reads the four configuration files emitted by Phase 2 / 2b / 2.5:

  • configs/class_weights.json       — LDAM margins + DRW schedule
  • configs/cvss_targets.json        — per-sample CVSS regression targets
  • configs/augmentation_config.json — online mutation hyperparameters
  • data/raw/*.meta.json             — split assignments + sample metadata

Builds the model + datasets + augmenter + Trainer, then runs the
three-phase schedule (SupCon warmup → LDAM Phase A → DRW Phase B) with
SAM-wrapped AdamW.

Usage:
    python scripts/run_phase3_train.py
    python scripts/run_phase3_train.py --warmup-epochs 3 --batch-size 32
    python scripts/run_phase3_train.py --no-sam --backbone microsoft/codebert-base
    python scripts/run_phase3_train.py --device cuda --output-dir runs/exp1
    python scripts/run_phase3_train.py --dry-run        # build everything, don't train

Outputs:
    runs/phase3/best.pt        — best checkpoint (highest val/cwe_macro_f1)
    runs/phase3/last.pt        — final-epoch checkpoint
    runs/phase3/history.json   — per-epoch metrics
    runs/phase3/tb/            — TensorBoard event files (if available)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.model import (  # noqa: E402
    GraphCodeBERTDualTask,
    ModelConfig,
    Trainer,
    TrainerConfig,
    build_dataset,
    load_samples_from_disk,
)
from src.red_team import (  # noqa: E402
    AugmentationConfig,
    OnlineAugmenter,
    all_mutators,
    compute_sample_weights,
)
from src.utils.logger import get_logger  # noqa: E402

logger = get_logger("phase3")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Phase 3 — train the GraphCodeBERT dual-task model"
    )

    # Inputs
    p.add_argument("--raw-dir", default="data/raw",
                   help="Directory of *.meta.json + *.py sample files")
    p.add_argument("--class-weights", default="configs/class_weights.json")
    p.add_argument("--cvss-targets", default="configs/cvss_targets.json")
    p.add_argument("--augmentation-config", default="configs/augmentation_config.json")

    # Model
    p.add_argument("--backbone", default="microsoft/graphcodebert-base")
    p.add_argument("--max-length", type=int, default=512)
    p.add_argument("--heteroscedastic", action="store_true",
                   help="Add (μ, log σ²) head for CVSS regression")
    p.add_argument("--freeze-backbone", action="store_true",
                   help="Train only the heads (ablation)")

    # Schedule (defaults pulled from class_weights.json drw_schedule when None)
    p.add_argument("--warmup-epochs", type=int, default=None)
    p.add_argument("--phase-a-epochs", type=int, default=None)
    p.add_argument("--phase-b-epochs", type=int, default=None)

    # Optimizer
    p.add_argument("--no-sam", action="store_true", help="Disable SAM")
    p.add_argument("--lr", type=float, default=2e-5)
    p.add_argument("--weight-decay", type=float, default=0.01)
    p.add_argument("--sam-rho", type=float, default=0.05)
    p.add_argument("--grad-clip", type=float, default=1.0)

    # Data
    p.add_argument("--batch-size", type=int, default=16)
    p.add_argument("--eval-batch-size", type=int, default=32)
    p.add_argument("--num-workers", type=int, default=0)
    p.add_argument("--no-class-balanced-sampler", action="store_true",
                   help="Disable WeightedRandomSampler in DRW Phase B")

    # Eval / output
    p.add_argument("--val-every", type=int, default=1)
    p.add_argument("--early-stop-patience", type=int, default=5)
    p.add_argument("--output-dir", default="runs/phase3")
    p.add_argument("--no-tensorboard", action="store_true")
    p.add_argument("--seed", type=int, default=42)

    # Augmentation
    p.add_argument("--no-augmentation", action="store_true",
                   help="Disable on-the-fly mutations entirely")

    # Runtime
    p.add_argument("--device", default="cpu",
                   help="cpu / cuda / cuda:0 / mps")
    p.add_argument("--dry-run", action="store_true",
                   help="Build everything, log dataset stats, exit before train()")

    return p.parse_args()


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def build_augmenter(
    config_path: str,
    enabled: bool,
) -> OnlineAugmenter | None:
    """Construct the OnlineAugmenter from a config file. Returns None if
    augmentation is disabled."""
    if not enabled:
        logger.info("Augmentation disabled (--no-augmentation)")
        return None

    cfg = AugmentationConfig.from_json_file(config_path)

    # Read training/holdout mutator names directly from the JSON (not
    # part of AugmentationConfig dataclass)
    raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
    train_names = set(raw.get("training_mutators", []))
    holdout_names = set(raw.get("holdout_mutators", []))

    all_muts = list(all_mutators())
    train_muts = [m for m in all_muts if m.name in train_names] if train_names else all_muts
    holdout_muts = [m for m in all_muts if m.name in holdout_names]

    logger.info(
        f"Augmenter: train={[m.name for m in train_muts]}  "
        f"holdout={[m.name for m in holdout_muts]}"
    )
    return OnlineAugmenter(
        mutators=train_muts,
        config=cfg,
        holdout_mutators=holdout_muts,
    )


def build_tokenizer(backbone: str):
    """Load the HuggingFace tokenizer for the chosen backbone."""
    from transformers import AutoTokenizer
    logger.info(f"Loading tokenizer: {backbone}")
    return AutoTokenizer.from_pretrained(backbone)


def build_trainer_config(args, drw_schedule: dict) -> TrainerConfig:
    """Translate CLI args + class-weights schedule into a TrainerConfig."""
    warmup = args.warmup_epochs if args.warmup_epochs is not None else 0
    phase_a = (
        args.phase_a_epochs if args.phase_a_epochs is not None
        else drw_schedule.get("phase_a_epochs", 8)
    )
    phase_b = (
        args.phase_b_epochs if args.phase_b_epochs is not None
        else drw_schedule.get("phase_b_epochs", 2)
    )

    return TrainerConfig(
        warmup_epochs=warmup,
        phase_a_epochs=phase_a,
        phase_b_epochs=phase_b,
        use_sam=not args.no_sam,
        lr=args.lr,
        weight_decay=args.weight_decay,
        sam_rho=args.sam_rho,
        grad_clip=args.grad_clip,
        batch_size=args.batch_size,
        eval_batch_size=args.eval_batch_size,
        num_workers=args.num_workers,
        use_class_balanced_sampler_in_b=not args.no_class_balanced_sampler,
        val_every=args.val_every,
        early_stop_patience=args.early_stop_patience,
        output_dir=args.output_dir,
        log_to_tensorboard=not args.no_tensorboard,
        seed=args.seed,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = parse_args()
    logger.info("=== Phase 3 — Training ===")

    # ---- Sanity-check inputs exist ----------------------------------------
    for path in (args.class_weights, args.cvss_targets, args.augmentation_config):
        if not Path(path).exists():
            logger.error(f"Missing required config: {path}")
            return 1
    if not Path(args.raw_dir).exists():
        logger.error(f"Missing raw data dir: {args.raw_dir}")
        return 1

    # ---- Load class weights & DRW schedule --------------------------------
    class_weights = json.loads(Path(args.class_weights).read_text(encoding="utf-8"))
    drw = class_weights.get("drw_schedule", {})

    # ---- Augmenter -------------------------------------------------------
    augmenter = build_augmenter(
        args.augmentation_config, enabled=not args.no_augmentation,
    )

    # ---- Tokenizer + datasets -------------------------------------------
    tokenizer = build_tokenizer(args.backbone)
    train_ds = build_dataset(
        raw_dir=args.raw_dir, split="train",
        cvss_targets_path=args.cvss_targets,
        tokenizer=tokenizer, max_length=args.max_length,
        augmenter=augmenter, epoch=0,
    )
    val_ds = build_dataset(
        raw_dir=args.raw_dir, split="val",
        cvss_targets_path=args.cvss_targets,
        tokenizer=tokenizer, max_length=args.max_length,
        augmenter=None,  # never augment val
    )
    logger.info(f"Train samples: {len(train_ds)}  Val samples: {len(val_ds)}")
    if len(train_ds) == 0 or len(val_ds) == 0:
        logger.error(
            "Empty dataset. Run scripts/run_phase2.py to assign splits first."
        )
        return 1

    # ---- Sample weights for Phase B class-balanced sampler ---------------
    train_cwes = [s["cwe"] for s in train_ds.samples]
    sample_weights = (
        compute_sample_weights(train_cwes, AugmentationConfig.from_json_file(
            args.augmentation_config,
        ))
        if not args.no_class_balanced_sampler else None
    )

    # ---- Model -----------------------------------------------------------
    model_cfg = ModelConfig(
        backbone_name=args.backbone,
        heteroscedastic=args.heteroscedastic,
        freeze_backbone=args.freeze_backbone,
    )
    logger.info(f"Building model with backbone={model_cfg.backbone_name}")
    model = GraphCodeBERTDualTask(model_cfg)
    n_params = sum(p.numel() for p in model.parameters())
    n_trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    logger.info(
        f"Model: {n_params/1e6:.2f}M params total ({n_trainable/1e6:.2f}M trainable)"
    )

    # ---- Trainer ---------------------------------------------------------
    trainer_cfg = build_trainer_config(args, drw)
    logger.info(f"Schedule: {trainer_cfg.total_epochs()} epochs total "
                f"(warmup={trainer_cfg.warmup_epochs}, "
                f"A={trainer_cfg.phase_a_epochs}, "
                f"B={trainer_cfg.phase_b_epochs})")

    trainer = Trainer(
        model=model,
        train_dataset=train_ds,
        val_dataset=val_ds,
        class_weights_blob=class_weights,
        config=trainer_cfg,
        device=args.device,
        sample_weights=sample_weights,
    )

    if args.dry_run:
        logger.info("--dry-run: skipping training")
        return 0

    result = trainer.train()
    logger.info(
        f"Training complete: best {trainer_cfg.checkpoint_metric}="
        f"{result['best_metric']:.4f} at epoch {result['best_epoch']}"
    )
    logger.info(f"Best checkpoint: {result['best_ckpt']}")
    logger.info(f"Last checkpoint: {result['last_ckpt']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
