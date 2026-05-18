"""
src/model/trainer.py — Phase 3 training loop.

Implements the three-phase schedule from PHASE2_DESIGN.md §4.5b:

    Phase 0 — Warmup
        Loss   = SupCon (dominant) + CE on CWE (small weight)
        Weights= uniform
        Sampler= random
        Goal   = build a clean embedding space where same-CWE cluster

    Phase A — Backbone training (DRW phase A)
        Loss   = LDAM on CWE + sub-vector CE + (optional) MSE on CVSS
        Weights= uniform (None — natural distribution)
        Sampler= random
        Goal   = let the backbone learn from the natural distribution

    Phase B — Re-weighting (DRW phase B)
        Loss   = LDAM on CWE (with effective-number class weights) + ...
        Weights= effective_number
        Sampler= class-balanced (WeightedRandomSampler) — optional
        Goal   = re-calibrate the classifier head for rare classes

Each phase is configurable via ``TrainerConfig``. Schedule boundaries
default to the values emitted by ``scripts/run_phase2b_configs.py`` into
``configs/class_weights.json``.

Optimization
------------
SAM (Foret et al. 2021) is the default optimizer. SAM doubles per-step
compute (two forward+backwards) but finds flatter minima — particularly
valuable on our 34-sample CWE-502. Disable via ``use_sam=False`` for
ablations.

Gradient clipping (``grad_clip``) and log-variance clamping
(``log_var_clamp``) protect against instability:
  • Grad clip prevents exploding gradients from rare-class minibatches
    after re-weighting kicks in.
  • log_var clamp keeps the heteroscedastic NLL term well-behaved when
    the model briefly predicts σ² ≈ 0 or very large.

Validation
----------
Per-epoch validation computes:
  • CWE macro-F1, per-class F1 (8 classes)
  • Sub-vector accuracy per head (8 heads)
  • CVSS MAE / RMSE on the subset with ground-truth scores
  • Composed CVSS MAE (argmax-composed from sub-vector heads vs. score)

Checkpoint kept = best CWE macro-F1 on val, with early stopping after
``early_stop_patience`` epochs without improvement.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset, WeightedRandomSampler

from src.model.dataset import CWE_TO_INDEX, IGNORE_INDEX, INDEX_TO_CWE, collate_dual_task
from src.model.graphcodebert_dualtask import GraphCodeBERTDualTask, compose_score_from_logits
from src.model.losses import (
    DualTaskLoss,
    DualTaskLossConfig,
    LDAMLoss,
    SupervisedContrastiveLoss,
)
from src.model.sam_optimizer import SAM, make_sam_adamw
from src.utils.logger import get_logger

logger = get_logger("trainer")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class TrainerConfig:
    """Knobs for the training loop. Defaults match PHASE2_DESIGN.md."""

    # ---- Schedule ----
    warmup_epochs:  int = 0    # SupCon-dominant phase (set > 0 to enable)
    phase_a_epochs: int = 8    # LDAM with uniform weights
    phase_b_epochs: int = 2    # LDAM with effective-number weights (DRW)

    # ---- Loss-term coefficients (steady state) ----
    lambda_cwe:           float = 1.0
    lambda_subvec:        float = 0.5
    lambda_score:         float = 0.1
    # SupCon coefficient during warmup (set to 0 outside warmup)
    lambda_supcon_warmup: float = 1.0
    # CWE coefficient during warmup (kept small so SupCon dominates)
    lambda_cwe_warmup:    float = 0.1

    # ---- LDAM ----
    ldam_scale: float = 30.0

    # ---- Optimizer ----
    use_sam:       bool  = True
    lr:            float = 2e-5
    weight_decay:  float = 0.01
    sam_rho:       float = 0.05
    sam_adaptive:  bool  = False
    grad_clip:     float = 1.0          # 0 disables
    log_var_clamp: tuple[float, float] = (-7.0, 7.0)

    # ---- Data ----
    batch_size:                       int  = 16
    eval_batch_size:                  int  = 32
    num_workers:                      int  = 0
    use_class_balanced_sampler_in_b:  bool = True

    # ---- Eval / checkpointing ----
    val_every:           int = 1
    early_stop_patience: int = 5         # 0 disables
    checkpoint_metric:   str = "val/cwe_macro_f1"   # higher-is-better

    # ---- Misc ----
    output_dir:          str  = "runs/phase3"
    log_to_tensorboard:  bool = True
    seed:                int  = 42

    # ---- Internal sanity ----
    def total_epochs(self) -> int:
        return self.warmup_epochs + self.phase_a_epochs + self.phase_b_epochs


# ---------------------------------------------------------------------------
# Helpers — class-weight tensors
# ---------------------------------------------------------------------------

def _weights_in_model_order(weights_dict: dict[str, float]) -> torch.Tensor:
    """
    Translate a dict keyed by CWE name into a [num_cwe_classes] tensor in
    ``INDEX_TO_CWE`` order. Missing keys default to 1.0.
    """
    return torch.tensor(
        [float(weights_dict.get(cwe, 1.0)) for cwe in INDEX_TO_CWE],
        dtype=torch.float32,
    )


def _margins_in_model_order(margins_dict: dict[str, float]) -> torch.Tensor:
    """LDAM margins in model class order. Missing keys default to a small
    baseline so the head still trains."""
    return torch.tensor(
        [float(margins_dict.get(cwe, 0.1)) for cwe in INDEX_TO_CWE],
        dtype=torch.float32,
    )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_cwe_metrics(
    preds: np.ndarray,
    labels: np.ndarray,
) -> dict[str, float]:
    """Macro-F1 + per-class F1 for CWE classification.

    Hand-rolled to avoid sklearn as a hard dependency in this module — but
    if sklearn is available we use it (it handles edge cases more
    robustly).
    """
    try:
        from sklearn.metrics import f1_score
        macro = float(f1_score(labels, preds, average="macro", zero_division=0))
        per_class = f1_score(
            labels, preds, average=None, zero_division=0,
            labels=list(range(len(INDEX_TO_CWE))),
        )
        return {
            "cwe_macro_f1": macro,
            **{f"cwe_f1/{INDEX_TO_CWE[i]}": float(per_class[i])
               for i in range(len(INDEX_TO_CWE))},
        }
    except ImportError:
        # Fallback: per-class F1 by hand
        n_classes = len(INDEX_TO_CWE)
        f1s: list[float] = []
        per_class_log: dict[str, float] = {}
        for c in range(n_classes):
            tp = int(((preds == c) & (labels == c)).sum())
            fp = int(((preds == c) & (labels != c)).sum())
            fn = int(((preds != c) & (labels == c)).sum())
            denom = 2 * tp + fp + fn
            f1 = (2 * tp / denom) if denom > 0 else 0.0
            f1s.append(f1)
            per_class_log[f"cwe_f1/{INDEX_TO_CWE[c]}"] = f1
        return {"cwe_macro_f1": sum(f1s) / n_classes, **per_class_log}


def compute_subvector_metrics(
    preds_per_head: dict[str, np.ndarray],
    labels_per_head: dict[str, np.ndarray],
) -> dict[str, float]:
    """Per-head accuracy on samples whose label != IGNORE_INDEX."""
    out: dict[str, float] = {}
    for key in preds_per_head:
        preds = preds_per_head[key]
        labels = labels_per_head[key]
        mask = labels != IGNORE_INDEX
        if mask.sum() == 0:
            out[f"sub_acc/{key}"] = float("nan")
            continue
        out[f"sub_acc/{key}"] = float((preds[mask] == labels[mask]).mean())
    valid = [v for v in out.values() if not math.isnan(v)]
    out["sub_acc/mean"] = float(np.mean(valid)) if valid else float("nan")
    return out


def compute_cvss_metrics(
    pred_scores: np.ndarray,
    target_scores: np.ndarray,
) -> dict[str, float]:
    """MAE and RMSE over samples with non-NaN target. Returns NaN if none."""
    mask = ~np.isnan(target_scores)
    if mask.sum() == 0:
        return {"cvss_mae": float("nan"), "cvss_rmse": float("nan"), "cvss_n": 0}
    diff = pred_scores[mask] - target_scores[mask]
    return {
        "cvss_mae":  float(np.mean(np.abs(diff))),
        "cvss_rmse": float(np.sqrt(np.mean(diff ** 2))),
        "cvss_n":    int(mask.sum()),
    }


# ---------------------------------------------------------------------------
# Trainer
# ---------------------------------------------------------------------------

class Trainer:
    """End-to-end training loop with the three-phase schedule and SAM."""

    PHASE_WARMUP = "warmup"
    PHASE_A      = "phase_a"
    PHASE_B      = "phase_b"

    def __init__(
        self,
        model: GraphCodeBERTDualTask,
        train_dataset: Dataset,
        val_dataset: Dataset,
        class_weights_blob: dict,
        config: TrainerConfig | None = None,
        device: str | torch.device = "cpu",
        sample_weights: list[float] | None = None,
    ):
        self.model = model
        self.train_dataset = train_dataset
        self.val_dataset = val_dataset
        self.config = config or TrainerConfig()
        self.device = torch.device(device)
        self.class_weights_blob = class_weights_blob
        self.sample_weights = sample_weights

        self.model.to(self.device)

        # ---- Build the LDAM loss + SupCon ahead of time -----------------
        margins = _margins_in_model_order(class_weights_blob.get("ldam_margins", {}))
        self._uniform_weights = _weights_in_model_order(
            class_weights_blob.get("uniform", {}),
        ).to(self.device)
        self._eff_num_weights = _weights_in_model_order(
            class_weights_blob.get("effective_number", {}),
        ).to(self.device)

        self._ldam_uniform = LDAMLoss(
            margins=margins, scale=self.config.ldam_scale,
            class_weights=None,  # uniform = no weighting
        ).to(self.device)
        self._ldam_eff = LDAMLoss(
            margins=margins, scale=self.config.ldam_scale,
            class_weights=self._eff_num_weights,
        ).to(self.device)

        self._supcon = SupervisedContrastiveLoss().to(self.device)

        # ---- Compose the dual-task loss starting in warmup config ------
        loss_cfg = DualTaskLossConfig(
            lambda_cwe=self.config.lambda_cwe,
            lambda_subvec=self.config.lambda_subvec,
            lambda_score=self.config.lambda_score,
            lambda_supcon=0.0,
            ignore_index=IGNORE_INDEX,
        )
        self.loss_fn = DualTaskLoss(
            config=loss_cfg,
            cwe_loss=nn.CrossEntropyLoss(),
            supcon_loss=self._supcon,
        ).to(self.device)

        # ---- Optimizer --------------------------------------------------
        if self.config.use_sam:
            self.optimizer = make_sam_adamw(
                self.model.parameters(),
                lr=self.config.lr,
                weight_decay=self.config.weight_decay,
                rho=self.config.sam_rho,
                adaptive=self.config.sam_adaptive,
            )
        else:
            self.optimizer = torch.optim.AdamW(
                self.model.parameters(),
                lr=self.config.lr,
                weight_decay=self.config.weight_decay,
            )

        # ---- Output dir + tensorboard ----------------------------------
        self.output_dir = Path(self.config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._tb_writer = self._maybe_make_tb_writer()

        # ---- State ------------------------------------------------------
        self.current_phase: str = self.PHASE_WARMUP
        self.global_step: int = 0
        self.best_metric: float = -float("inf")
        self.best_epoch: int = -1
        self.epochs_since_improvement: int = 0
        self.history: list[dict] = []

        torch.manual_seed(self.config.seed)
        np.random.seed(self.config.seed)

    # ---- Setup helpers ----------------------------------------------------

    def _maybe_make_tb_writer(self):
        if not self.config.log_to_tensorboard:
            return None
        try:
            from torch.utils.tensorboard import SummaryWriter
            return SummaryWriter(log_dir=str(self.output_dir / "tb"))
        except Exception as e:
            logger.warning(f"TensorBoard unavailable ({e}); logs go to JSON only")
            return None

    def _make_train_loader(self, phase: str) -> DataLoader:
        sampler = None
        shuffle = True
        if (
            phase == self.PHASE_B
            and self.config.use_class_balanced_sampler_in_b
            and self.sample_weights is not None
        ):
            sampler = WeightedRandomSampler(
                weights=self.sample_weights,
                num_samples=len(self.sample_weights),
                replacement=True,
            )
            shuffle = False  # mutually exclusive with sampler

        return DataLoader(
            self.train_dataset,
            batch_size=self.config.batch_size,
            shuffle=shuffle,
            sampler=sampler,
            num_workers=self.config.num_workers,
            collate_fn=collate_dual_task,
            drop_last=False,
        )

    def _make_val_loader(self) -> DataLoader:
        return DataLoader(
            self.val_dataset,
            batch_size=self.config.eval_batch_size,
            shuffle=False,
            num_workers=self.config.num_workers,
            collate_fn=collate_dual_task,
            drop_last=False,
        )

    # ---- Phase transitions -----------------------------------------------

    def _phase_for_epoch(self, epoch: int) -> str:
        """Return the active phase given a 0-indexed epoch."""
        if epoch < self.config.warmup_epochs:
            return self.PHASE_WARMUP
        if epoch < self.config.warmup_epochs + self.config.phase_a_epochs:
            return self.PHASE_A
        return self.PHASE_B

    def _enter_phase(self, phase: str) -> None:
        """Reconfigure the loss function for the named phase."""
        if phase == self.PHASE_WARMUP:
            self.loss_fn.set_cwe_loss(nn.CrossEntropyLoss())
            self.loss_fn.set_lambda(
                lambda_supcon=self.config.lambda_supcon_warmup,
                lambda_cwe=self.config.lambda_cwe_warmup,
                lambda_subvec=0.0,
                lambda_score=0.0,
            )
        elif phase == self.PHASE_A:
            self.loss_fn.set_cwe_loss(self._ldam_uniform)
            self.loss_fn.set_lambda(
                lambda_supcon=0.0,
                lambda_cwe=self.config.lambda_cwe,
                lambda_subvec=self.config.lambda_subvec,
                lambda_score=self.config.lambda_score,
            )
        elif phase == self.PHASE_B:
            self.loss_fn.set_cwe_loss(self._ldam_eff)
            self.loss_fn.set_lambda(
                lambda_supcon=0.0,
                lambda_cwe=self.config.lambda_cwe,
                lambda_subvec=self.config.lambda_subvec,
                lambda_score=self.config.lambda_score,
            )
        else:
            raise ValueError(f"Unknown phase: {phase!r}")

        self.current_phase = phase
        logger.info(f"Entered phase: {phase}")

    # ---- Forward + loss ---------------------------------------------------

    def _forward_loss(self, batch: dict) -> tuple[torch.Tensor, dict]:
        """Run model forward, clamp log_var, compute composite loss."""
        outputs = self.model(
            input_ids=batch["input_ids"].to(self.device),
            attention_mask=batch["attention_mask"].to(self.device),
        )
        if "cvss_log_var" in outputs:
            lo, hi = self.config.log_var_clamp
            outputs["cvss_log_var"] = outputs["cvss_log_var"].clamp(min=lo, max=hi)

        sub_targets = {
            k: v.to(self.device) for k, v in batch["subvector_labels"].items()
        }
        loss, log = self.loss_fn(
            outputs=outputs,
            cwe_target=batch["cwe_label"].to(self.device),
            subvec_targets=sub_targets,
            cvss_score_target=batch["cvss_score"].to(self.device),
            loss_weight=batch["loss_weight"].to(self.device),
        )
        return loss, log

    # ---- Training step ----------------------------------------------------

    def _train_step(self, batch: dict) -> dict:
        if self.config.use_sam:
            return self._train_step_sam(batch)
        return self._train_step_plain(batch)

    def _train_step_plain(self, batch: dict) -> dict:
        self.optimizer.zero_grad(set_to_none=True)
        loss, log = self._forward_loss(batch)
        loss.backward()
        if self.config.grad_clip > 0:
            torch.nn.utils.clip_grad_norm_(
                self.model.parameters(), self.config.grad_clip,
            )
        self.optimizer.step()
        return log

    def _train_step_sam(self, batch: dict) -> dict:
        # First forward+backward at θ → grad is ∇L(θ)
        self.optimizer.zero_grad(set_to_none=True)
        loss, log = self._forward_loss(batch)
        loss.backward()
        if self.config.grad_clip > 0:
            torch.nn.utils.clip_grad_norm_(
                self.model.parameters(), self.config.grad_clip,
            )
        # type-narrowed: we know optimizer is SAM here
        sam: SAM = self.optimizer  # type: ignore[assignment]
        sam.first_step(zero_grad=True)

        # Second forward+backward at θ' = θ + ε* → grad is ∇L(θ')
        loss2, _ = self._forward_loss(batch)
        loss2.backward()
        if self.config.grad_clip > 0:
            torch.nn.utils.clip_grad_norm_(
                self.model.parameters(), self.config.grad_clip,
            )
        sam.second_step(zero_grad=True)
        return log

    # ---- Train + validate per epoch --------------------------------------

    def _train_epoch(self, epoch: int) -> dict:
        phase = self._phase_for_epoch(epoch)
        if phase != self.current_phase:
            self._enter_phase(phase)

        # Update augmenter epoch on dataset (if it has set_epoch)
        if hasattr(self.train_dataset, "set_epoch"):
            self.train_dataset.set_epoch(epoch)  # type: ignore[union-attr]

        loader = self._make_train_loader(phase)
        self.model.train()

        agg: dict[str, float] = {}
        n_batches = 0
        t0 = time.time()
        for batch in loader:
            log = self._train_step(batch)
            for k, v in log.items():
                agg[k] = agg.get(k, 0.0) + float(v)
            n_batches += 1
            self.global_step += 1

        elapsed = time.time() - t0
        means = {k: v / max(n_batches, 1) for k, v in agg.items()}
        means["epoch_seconds"] = elapsed
        means["batches"] = n_batches
        means["phase"] = phase
        return means

    @torch.no_grad()
    def _validate(self) -> dict:
        self.model.eval()
        loader = self._make_val_loader()

        cwe_preds: list[np.ndarray] = []
        cwe_labels: list[np.ndarray] = []
        sub_preds: dict[str, list[np.ndarray]] = {}
        sub_labels: dict[str, list[np.ndarray]] = {}
        composed_scores: list[np.ndarray] = []
        target_scores: list[np.ndarray] = []
        mu_scores: list[np.ndarray] = []

        for batch in loader:
            outputs = self.model(
                input_ids=batch["input_ids"].to(self.device),
                attention_mask=batch["attention_mask"].to(self.device),
            )

            cwe_logits = outputs["cwe_logits"]
            cwe_preds.append(cwe_logits.argmax(dim=-1).cpu().numpy())
            cwe_labels.append(batch["cwe_label"].numpy())

            for k, logits in outputs["sub_logits"].items():
                sub_preds.setdefault(k, []).append(
                    logits.argmax(dim=-1).cpu().numpy(),
                )
                sub_labels.setdefault(k, []).append(
                    batch["subvector_labels"][k].numpy(),
                )

            # Compose score from sub-vector argmax (deterministic CVSS 3.1)
            composed_scores.append(
                compose_score_from_logits(outputs["sub_logits"]).cpu().numpy(),
            )
            target_scores.append(batch["cvss_score"].numpy())
            if "cvss_mu" in outputs:
                mu_scores.append(outputs["cvss_mu"].cpu().numpy())

        # ---- Aggregate ---------------------------------------------------
        cwe_preds_all  = np.concatenate(cwe_preds)
        cwe_labels_all = np.concatenate(cwe_labels)
        metrics: dict[str, float] = {}
        metrics.update({f"val/{k}": v for k, v in compute_cwe_metrics(
            cwe_preds_all, cwe_labels_all,
        ).items()})

        sub_preds_all  = {k: np.concatenate(v) for k, v in sub_preds.items()}
        sub_labels_all = {k: np.concatenate(v) for k, v in sub_labels.items()}
        metrics.update({f"val/{k}": v for k, v in compute_subvector_metrics(
            sub_preds_all, sub_labels_all,
        ).items()})

        composed_all = np.concatenate(composed_scores)
        targets_all  = np.concatenate(target_scores)
        composed_metrics = compute_cvss_metrics(composed_all, targets_all)
        metrics.update({
            f"val/composed_{k}": v for k, v in composed_metrics.items()
        })

        if mu_scores:
            mu_all = np.concatenate(mu_scores)
            mu_metrics = compute_cvss_metrics(mu_all, targets_all)
            metrics.update({f"val/mu_{k}": v for k, v in mu_metrics.items()})

        return metrics

    # ---- Checkpointing ---------------------------------------------------

    def _save_checkpoint(self, path: Path, epoch: int, metrics: dict) -> None:
        opt_state = (
            self.optimizer.base_optimizer.state_dict()
            if isinstance(self.optimizer, SAM)
            else self.optimizer.state_dict()
        )
        torch.save({
            "model":          self.model.state_dict(),
            "optimizer":      opt_state,
            "epoch":          epoch,
            "metrics":        metrics,
            "config":         asdict(self.config),
            "current_phase":  self.current_phase,
        }, path)

    def load_checkpoint(self, path: str | Path) -> dict:
        """Restore model and optimizer state from a checkpoint."""
        ckpt = torch.load(path, map_location=self.device)
        self.model.load_state_dict(ckpt["model"])
        if isinstance(self.optimizer, SAM):
            self.optimizer.base_optimizer.load_state_dict(ckpt["optimizer"])
        else:
            self.optimizer.load_state_dict(ckpt["optimizer"])
        return ckpt

    # ---- Logging ---------------------------------------------------------

    def _log_metrics(self, metrics: dict, step: int, prefix: str = "") -> None:
        if self._tb_writer is None:
            return
        for k, v in metrics.items():
            if not isinstance(v, (int, float)):
                continue
            if math.isnan(v):
                continue
            tag = f"{prefix}{k}" if prefix else k
            self._tb_writer.add_scalar(tag, v, step)

    # ---- Main entry -------------------------------------------------------

    def train(self) -> dict:
        """Run the full training schedule. Returns the final history dict."""
        total = self.config.total_epochs()
        if total == 0:
            raise ValueError("total_epochs() == 0; nothing to train")

        logger.info(
            f"Starting training: {total} epochs "
            f"(warmup={self.config.warmup_epochs}, "
            f"A={self.config.phase_a_epochs}, "
            f"B={self.config.phase_b_epochs})"
        )

        # Initialize phase before epoch 0 so logs are correct
        self._enter_phase(self._phase_for_epoch(0))

        for epoch in range(total):
            train_log = self._train_epoch(epoch)
            self._log_metrics(train_log, step=epoch, prefix="train/")

            entry: dict[str, Any] = {"epoch": epoch, **{
                f"train/{k}": v for k, v in train_log.items()
            }}

            should_validate = (
                self.config.val_every > 0
                and (epoch % self.config.val_every == 0 or epoch == total - 1)
            )
            if should_validate:
                val_metrics = self._validate()
                self._log_metrics(val_metrics, step=epoch)
                entry.update(val_metrics)

                metric_value = val_metrics.get(self.config.checkpoint_metric)
                if metric_value is not None and metric_value > self.best_metric:
                    self.best_metric = float(metric_value)
                    self.best_epoch = epoch
                    self.epochs_since_improvement = 0
                    self._save_checkpoint(
                        self.output_dir / "best.pt", epoch, val_metrics,
                    )
                    logger.info(
                        f"Epoch {epoch}: new best "
                        f"{self.config.checkpoint_metric}={metric_value:.4f}"
                    )
                else:
                    self.epochs_since_improvement += 1

            self.history.append(entry)
            self._dump_history()

            logger.info(
                f"Epoch {epoch} ({entry.get('train/phase', '?')}): "
                f"loss={entry.get('train/loss/total', float('nan')):.4f}  "
                f"val_macro_f1={entry.get('val/cwe_macro_f1', float('nan')):.4f}  "
                f"({entry.get('train/epoch_seconds', 0):.1f}s)"
            )

            if (
                self.config.early_stop_patience > 0
                and self.epochs_since_improvement >= self.config.early_stop_patience
            ):
                logger.info(
                    f"Early stopping at epoch {epoch}: no improvement in "
                    f"{self.config.early_stop_patience} epochs"
                )
                break

        # Always save a final checkpoint regardless of best
        self._save_checkpoint(
            self.output_dir / "last.pt", epoch, self.history[-1],
        )
        return {
            "history":      self.history,
            "best_metric":  self.best_metric,
            "best_epoch":   self.best_epoch,
            "best_ckpt":    str(self.output_dir / "best.pt"),
            "last_ckpt":    str(self.output_dir / "last.pt"),
        }

    def _dump_history(self) -> None:
        """Persist history to JSON for external monitoring."""
        path = self.output_dir / "history.json"
        try:
            path.write_text(json.dumps(self.history, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Could not write history.json: {e}")
