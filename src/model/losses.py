"""
src/model/losses.py — Loss functions for the Phase 3 dual-task model.

Implements (with citations):

  • SupervisedContrastiveLoss — Khosla et al. 2020 (NeurIPS)
      Used during the warmup phase to learn an embedding space where
      same-CWE samples cluster together. Defeats the "CWE-89 dominates
      the embedding" failure mode of plain cross-entropy on imbalanced
      data.

  • LDAMLoss — Cao et al. 2019 (NeurIPS)
      Label-Distribution-Aware Margin loss. Adds class-specific margins
      to the target-class logit at training time, pushing the decision
      boundary further from rare classes.

  • HeteroscedasticRegressionLoss — Kendall & Gal 2017 (NeurIPS)
      Trains the model to predict both μ and log σ² for the CVSS scalar
      regression target, giving the trainer calibrated uncertainty.

  • DualTaskLoss — composite loss for the full multi-head model
      Combines: (a) CWE classification loss, (b) 8 sub-vector
      classification losses, (c) optional CVSS scalar regression loss,
      (d) optional SupCon loss. Per-sample confidence weighting is
      applied to the CVSS-related terms (so noisy/missing-CVSS samples
      don't dominate gradients while still contributing to CWE training).

Each loss returns a dict of per-term scalars for logging in addition to
the total summed loss.
"""

from __future__ import annotations

from dataclasses import dataclass

import torch
import torch.nn as nn
import torch.nn.functional as F


# ---------------------------------------------------------------------------
# SupCon (Khosla et al. 2020)
# ---------------------------------------------------------------------------

class SupervisedContrastiveLoss(nn.Module):
    """
    Pulls same-class projections together and pushes different-class apart.

    Args:
      temperature: τ in the SupCon paper. 0.07 is the standard value.
    """

    def __init__(self, temperature: float = 0.07):
        super().__init__()
        if temperature <= 0:
            raise ValueError(f"temperature must be > 0, got {temperature}")
        self.temperature = temperature

    def forward(self, features: torch.Tensor, labels: torch.Tensor) -> torch.Tensor:
        """
        features: [B, D] — already L2-normalized projection-head outputs
        labels:   [B]   — class indices (any integer encoding works)

        Returns:
          scalar loss. Returns 0 if no batch contains a positive pair
          (e.g., a degenerate batch where every sample has a unique class).
        """
        B = features.shape[0]
        device = features.device

        if B < 2:
            return torch.tensor(0.0, device=device, requires_grad=True)

        # Cosine similarity matrix (features assumed L2-normalized)
        sim = features @ features.T / self.temperature       # [B, B]

        # Numerical stability: subtract max per row before exp
        sim_max, _ = sim.max(dim=1, keepdim=True)
        sim = sim - sim_max.detach()

        # Mask out self-similarity (diagonal)
        self_mask = torch.eye(B, dtype=torch.bool, device=device)
        sim = sim.masked_fill(self_mask, -1e9)

        # Positives: same label, not self
        labels = labels.view(-1, 1)
        positive_mask = (labels == labels.T).float()
        positive_mask = positive_mask.masked_fill(self_mask, 0.0)

        # log-softmax over the row
        exp_sim = torch.exp(sim)
        log_prob = sim - torch.log(exp_sim.sum(dim=1, keepdim=True) + 1e-12)

        # Mean of log-probs over positives, per anchor
        n_positives = positive_mask.sum(dim=1)               # [B]
        # Avoid div-by-zero — for anchors with no positives, contribute 0
        valid = n_positives > 0
        if valid.sum() == 0:
            return torch.tensor(0.0, device=device, requires_grad=True)

        per_anchor = (positive_mask * log_prob).sum(dim=1)
        # Where valid, divide by n_positives; else, contribute 0
        per_anchor = torch.where(
            valid, per_anchor / n_positives.clamp(min=1), torch.zeros_like(per_anchor)
        )

        loss = -per_anchor[valid].mean()
        return loss


# ---------------------------------------------------------------------------
# LDAM (Cao et al. 2019)
# ---------------------------------------------------------------------------

class LDAMLoss(nn.Module):
    """
    Label-Distribution-Aware Margin Loss.

    Args:
      margins:     [C] tensor of per-class margins. Larger margins push the
                   decision boundary further from that class — good for
                   rare classes.
      scale:       Logit scaling factor (s in the paper). 30.0 is standard.
      class_weights: Optional [C] re-weighting tensor. Use uniform weights
                   in DRW Phase A and the Effective-Number weights in Phase B.

    Forward:
      logits:  [B, C]
      targets: [B]   class indices

    Returns scalar loss.
    """

    def __init__(
        self,
        margins: torch.Tensor,
        scale: float = 30.0,
        class_weights: torch.Tensor | None = None,
    ):
        super().__init__()
        if margins.dim() != 1:
            raise ValueError(f"margins must be 1-D, got shape {margins.shape}")
        # Register as buffer so it moves with the model (.to(device))
        self.register_buffer("margins", margins.float())
        self.scale = scale
        if class_weights is not None:
            self.register_buffer("class_weights", class_weights.float())
        else:
            self.class_weights = None  # type: ignore[assignment]

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        # Build a one-hot mask of the target class
        B, C = logits.shape
        index = torch.zeros_like(logits, dtype=torch.bool)
        index.scatter_(1, targets.view(-1, 1), True)

        # Subtract margin only from the target-class logit
        margins_per_sample = self.margins[targets]           # [B]
        margin_offset = torch.zeros_like(logits)
        margin_offset[index] = margins_per_sample
        logits_modified = logits - margin_offset

        # Apply scale
        logits_modified = self.scale * logits_modified

        return F.cross_entropy(
            logits_modified, targets,
            weight=self.class_weights,
        )


# ---------------------------------------------------------------------------
# Heteroscedastic regression loss (Kendall & Gal 2017)
# ---------------------------------------------------------------------------

class HeteroscedasticRegressionLoss(nn.Module):
    """
    Negative log-likelihood under a Gaussian whose variance is also
    predicted: ``L = (y - μ)² / (2 σ²) + ½ log σ²``.

    For numerical stability we operate on ``log_var = log σ²`` directly:
    ``L = ½ exp(-log_var) (y - μ)² + ½ log_var``.

    Args:
      reduction: "mean" or "none". "none" returns per-sample losses
                 [B] for confidence-weighted aggregation by the caller.
    """

    def __init__(self, reduction: str = "none"):
        super().__init__()
        if reduction not in {"mean", "none"}:
            raise ValueError(f"reduction must be 'mean' or 'none', got {reduction!r}")
        self.reduction = reduction

    def forward(
        self,
        mu: torch.Tensor,
        log_var: torch.Tensor,
        target: torch.Tensor,
    ) -> torch.Tensor:
        per_sample = 0.5 * torch.exp(-log_var) * (target - mu) ** 2 + 0.5 * log_var
        if self.reduction == "mean":
            return per_sample.mean()
        return per_sample


# ---------------------------------------------------------------------------
# Composite dual-task loss
# ---------------------------------------------------------------------------

@dataclass
class DualTaskLossConfig:
    """Knobs for the composite loss."""

    # Per-term coefficients — multiplicative weights on each loss component
    lambda_cwe:        float = 1.0
    lambda_subvec:     float = 0.5
    lambda_score:      float = 0.1
    lambda_supcon:     float = 0.0   # set > 0 only during warmup phase

    ignore_index:      int = -100
    sub_vector_keys:   tuple = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class DualTaskLoss(nn.Module):
    """
    Aggregates (weighted) cross-entropy on the CWE head, cross-entropy on
    the 8 sub-vector heads, optional MSE/heteroscedastic CVSS regression,
    and optional SupCon contrastive loss.

    Confidence weighting (per design doc §5.4): each sample's CVSS-related
    losses are scaled by ``loss_weight ∈ [0, 1]``. Hardneg / unlabeled
    samples can have ``loss_weight=0`` which makes them invisible to the
    CVSS heads while still training the CWE head.

    CWE label is always trusted (CWE labels are high-quality from the
    scrapers), so the CWE head loss does NOT use ``loss_weight``.
    """

    def __init__(
        self,
        config: DualTaskLossConfig | None = None,
        cwe_loss: nn.Module | None = None,
        supcon_loss: nn.Module | None = None,
    ):
        super().__init__()
        self.config = config or DualTaskLossConfig()
        self.cwe_loss = cwe_loss or nn.CrossEntropyLoss()
        self.subvec_loss = nn.CrossEntropyLoss(
            ignore_index=self.config.ignore_index, reduction="none",
        )
        self.supcon_loss = supcon_loss

    def set_cwe_loss(self, cwe_loss: nn.Module) -> None:
        """Swap the CWE loss at runtime (e.g., DRW: CE → LDAM in Phase B)."""
        self.cwe_loss = cwe_loss

    def set_lambda(self, **kwargs) -> None:
        """Adjust loss term coefficients at runtime (e.g., enable SupCon
        only during warmup, then disable it for Phase A/B)."""
        for k, v in kwargs.items():
            if not hasattr(self.config, k):
                raise AttributeError(f"Unknown lambda: {k!r}")
            setattr(self.config, k, v)

    def forward(
        self,
        outputs: dict,
        cwe_target: torch.Tensor,
        subvec_targets: dict[str, torch.Tensor],
        cvss_score_target: torch.Tensor | None = None,
        loss_weight: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, dict[str, float]]:
        """
        Compute the total loss and return (total_loss, per_term_log_dict).

        ``outputs`` is the dict returned by ``GraphCodeBERTDualTask.forward``.
        """
        cfg = self.config
        components: dict[str, torch.Tensor] = {}

        # -- CWE head (always trusted) -----------------------------------
        cwe_logits = outputs["cwe_logits"]
        components["cwe"] = self.cwe_loss(cwe_logits, cwe_target)

        # -- Sub-vector heads (per-sample masked + confidence-weighted) --
        sub_logits = outputs["sub_logits"]
        sub_total = torch.zeros((), device=cwe_logits.device)
        if cfg.lambda_subvec > 0 and sub_logits:
            n_terms = 0
            for key in cfg.sub_vector_keys:
                if key not in sub_logits or key not in subvec_targets:
                    continue
                logits = sub_logits[key]
                target = subvec_targets[key]
                # CrossEntropy with ignore_index=-100 masks out missing
                per_sample = self.subvec_loss(logits, target)         # [B]
                # Apply confidence weights to per-sample losses, but only
                # where the target wasn't IGNORE_INDEX (CE returns 0 there)
                if loss_weight is not None:
                    per_sample = per_sample * loss_weight
                # Average over non-ignored samples (denominator > 0)
                valid_mask = target != cfg.ignore_index
                if valid_mask.any():
                    sub_total = sub_total + per_sample[valid_mask].mean()
                    n_terms += 1
            if n_terms > 0:
                sub_total = sub_total / n_terms
        components["subvec"] = sub_total

        # -- CVSS scalar regression (optional, masked, confidence-weighted)
        score_loss = torch.zeros((), device=cwe_logits.device)
        if (
            cfg.lambda_score > 0
            and cvss_score_target is not None
            and "cvss_mu" in outputs
        ):
            mu = outputs["cvss_mu"]
            target = cvss_score_target
            # NaN means "no target" — mask out
            valid = ~torch.isnan(target)
            if valid.any():
                if "cvss_log_var" in outputs:
                    # Heteroscedastic
                    log_var = outputs["cvss_log_var"]
                    per_sample = (
                        0.5 * torch.exp(-log_var) * (target - mu) ** 2
                        + 0.5 * log_var
                    )
                else:
                    # Plain MSE
                    per_sample = (target - mu) ** 2
                # Replace NaN entries with 0 for safe weighting
                per_sample = torch.where(valid, per_sample, torch.zeros_like(per_sample))
                if loss_weight is not None:
                    per_sample = per_sample * loss_weight
                score_loss = per_sample[valid].mean()
        components["score"] = score_loss

        # -- SupCon (optional, batch-level) -----------------------------
        supcon = torch.zeros((), device=cwe_logits.device)
        if (
            cfg.lambda_supcon > 0
            and self.supcon_loss is not None
            and "supcon_proj" in outputs
        ):
            supcon = self.supcon_loss(outputs["supcon_proj"], cwe_target)
        components["supcon"] = supcon

        # -- Sum --------------------------------------------------------
        total = (
            cfg.lambda_cwe    * components["cwe"]
            + cfg.lambda_subvec * components["subvec"]
            + cfg.lambda_score  * components["score"]
            + cfg.lambda_supcon * components["supcon"]
        )

        log = {
            "loss/total":  total.detach().item(),
            "loss/cwe":    components["cwe"].detach().item(),
            "loss/subvec": components["subvec"].detach().item(),
            "loss/score":  components["score"].detach().item(),
            "loss/supcon": components["supcon"].detach().item(),
        }
        return total, log
