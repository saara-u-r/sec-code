"""
test_losses.py — tests for SupCon, LDAM, heteroscedastic regression,
and the composite DualTaskLoss.
"""

from __future__ import annotations

import math

import pytest
import torch
import torch.nn.functional as F

from src.model.losses import (
    DualTaskLoss,
    DualTaskLossConfig,
    HeteroscedasticRegressionLoss,
    LDAMLoss,
    SupervisedContrastiveLoss,
)


# ---------------------------------------------------------------------------
# SupervisedContrastiveLoss
# ---------------------------------------------------------------------------

class TestSupCon:

    def test_rejects_non_positive_temperature(self):
        with pytest.raises(ValueError):
            SupervisedContrastiveLoss(temperature=0.0)
        with pytest.raises(ValueError):
            SupervisedContrastiveLoss(temperature=-0.1)

    def test_zero_loss_when_batch_too_small(self):
        loss = SupervisedContrastiveLoss()
        feats = torch.randn(1, 16)
        feats = F.normalize(feats, dim=-1)
        out = loss(feats, torch.tensor([0]))
        assert out.item() == 0.0

    def test_zero_loss_when_no_positives(self):
        """All samples have unique classes → no positive pairs → 0."""
        loss = SupervisedContrastiveLoss()
        feats = F.normalize(torch.randn(4, 16), dim=-1)
        labels = torch.tensor([0, 1, 2, 3])
        out = loss(feats, labels)
        assert out.item() == 0.0

    def test_finite_loss_with_positives(self):
        loss = SupervisedContrastiveLoss()
        feats = F.normalize(torch.randn(8, 16), dim=-1)
        labels = torch.tensor([0, 0, 1, 1, 2, 2, 0, 1])
        out = loss(feats, labels)
        assert torch.isfinite(out)
        assert out.item() >= 0.0

    def test_perfectly_clustered_features_give_lower_loss_than_anti_clustered(self):
        """Comparison: perfectly-clustered same-class vs deliberately
        anti-aligned same-class (positives orthogonal to anchor).

        The clustered case must produce strictly lower loss — this is the
        property that makes SupCon useful as a representation objective.
        """
        loss = SupervisedContrastiveLoss(temperature=0.07)

        # Clustered: same class → identical feature
        c1 = torch.tensor([1.0, 0.0, 0.0])
        c2 = torch.tensor([0.0, 1.0, 0.0])
        clustered = F.normalize(torch.stack([c1, c1, c1, c2, c2, c2]), dim=-1)
        labels = torch.tensor([0, 0, 0, 1, 1, 1])
        l_clustered = loss(clustered, labels).item()

        # Anti-clustered: each "same-class" pair is orthogonal (similarity=0
        # vs negatives that are also orthogonal — no signal at all)
        # Actually for a stricter contrast, make positives ANTI-aligned
        # (similarity = -1) and negatives near 0.
        anti = torch.tensor([
            [ 1.0,  0.0,  0.0],
            [-1.0,  0.0,  0.0],
            [ 1.0,  0.0,  0.0],
            [ 0.0,  1.0,  0.0],
            [ 0.0, -1.0,  0.0],
            [ 0.0,  1.0,  0.0],
        ])
        anti = F.normalize(anti, dim=-1)
        l_anti = loss(anti, labels).item()

        assert l_clustered < l_anti

    def test_random_features_give_higher_loss_than_clustered(self):
        same_class_loss = SupervisedContrastiveLoss(temperature=0.07)
        c1 = torch.tensor([1.0, 0.0, 0.0])
        c2 = torch.tensor([0.0, 1.0, 0.0])
        clustered = F.normalize(torch.stack([c1, c1, c2, c2]), dim=-1)
        labels = torch.tensor([0, 0, 1, 1])
        l_clustered = same_class_loss(clustered, labels)

        torch.manual_seed(42)
        random_feats = F.normalize(torch.randn(4, 3), dim=-1)
        l_random = same_class_loss(random_feats, labels)

        assert l_random.item() > l_clustered.item()

    def test_gradient_flows(self):
        """Gradients must flow through the loss back to the underlying
        leaf tensor (which lives upstream of the F.normalize)."""
        loss = SupervisedContrastiveLoss()
        # Make the LEAF require grad, then normalize as a non-leaf op
        raw = torch.randn(4, 8, requires_grad=True)
        feats = F.normalize(raw, dim=-1)
        labels = torch.tensor([0, 0, 1, 1])
        out = loss(feats, labels)
        out.backward()
        assert raw.grad is not None
        assert raw.grad.abs().sum().item() > 0


# ---------------------------------------------------------------------------
# LDAMLoss
# ---------------------------------------------------------------------------

class TestLDAM:

    def test_rejects_2d_margins(self):
        with pytest.raises(ValueError):
            LDAMLoss(margins=torch.zeros(3, 3))

    def test_zero_margins_recovers_scaled_cross_entropy(self):
        """With margins=0, LDAM = CrossEntropy on (scale * logits)."""
        margins = torch.zeros(3)
        ldam = LDAMLoss(margins=margins, scale=1.0)
        logits = torch.randn(4, 3)
        targets = torch.tensor([0, 1, 2, 0])
        out_ldam = ldam(logits, targets)
        out_ce = F.cross_entropy(logits, targets)
        assert torch.allclose(out_ldam, out_ce, atol=1e-5)

    def test_larger_margin_increases_loss_on_target(self):
        """Bigger margin on target class → more loss (model has to be more
        confident to overcome the margin)."""
        logits = torch.tensor([[2.0, 1.0, 0.5]])
        targets = torch.tensor([0])

        small = LDAMLoss(margins=torch.tensor([0.0, 0.0, 0.0]), scale=1.0)
        large = LDAMLoss(margins=torch.tensor([1.0, 0.0, 0.0]), scale=1.0)

        l_small = small(logits, targets)
        l_large = large(logits, targets)
        assert l_large.item() > l_small.item()

    def test_class_weights_applied(self):
        """Per-class re-weighting should produce a different loss than uniform."""
        logits = torch.tensor([[2.0, 1.0], [0.5, 1.5]])
        targets = torch.tensor([0, 1])
        margins = torch.tensor([0.1, 0.1])

        unweighted = LDAMLoss(margins=margins, scale=1.0)
        weighted = LDAMLoss(
            margins=margins, scale=1.0,
            class_weights=torch.tensor([1.0, 5.0]),
        )
        l1 = unweighted(logits, targets)
        l2 = weighted(logits, targets)
        assert l1.item() != l2.item()

    def test_gradient_flows(self):
        margins = torch.tensor([0.1, 0.2, 0.3])
        ldam = LDAMLoss(margins=margins, scale=1.0)
        logits = torch.randn(4, 3, requires_grad=True)
        targets = torch.tensor([0, 1, 2, 0])
        out = ldam(logits, targets)
        out.backward()
        assert logits.grad is not None


# ---------------------------------------------------------------------------
# HeteroscedasticRegressionLoss
# ---------------------------------------------------------------------------

class TestHeteroscedastic:

    def test_rejects_invalid_reduction(self):
        with pytest.raises(ValueError):
            HeteroscedasticRegressionLoss(reduction="bogus")

    def test_low_variance_high_error_high_loss(self):
        """When σ² is small but error is large, loss is large."""
        loss = HeteroscedasticRegressionLoss(reduction="mean")
        target = torch.tensor([5.0])
        mu = torch.tensor([2.0])  # error = 3
        log_var_low = torch.tensor([math.log(0.01)])  # σ² = 0.01
        log_var_high = torch.tensor([math.log(10.0)])  # σ² = 10

        l_low_var = loss(mu, log_var_low, target)
        l_high_var = loss(mu, log_var_high, target)
        # With high error, low variance is heavily penalized
        assert l_low_var.item() > l_high_var.item()

    def test_no_error_log_var_zero_optimum(self):
        """At μ=target and log σ²=0 (σ=1), loss is just 0.5·log(1) = 0."""
        loss = HeteroscedasticRegressionLoss(reduction="mean")
        target = torch.tensor([1.0, 2.0, 3.0])
        mu = target.clone()
        log_var = torch.zeros(3)
        out = loss(mu, log_var, target)
        assert torch.allclose(out, torch.zeros(()), atol=1e-6)

    def test_per_sample_reduction(self):
        loss = HeteroscedasticRegressionLoss(reduction="none")
        target = torch.tensor([1.0, 2.0, 3.0])
        mu = torch.tensor([1.5, 1.5, 3.5])
        log_var = torch.zeros(3)
        out = loss(mu, log_var, target)
        assert out.shape == (3,)


# ---------------------------------------------------------------------------
# DualTaskLoss
# ---------------------------------------------------------------------------

class TestDualTaskLoss:

    def _make_outputs(self, B=4, num_cwe=8, supcon_dim=128, with_score=True):
        sub_logits = {
            "AV": torch.randn(B, 4),
            "AC": torch.randn(B, 2),
            "PR": torch.randn(B, 3),
            "UI": torch.randn(B, 2),
            "S":  torch.randn(B, 2),
            "C":  torch.randn(B, 3),
            "I":  torch.randn(B, 3),
            "A":  torch.randn(B, 3),
        }
        # Make outputs require grad so the test can differentiate
        for k, v in sub_logits.items():
            v.requires_grad_(True)
        cwe_logits = torch.randn(B, num_cwe, requires_grad=True)
        supcon_proj = F.normalize(torch.randn(B, supcon_dim, requires_grad=True), dim=-1)
        out = {
            "cwe_logits":  cwe_logits,
            "sub_logits":  sub_logits,
            "supcon_proj": supcon_proj,
        }
        if with_score:
            out["cvss_mu"] = torch.randn(B, requires_grad=True)
            out["cvss_log_var"] = torch.zeros(B, requires_grad=True)
        return out

    def _make_targets(self, B=4):
        return {
            "cwe": torch.randint(0, 8, (B,)),
            "sub": {
                "AV": torch.randint(0, 4, (B,)),
                "AC": torch.randint(0, 2, (B,)),
                "PR": torch.randint(0, 3, (B,)),
                "UI": torch.randint(0, 2, (B,)),
                "S":  torch.randint(0, 2, (B,)),
                "C":  torch.randint(0, 3, (B,)),
                "I":  torch.randint(0, 3, (B,)),
                "A":  torch.randint(0, 3, (B,)),
            },
        }

    def test_basic_forward_returns_total_and_components(self):
        loss = DualTaskLoss()
        out = self._make_outputs()
        targets = self._make_targets()
        score = torch.tensor([5.0, 7.5, 3.2, 9.1])
        weights = torch.tensor([1.0, 1.0, 0.3, 1.0])

        total, log = loss(out, targets["cwe"], targets["sub"], score, weights)
        assert torch.isfinite(total)
        for k in ("loss/total", "loss/cwe", "loss/subvec", "loss/score", "loss/supcon"):
            assert k in log

    def test_lambda_zero_disables_component(self):
        cfg = DualTaskLossConfig(
            lambda_cwe=1.0, lambda_subvec=0.0, lambda_score=0.0, lambda_supcon=0.0,
        )
        loss = DualTaskLoss(config=cfg)
        out = self._make_outputs()
        targets = self._make_targets()
        score = torch.tensor([5.0, 7.5, 3.2, 9.1])
        total, log = loss(out, targets["cwe"], targets["sub"], score, None)

        # Total should equal cwe (others zeroed by lambda)
        assert math.isclose(log["loss/total"], log["loss/cwe"], rel_tol=1e-5)

    def test_supcon_only_active_when_lambda_set(self):
        cfg_off = DualTaskLossConfig(lambda_supcon=0.0)
        cfg_on  = DualTaskLossConfig(lambda_supcon=1.0)
        loss_off = DualTaskLoss(
            config=cfg_off, supcon_loss=SupervisedContrastiveLoss(),
        )
        loss_on = DualTaskLoss(
            config=cfg_on, supcon_loss=SupervisedContrastiveLoss(),
        )
        out = self._make_outputs()
        targets = self._make_targets()
        score = torch.tensor([5.0] * 4)

        _, log_off = loss_off(out, targets["cwe"], targets["sub"], score, None)
        _, log_on  = loss_on(out, targets["cwe"], targets["sub"], score, None)
        # Supcon component is computed in both, but only weighted in the second
        assert log_on["loss/total"] != log_off["loss/total"]

    def test_subvec_ignore_index_skipped(self):
        """Sub-vector targets set to IGNORE_INDEX should not contribute to loss."""
        loss = DualTaskLoss()
        out = self._make_outputs()
        targets = self._make_targets()
        # Set all AV/AC/PR/UI/S/C/I/A targets to ignore
        for k in targets["sub"]:
            targets["sub"][k] = torch.full((4,), -100, dtype=torch.long)
        score = torch.tensor([float("nan")] * 4)  # disable score loss

        total, log = loss(out, targets["cwe"], targets["sub"], score, None)
        # subvec loss should be zero (no valid samples)
        assert log["loss/subvec"] == 0.0

    def test_score_nan_skipped(self):
        """NaN CVSS targets should be masked out of the regression loss."""
        loss = DualTaskLoss()
        out = self._make_outputs()
        targets = self._make_targets()
        score = torch.tensor([float("nan")] * 4)
        total, log = loss(out, targets["cwe"], targets["sub"], score, None)
        assert log["loss/score"] == 0.0

    def test_loss_weight_scales_score_term(self):
        loss = DualTaskLoss()
        out = self._make_outputs()
        targets = self._make_targets()
        score = torch.tensor([5.0, 7.5, 3.2, 9.1])

        weights_full = torch.ones(4)
        weights_zero = torch.zeros(4)
        _, log_full = loss(out, targets["cwe"], targets["sub"], score, weights_full)
        _, log_zero = loss(out, targets["cwe"], targets["sub"], score, weights_zero)

        # With zero weight, score+subvec terms should both be 0
        assert log_zero["loss/score"] == 0.0
        # And full-weight score term must be non-zero (random outputs ≠ random targets)
        assert log_full["loss/score"] > 0

    def test_set_cwe_loss_swaps_at_runtime(self):
        """For DRW, the trainer swaps CE → LDAM mid-training."""
        loss = DualTaskLoss()
        ldam = LDAMLoss(margins=torch.tensor([0.1] * 8), scale=1.0)
        loss.set_cwe_loss(ldam)
        assert loss.cwe_loss is ldam

    def test_set_lambda_updates_config(self):
        loss = DualTaskLoss()
        loss.set_lambda(lambda_supcon=0.5, lambda_subvec=0.2)
        assert loss.config.lambda_supcon == 0.5
        assert loss.config.lambda_subvec == 0.2
        with pytest.raises(AttributeError):
            loss.set_lambda(nonsense=1.0)

    def test_total_loss_backprops_to_all_outputs(self):
        loss = DualTaskLoss(
            config=DualTaskLossConfig(
                lambda_cwe=1.0, lambda_subvec=1.0, lambda_score=1.0, lambda_supcon=1.0,
            ),
            supcon_loss=SupervisedContrastiveLoss(),
        )
        out = self._make_outputs()
        targets = self._make_targets()
        score = torch.tensor([5.0, 7.5, 3.2, 9.1])
        total, _ = loss(out, targets["cwe"], targets["sub"], score, torch.ones(4))
        total.backward()
        assert out["cwe_logits"].grad is not None
        for k in out["sub_logits"]:
            assert out["sub_logits"][k].grad is not None
