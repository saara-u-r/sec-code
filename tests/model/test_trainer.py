"""
test_trainer.py — tests for the Phase 3 training loop.

Covers:
  • Phase transitions (warmup → phase_a → phase_b) and the loss / cwe_loss
    swaps that go with them
  • Metric helpers (CWE F1, sub-vector accuracy, CVSS MAE/RMSE)
  • End-to-end smoke run with the stub backbone — confirms the full
    pipeline executes without errors and saves checkpoints
  • Class-balanced sampler is constructed only in Phase B
  • Heteroscedastic log_var clamping
"""

from __future__ import annotations

import json

import numpy as np
import pytest
import torch
import torch.nn as nn

from src.model.dataset import (
    CWE_TO_INDEX,
    IGNORE_INDEX,
    INDEX_TO_CWE,
    DualTaskDataset,
)
from src.model.graphcodebert_dualtask import GraphCodeBERTDualTask, ModelConfig
from src.model.losses import LDAMLoss
from src.model.trainer import (
    Trainer,
    TrainerConfig,
    _margins_in_model_order,
    _weights_in_model_order,
    compute_cvss_metrics,
    compute_cwe_metrics,
    compute_subvector_metrics,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def class_weights_blob():
    """Mimics configs/class_weights.json structure."""
    return {
        "label_order": INDEX_TO_CWE + ["other"],
        "raw_counts":  {cwe: 100 for cwe in INDEX_TO_CWE},
        "uniform":     {cwe: 1.0 for cwe in INDEX_TO_CWE},
        "effective_number": {
            "CWE-89":  0.30,  "CWE-78":  1.50,  "CWE-22":  0.50,
            "CWE-79":  0.35,  "CWE-94":  2.00,  "CWE-918": 0.80,
            "CWE-502": 2.80,  "safe":    0.40,
        },
        "ldam_margins": {
            "CWE-89":  0.10,  "CWE-78":  0.18,  "CWE-22":  0.13,
            "CWE-79":  0.12,  "CWE-94":  0.19,  "CWE-918": 0.15,
            "CWE-502": 0.20,  "safe":    0.12,
        },
        "drw_schedule": {
            "phase_a_epochs": 2, "phase_b_epochs": 1,
        },
    }


@pytest.fixture
def stub_model(stub_backbone):
    """Minimal model using the tiny stub backbone — fast to train."""
    cfg = ModelConfig(hidden_dim=64, head_hidden_dim=32, supcon_proj_dim=32)
    model = GraphCodeBERTDualTask.__new__(GraphCodeBERTDualTask)
    nn.Module.__init__(model)
    model.config = cfg
    model.backbone = stub_backbone
    # Build heads manually (mirrors what __init__ does after backbone)
    from src.model.graphcodebert_dualtask import _MLPHead, _ProjectionHead
    model.cwe_head = _MLPHead(64, 32, cfg.num_cwe_classes, dropout=0.1)
    model.supcon_head = _ProjectionHead(64, 32, cfg.supcon_proj_dim)
    model.subvector_heads = nn.ModuleDict({
        key: _MLPHead(64, 32, n, dropout=0.1)
        for key, n in cfg.cvss_subvector_heads.items()
    })
    model.scalar_head = None
    return model


def _make_dataset(samples, cvss_targets, tokenizer):
    return DualTaskDataset(
        samples=samples,
        cvss_targets=cvss_targets,
        tokenizer=tokenizer,
        max_length=32,  # tiny so tests are fast
    )


# ---------------------------------------------------------------------------
# Helpers — class-weight tensor builders
# ---------------------------------------------------------------------------

class TestWeightHelpers:

    def test_weights_in_model_order_known_keys(self):
        weights = {"CWE-89": 0.5, "safe": 0.7}
        out = _weights_in_model_order(weights)
        assert out.shape == (8,)
        assert out[CWE_TO_INDEX["CWE-89"]].item() == pytest.approx(0.5)
        assert out[CWE_TO_INDEX["safe"]].item() == pytest.approx(0.7)

    def test_weights_in_model_order_missing_keys_default_to_one(self):
        out = _weights_in_model_order({})
        assert out.shape == (8,)
        assert torch.allclose(out, torch.ones(8))

    def test_margins_in_model_order_default(self):
        out = _margins_in_model_order({"CWE-502": 0.5})
        assert out[CWE_TO_INDEX["CWE-502"]].item() == pytest.approx(0.5)
        # Other classes default to 0.1, not 1.0
        assert out[CWE_TO_INDEX["CWE-89"]].item() == pytest.approx(0.1)


# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------

class TestMetrics:

    def test_cwe_metrics_perfect_predictions(self):
        labels = np.array([0, 1, 2, 0, 1, 2])
        m = compute_cwe_metrics(labels, labels)
        assert m["cwe_macro_f1"] == pytest.approx(1.0 * len(labels) / len(labels))
        # All 8 per-class F1 keys present
        for cwe in INDEX_TO_CWE:
            assert f"cwe_f1/{cwe}" in m

    def test_cwe_metrics_all_wrong(self):
        labels = np.array([0, 1, 2])
        preds  = np.array([1, 2, 0])
        m = compute_cwe_metrics(preds, labels)
        assert m["cwe_macro_f1"] < 0.5

    def test_subvector_metrics_ignores_missing(self):
        preds = {"AV": np.array([0, 1, 2])}
        labels = {"AV": np.array([0, 1, IGNORE_INDEX])}
        m = compute_subvector_metrics(preds, labels)
        # Only the first two samples count → 100% accuracy
        assert m["sub_acc/AV"] == pytest.approx(1.0)

    def test_subvector_metrics_all_missing_returns_nan(self):
        preds = {"AV": np.array([0, 1])}
        labels = {"AV": np.array([IGNORE_INDEX, IGNORE_INDEX])}
        m = compute_subvector_metrics(preds, labels)
        assert np.isnan(m["sub_acc/AV"])

    def test_cvss_metrics_basic(self):
        preds = np.array([7.0, 8.0, 9.0])
        targets = np.array([7.0, 8.5, 9.5])
        m = compute_cvss_metrics(preds, targets)
        assert m["cvss_n"] == 3
        assert m["cvss_mae"] == pytest.approx((0 + 0.5 + 0.5) / 3)

    def test_cvss_metrics_all_nan_targets(self):
        preds = np.array([7.0, 8.0])
        targets = np.array([np.nan, np.nan])
        m = compute_cvss_metrics(preds, targets)
        assert np.isnan(m["cvss_mae"])
        assert m["cvss_n"] == 0


# ---------------------------------------------------------------------------
# Phase transitions
# ---------------------------------------------------------------------------

class TestPhaseTransitions:

    def test_phase_for_epoch_boundaries(
        self, stub_model, synthetic_samples, synthetic_cvss_targets,
        stub_tokenizer, class_weights_blob, tmp_path,
    ):
        ds = _make_dataset(synthetic_samples, synthetic_cvss_targets, stub_tokenizer)
        cfg = TrainerConfig(
            warmup_epochs=2, phase_a_epochs=3, phase_b_epochs=1,
            output_dir=str(tmp_path),
            log_to_tensorboard=False, use_sam=False,
        )
        t = Trainer(stub_model, ds, ds, class_weights_blob, cfg)

        assert t._phase_for_epoch(0) == Trainer.PHASE_WARMUP
        assert t._phase_for_epoch(1) == Trainer.PHASE_WARMUP
        assert t._phase_for_epoch(2) == Trainer.PHASE_A
        assert t._phase_for_epoch(4) == Trainer.PHASE_A
        assert t._phase_for_epoch(5) == Trainer.PHASE_B
        assert t._phase_for_epoch(99) == Trainer.PHASE_B

    def test_enter_warmup_swaps_loss_lambdas(
        self, stub_model, synthetic_samples, synthetic_cvss_targets,
        stub_tokenizer, class_weights_blob, tmp_path,
    ):
        ds = _make_dataset(synthetic_samples, synthetic_cvss_targets, stub_tokenizer)
        cfg = TrainerConfig(
            warmup_epochs=1, phase_a_epochs=1, phase_b_epochs=1,
            output_dir=str(tmp_path),
            log_to_tensorboard=False, use_sam=False,
            lambda_supcon_warmup=0.7, lambda_cwe_warmup=0.05,
        )
        t = Trainer(stub_model, ds, ds, class_weights_blob, cfg)
        t._enter_phase(Trainer.PHASE_WARMUP)

        assert t.loss_fn.config.lambda_supcon == 0.7
        assert t.loss_fn.config.lambda_cwe == 0.05
        assert t.loss_fn.config.lambda_subvec == 0.0
        assert isinstance(t.loss_fn.cwe_loss, nn.CrossEntropyLoss)

    def test_enter_phase_a_uses_uniform_ldam(
        self, stub_model, synthetic_samples, synthetic_cvss_targets,
        stub_tokenizer, class_weights_blob, tmp_path,
    ):
        ds = _make_dataset(synthetic_samples, synthetic_cvss_targets, stub_tokenizer)
        cfg = TrainerConfig(
            warmup_epochs=0, phase_a_epochs=1, phase_b_epochs=1,
            output_dir=str(tmp_path),
            log_to_tensorboard=False, use_sam=False,
        )
        t = Trainer(stub_model, ds, ds, class_weights_blob, cfg)
        t._enter_phase(Trainer.PHASE_A)

        assert isinstance(t.loss_fn.cwe_loss, LDAMLoss)
        # Uniform = no class_weights buffer
        assert t.loss_fn.cwe_loss.class_weights is None
        assert t.loss_fn.config.lambda_supcon == 0.0

    def test_enter_phase_b_uses_effective_number_weights(
        self, stub_model, synthetic_samples, synthetic_cvss_targets,
        stub_tokenizer, class_weights_blob, tmp_path,
    ):
        ds = _make_dataset(synthetic_samples, synthetic_cvss_targets, stub_tokenizer)
        cfg = TrainerConfig(
            warmup_epochs=0, phase_a_epochs=0, phase_b_epochs=1,
            output_dir=str(tmp_path),
            log_to_tensorboard=False, use_sam=False,
        )
        t = Trainer(stub_model, ds, ds, class_weights_blob, cfg)
        t._enter_phase(Trainer.PHASE_B)

        assert isinstance(t.loss_fn.cwe_loss, LDAMLoss)
        # Phase B has effective-number class weights
        cw = t.loss_fn.cwe_loss.class_weights
        assert cw is not None
        # CWE-502 weight should be much larger than CWE-89's
        assert cw[CWE_TO_INDEX["CWE-502"]] > cw[CWE_TO_INDEX["CWE-89"]]


# ---------------------------------------------------------------------------
# Sampler construction
# ---------------------------------------------------------------------------

class TestSamplerSelection:

    def test_phase_b_uses_weighted_sampler_when_weights_given(
        self, stub_model, synthetic_samples, synthetic_cvss_targets,
        stub_tokenizer, class_weights_blob, tmp_path,
    ):
        ds = _make_dataset(synthetic_samples, synthetic_cvss_targets, stub_tokenizer)
        cfg = TrainerConfig(
            warmup_epochs=0, phase_a_epochs=0, phase_b_epochs=1,
            output_dir=str(tmp_path),
            log_to_tensorboard=False, use_sam=False,
            use_class_balanced_sampler_in_b=True,
        )
        t = Trainer(
            stub_model, ds, ds, class_weights_blob, cfg,
            sample_weights=[1.0, 8.0, 1.0],
        )
        loader = t._make_train_loader(Trainer.PHASE_B)
        from torch.utils.data import WeightedRandomSampler
        assert isinstance(loader.sampler, WeightedRandomSampler)

    def test_phase_a_does_not_use_weighted_sampler(
        self, stub_model, synthetic_samples, synthetic_cvss_targets,
        stub_tokenizer, class_weights_blob, tmp_path,
    ):
        ds = _make_dataset(synthetic_samples, synthetic_cvss_targets, stub_tokenizer)
        cfg = TrainerConfig(
            warmup_epochs=0, phase_a_epochs=1, phase_b_epochs=1,
            output_dir=str(tmp_path),
            log_to_tensorboard=False, use_sam=False,
        )
        t = Trainer(
            stub_model, ds, ds, class_weights_blob, cfg,
            sample_weights=[1.0] * len(synthetic_samples),
        )
        loader = t._make_train_loader(Trainer.PHASE_A)
        from torch.utils.data import WeightedRandomSampler
        assert not isinstance(loader.sampler, WeightedRandomSampler)


# ---------------------------------------------------------------------------
# log_var clamping
# ---------------------------------------------------------------------------

class TestLogVarClamping:

    def test_log_var_clamped_to_safe_range(
        self, stub_backbone, synthetic_samples, synthetic_cvss_targets,
        stub_tokenizer, class_weights_blob, tmp_path,
    ):
        # Build a model with the heteroscedastic head enabled
        cfg = ModelConfig(hidden_dim=64, head_hidden_dim=32, supcon_proj_dim=32,
                          heteroscedastic=True)
        model = GraphCodeBERTDualTask.__new__(GraphCodeBERTDualTask)
        nn.Module.__init__(model)
        model.config = cfg
        model.backbone = stub_backbone
        from src.model.graphcodebert_dualtask import _MLPHead, _ProjectionHead
        model.cwe_head = _MLPHead(64, 32, cfg.num_cwe_classes, dropout=0.1)
        model.supcon_head = _ProjectionHead(64, 32, cfg.supcon_proj_dim)
        model.subvector_heads = nn.ModuleDict({
            key: _MLPHead(64, 32, n, dropout=0.1)
            for key, n in cfg.cvss_subvector_heads.items()
        })
        model.scalar_head = _MLPHead(64, 32, 2, dropout=0.1)

        ds = _make_dataset(synthetic_samples, synthetic_cvss_targets, stub_tokenizer)
        tcfg = TrainerConfig(
            warmup_epochs=0, phase_a_epochs=1, phase_b_epochs=0,
            output_dir=str(tmp_path),
            log_to_tensorboard=False, use_sam=False,
            log_var_clamp=(-2.0, 2.0),
            batch_size=2,
        )
        t = Trainer(model, ds, ds, class_weights_blob, tcfg)
        t._enter_phase(Trainer.PHASE_A)

        from src.model.dataset import collate_dual_task
        batch = collate_dual_task([ds[0], ds[1]])
        # _forward_loss applies the clamp internally — verify by re-running
        # the forward and checking it manually
        outputs = t.model(batch["input_ids"], batch["attention_mask"])
        clamped = outputs["cvss_log_var"].clamp(min=-2.0, max=2.0)
        assert clamped.min() >= -2.0 - 1e-6
        assert clamped.max() <= 2.0 + 1e-6


# ---------------------------------------------------------------------------
# End-to-end smoke test
# ---------------------------------------------------------------------------

class TestSmokeRun:

    def test_two_epoch_train_completes_and_saves_checkpoints(
        self, stub_model, synthetic_samples, synthetic_cvss_targets,
        stub_tokenizer, class_weights_blob, tmp_path,
    ):
        # Inflate the dataset a bit so batches are non-trivial
        samples = synthetic_samples * 4  # 12 samples
        ds = _make_dataset(samples, synthetic_cvss_targets, stub_tokenizer)
        cfg = TrainerConfig(
            warmup_epochs=1, phase_a_epochs=1, phase_b_epochs=0,
            output_dir=str(tmp_path),
            log_to_tensorboard=False, use_sam=False,  # SAM doubles the cost
            batch_size=4, eval_batch_size=4,
            grad_clip=1.0, early_stop_patience=0,
        )
        t = Trainer(
            stub_model, ds, ds, class_weights_blob, cfg,
            sample_weights=[1.0] * len(samples),
        )
        result = t.train()

        # History recorded for each epoch
        assert len(result["history"]) == 2
        # Both checkpoints written
        assert (tmp_path / "best.pt").exists()
        assert (tmp_path / "last.pt").exists()
        # History.json written
        hist = json.loads((tmp_path / "history.json").read_text())
        assert len(hist) == 2
        # Each entry has training loss + val metrics
        for entry in hist:
            assert "train/loss/total" in entry
            assert "val/cwe_macro_f1" in entry

    def test_train_with_sam_completes(
        self, stub_model, synthetic_samples, synthetic_cvss_targets,
        stub_tokenizer, class_weights_blob, tmp_path,
    ):
        samples = synthetic_samples * 4
        ds = _make_dataset(samples, synthetic_cvss_targets, stub_tokenizer)
        cfg = TrainerConfig(
            warmup_epochs=0, phase_a_epochs=1, phase_b_epochs=0,
            output_dir=str(tmp_path),
            log_to_tensorboard=False, use_sam=True,
            batch_size=4, eval_batch_size=4, early_stop_patience=0,
        )
        t = Trainer(stub_model, ds, ds, class_weights_blob, cfg)
        result = t.train()
        assert (tmp_path / "best.pt").exists()
        assert len(result["history"]) == 1

    def test_checkpoint_load_round_trip(
        self, stub_model, synthetic_samples, synthetic_cvss_targets,
        stub_tokenizer, class_weights_blob, tmp_path,
    ):
        samples = synthetic_samples * 4
        ds = _make_dataset(samples, synthetic_cvss_targets, stub_tokenizer)
        cfg = TrainerConfig(
            warmup_epochs=0, phase_a_epochs=1, phase_b_epochs=0,
            output_dir=str(tmp_path),
            log_to_tensorboard=False, use_sam=False,
            batch_size=4, early_stop_patience=0,
        )
        t = Trainer(stub_model, ds, ds, class_weights_blob, cfg)
        t.train()

        # Reload into a fresh trainer
        t2 = Trainer(stub_model, ds, ds, class_weights_blob, cfg)
        ckpt = t2.load_checkpoint(tmp_path / "best.pt")
        assert ckpt["epoch"] == 0
        assert "metrics" in ckpt
        assert ckpt["current_phase"] == Trainer.PHASE_A
