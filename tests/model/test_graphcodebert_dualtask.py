"""
test_graphcodebert_dualtask.py — tests for the dual-task model.

Avoids downloading the 500MB GraphCodeBERT weights by replacing the
backbone with a stub that has the same forward-pass API. This is
sufficient to validate head shapes, gradient flow, and the deterministic
score composer.
"""

from __future__ import annotations

import torch
import torch.nn as nn

from src.model.graphcodebert_dualtask import (
    SUBVECTOR_HEAD_CONFIG,
    GraphCodeBERTDualTask,
    ModelConfig,
    compose_score_from_logits,
    _MLPHead,
    _ProjectionHead,
)


# ---------------------------------------------------------------------------
# Helper to build the model with a stub backbone (no HF download)
# ---------------------------------------------------------------------------

def _build_with_stub(backbone, hidden_dim=64, **cfg_kwargs):
    """Construct GraphCodeBERTDualTask with a stub backbone — bypasses
    the HuggingFace download in __init__."""
    config = ModelConfig(hidden_dim=hidden_dim, **cfg_kwargs)
    # Skip the parent __init__ — just build the heads manually with the stub
    model = GraphCodeBERTDualTask.__new__(GraphCodeBERTDualTask)
    nn.Module.__init__(model)
    model.config = config
    model.backbone = backbone

    if config.freeze_backbone:
        for p in model.backbone.parameters():
            p.requires_grad = False

    model.cwe_head = _MLPHead(
        config.hidden_dim, config.head_hidden_dim, config.num_cwe_classes,
        dropout=config.head_dropout,
    )
    model.supcon_head = _ProjectionHead(
        config.hidden_dim, config.head_hidden_dim, config.supcon_proj_dim,
    )
    model.subvector_heads = nn.ModuleDict({
        key: _MLPHead(
            config.hidden_dim, config.head_hidden_dim, n_classes,
            dropout=config.head_dropout,
        )
        for key, n_classes in config.cvss_subvector_heads.items()
    })
    if config.heteroscedastic:
        model.scalar_head = _MLPHead(
            config.hidden_dim, config.head_hidden_dim, 2, dropout=config.head_dropout,
        )
    else:
        model.scalar_head = None
    return model


# ---------------------------------------------------------------------------
# Heads in isolation
# ---------------------------------------------------------------------------

def test_mlp_head_output_shape():
    head = _MLPHead(in_dim=64, hidden_dim=32, out_dim=8, dropout=0.0)
    x = torch.randn(4, 64)
    out = head(x)
    assert out.shape == (4, 8)


def test_supcon_head_outputs_l2_normalized():
    head = _ProjectionHead(in_dim=64, hidden_dim=32, proj_dim=16)
    x = torch.randn(4, 64)
    z = head(x)
    norms = z.norm(dim=-1)
    assert torch.allclose(norms, torch.ones_like(norms), atol=1e-5)


# ---------------------------------------------------------------------------
# Forward pass — shape checks
# ---------------------------------------------------------------------------

def test_forward_pass_returns_all_heads(stub_backbone):
    model = _build_with_stub(stub_backbone, hidden_dim=64)
    model.eval()

    B, T = 3, 32
    input_ids = torch.randint(0, 50000, (B, T))
    attention_mask = torch.ones(B, T, dtype=torch.long)

    with torch.no_grad():
        out = model(input_ids, attention_mask)

    assert "embedding" in out
    assert "supcon_proj" in out
    assert "cwe_logits" in out
    assert "sub_logits" in out

    assert out["embedding"].shape    == (B, 64)
    assert out["supcon_proj"].shape  == (B, 128)
    assert out["cwe_logits"].shape   == (B, 8)
    for key, n_classes in SUBVECTOR_HEAD_CONFIG.items():
        assert out["sub_logits"][key].shape == (B, n_classes)


def test_forward_with_heteroscedastic_returns_mu_logvar(stub_backbone):
    model = _build_with_stub(stub_backbone, hidden_dim=64, heteroscedastic=True)
    model.eval()

    B = 2
    input_ids = torch.randint(0, 50000, (B, 16))
    attention_mask = torch.ones(B, 16, dtype=torch.long)

    with torch.no_grad():
        out = model(input_ids, attention_mask)

    assert "cvss_mu"      in out
    assert "cvss_log_var" in out
    assert out["cvss_mu"].shape      == (B,)
    assert out["cvss_log_var"].shape == (B,)


def test_forward_without_heteroscedastic_no_scalar_outputs(stub_backbone):
    model = _build_with_stub(stub_backbone, hidden_dim=64, heteroscedastic=False)
    model.eval()
    out = model(torch.randint(0, 50000, (2, 16)), torch.ones(2, 16, dtype=torch.long))
    assert "cvss_mu"      not in out
    assert "cvss_log_var" not in out


# ---------------------------------------------------------------------------
# Gradient flow
# ---------------------------------------------------------------------------

def test_gradients_flow_through_all_heads(stub_backbone):
    model = _build_with_stub(stub_backbone, hidden_dim=64)
    model.train()

    input_ids = torch.randint(0, 50000, (4, 16))
    attention_mask = torch.ones(4, 16, dtype=torch.long)
    out = model(input_ids, attention_mask)

    # Synthesize a loss covering every head
    cwe_targets = torch.randint(0, 8, (4,))
    sub_targets = {
        key: torch.randint(0, n, (4,))
        for key, n in SUBVECTOR_HEAD_CONFIG.items()
    }
    loss = torch.nn.functional.cross_entropy(out["cwe_logits"], cwe_targets)
    for key, t in sub_targets.items():
        loss = loss + torch.nn.functional.cross_entropy(out["sub_logits"][key], t)
    loss = loss + out["supcon_proj"].sum()  # touch the supcon head too

    loss.backward()

    # Every head's first linear layer must have a non-None grad
    assert model.cwe_head.net[0].weight.grad is not None
    assert model.supcon_head.fc1.weight.grad is not None
    for key in SUBVECTOR_HEAD_CONFIG:
        assert model.subvector_heads[key].net[0].weight.grad is not None


def test_freeze_backbone_disables_backbone_grads(stub_backbone):
    model = _build_with_stub(stub_backbone, hidden_dim=64, freeze_backbone=True)
    for p in model.backbone.parameters():
        assert not p.requires_grad


# ---------------------------------------------------------------------------
# Inference helpers
# ---------------------------------------------------------------------------

def test_predict_cwe_returns_class_indices(stub_backbone):
    model = _build_with_stub(stub_backbone, hidden_dim=64)
    preds = model.predict_cwe(
        torch.randint(0, 50000, (5, 16)),
        torch.ones(5, 16, dtype=torch.long),
    )
    assert preds.shape == (5,)
    assert preds.dtype == torch.long
    assert (preds >= 0).all() and (preds < 8).all()


def test_predict_subvectors_returns_dict(stub_backbone):
    model = _build_with_stub(stub_backbone, hidden_dim=64)
    preds = model.predict_subvectors(
        torch.randint(0, 50000, (3, 16)),
        torch.ones(3, 16, dtype=torch.long),
    )
    assert set(preds.keys()) == set(SUBVECTOR_HEAD_CONFIG.keys())
    for key, p in preds.items():
        assert p.shape == (3,)
        assert (p >= 0).all() and (p < SUBVECTOR_HEAD_CONFIG[key]).all()


# ---------------------------------------------------------------------------
# CVSS score composition
# ---------------------------------------------------------------------------

def test_compose_score_from_logits_matches_argmax_composition():
    """Build logits whose argmax produces a known CVSS vector and confirm
    the composed score matches the ground-truth value."""
    # Force argmax → AV:N AC:L PR:N UI:N S:U C:H I:H A:H → CVSS 9.8
    target_indices = {"AV": 0, "AC": 0, "PR": 0, "UI": 0, "S": 0, "C": 2, "I": 2, "A": 2}
    sub_logits: dict[str, torch.Tensor] = {}
    for key, n in SUBVECTOR_HEAD_CONFIG.items():
        # Make the chosen index strongly preferred
        logits = torch.full((1, n), -10.0)
        logits[0, target_indices[key]] = 10.0
        sub_logits[key] = logits

    score = compose_score_from_logits(sub_logits)
    assert score.shape == (1,)
    # 9.8 is the canonical CVSS 9.8 example
    assert abs(score.item() - 9.8) < 0.1


def test_compose_score_handles_batch():
    """Multiple samples → one score each."""
    B = 4
    sub_logits: dict[str, torch.Tensor] = {
        key: torch.randn(B, n) for key, n in SUBVECTOR_HEAD_CONFIG.items()
    }
    scores = compose_score_from_logits(sub_logits)
    assert scores.shape == (B,)
    assert (scores >= 0).all() and (scores <= 10.0).all()
