"""
test_sam_optimizer.py — tests for SAM (Sharpness-Aware Minimization).
"""

from __future__ import annotations

import pytest
import torch
import torch.nn as nn

from src.model.sam_optimizer import SAM, make_sam_adamw


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

def test_rejects_negative_rho():
    params = [torch.zeros(2, requires_grad=True)]
    base = torch.optim.SGD(params, lr=0.1)
    with pytest.raises(ValueError):
        SAM(params, base_optimizer=base, rho=-0.1)


def test_constructor_mirrors_param_groups():
    """SAM and the base optimizer must share param_groups so state is consistent."""
    params = [torch.zeros(2, requires_grad=True)]
    base = torch.optim.SGD(params, lr=0.1)
    sam = SAM(params, base_optimizer=base, rho=0.05)
    assert sam.param_groups is base.param_groups


def test_make_sam_adamw_constructs_correctly():
    p = torch.zeros(4, requires_grad=True)
    sam = make_sam_adamw([p], lr=1e-3, weight_decay=0.01, rho=0.05)
    assert isinstance(sam, SAM)
    assert isinstance(sam.base_optimizer, torch.optim.AdamW)


# ---------------------------------------------------------------------------
# Two-step pattern: first_step + second_step
# ---------------------------------------------------------------------------

def test_first_step_perturbs_parameters_in_grad_direction():
    """After first_step, parameters should have moved by ε* = ρ · g/||g||."""
    p = torch.zeros(3, requires_grad=True)
    p_original = p.detach().clone()
    base = torch.optim.SGD([p], lr=0.1)
    sam = SAM([p], base_optimizer=base, rho=0.05)

    # Synthetic gradient: ∇L = [3, 4, 0], ‖g‖ = 5
    p.grad = torch.tensor([3.0, 4.0, 0.0])
    sam.first_step(zero_grad=False)

    # ε* should be ρ · g / ‖g‖ = 0.05 · [3,4,0] / 5 = [0.03, 0.04, 0]
    expected = torch.tensor([0.03, 0.04, 0.0])
    assert torch.allclose(p - p_original, expected, atol=1e-6)


def test_second_step_restores_then_takes_base_step():
    """After second_step, the original θ should be restored (then stepped)."""
    p = torch.tensor([1.0, 2.0, 3.0], requires_grad=True)
    p_original = p.detach().clone()
    base = torch.optim.SGD([p], lr=0.0)  # zero LR so the actual step is a no-op
    sam = SAM([p], base_optimizer=base, rho=0.05)

    p.grad = torch.tensor([1.0, 0.0, 0.0])
    sam.first_step(zero_grad=False)
    assert not torch.allclose(p, p_original)  # we moved

    # Second step: gradient might differ, but with lr=0 it's pure restoration
    p.grad = torch.tensor([0.0, 1.0, 0.0])  # different "g₂"
    sam.second_step(zero_grad=False)
    # With base lr=0, after restore we should be back at p_original
    assert torch.allclose(p, p_original, atol=1e-6)


def test_first_step_with_zero_gradient_norm_does_not_crash():
    """If all gradients are exactly zero, first_step should be a no-op."""
    p = torch.zeros(3, requires_grad=True)
    p_original = p.detach().clone()
    base = torch.optim.SGD([p], lr=0.1)
    sam = SAM([p], base_optimizer=base, rho=0.05)

    p.grad = torch.zeros(3)
    sam.first_step(zero_grad=False)
    # Parameters should remain at zero (eps prevents division by zero)
    assert torch.allclose(p, p_original)


# ---------------------------------------------------------------------------
# End-to-end: SAM on a simple convex problem makes loss decrease
# ---------------------------------------------------------------------------

def test_sam_decreases_loss_on_simple_problem():
    """Run a few steps of SAM on a quadratic and confirm the loss drops."""
    torch.manual_seed(42)

    # f(w) = ||w - target||² + small noise
    w = nn.Parameter(torch.randn(8))
    target = torch.randn(8)
    base = torch.optim.AdamW([w], lr=0.1, weight_decay=0.0)
    sam = SAM([w], base_optimizer=base, rho=0.05)

    def loss_fn():
        return ((w - target) ** 2).sum()

    initial_loss = loss_fn().item()

    for _ in range(20):
        # First step
        sam.zero_grad()
        loss = loss_fn()
        loss.backward()
        sam.first_step(zero_grad=True)

        # Second step
        loss = loss_fn()
        loss.backward()
        sam.second_step(zero_grad=True)

    final_loss = loss_fn().item()
    assert final_loss < initial_loss
    # Should have made significant progress on a simple convex problem
    assert final_loss < 0.5 * initial_loss


# ---------------------------------------------------------------------------
# Closure interface
# ---------------------------------------------------------------------------

def test_step_with_closure_runs_full_two_step_cycle():
    torch.manual_seed(0)
    w = nn.Parameter(torch.randn(4))
    target = torch.randn(4)
    base = torch.optim.SGD([w], lr=0.1)
    sam = SAM([w], base_optimizer=base, rho=0.05)

    n_calls = [0]

    def closure():
        sam.zero_grad()
        loss = ((w - target) ** 2).sum()
        loss.backward()
        n_calls[0] += 1
        return loss

    sam.step(closure)
    # Closure should be called twice (first_step + second_step)
    assert n_calls[0] == 2


def test_step_without_closure_raises():
    p = torch.zeros(2, requires_grad=True)
    base = torch.optim.SGD([p], lr=0.1)
    sam = SAM([p], base_optimizer=base, rho=0.05)
    with pytest.raises(RuntimeError):
        sam.step()


# ---------------------------------------------------------------------------
# Adaptive (ASAM) variant
# ---------------------------------------------------------------------------

def test_adaptive_sam_scales_perturbation_by_param_magnitude():
    """ASAM-style adaptive scaling multiplies grad by |θ| before normalizing."""
    p1 = nn.Parameter(torch.tensor([10.0, 0.0]))
    p2 = nn.Parameter(torch.tensor([0.1, 0.0]))
    base = torch.optim.SGD([p1, p2], lr=0.0)
    sam = SAM([p1, p2], base_optimizer=base, rho=0.05, adaptive=True)

    p1.grad = torch.tensor([1.0, 0.0])
    p2.grad = torch.tensor([1.0, 0.0])

    p1_before = p1.detach().clone()
    p2_before = p2.detach().clone()

    sam.first_step(zero_grad=False)

    # Larger-magnitude param should get a larger perturbation
    delta1 = (p1 - p1_before).norm().item()
    delta2 = (p2 - p2_before).norm().item()
    assert delta1 > delta2


# ---------------------------------------------------------------------------
# Multi-parameter group coverage
# ---------------------------------------------------------------------------

def test_sam_handles_multiple_param_groups():
    """SAM should work with the param-group pattern used for layer-wise LRs."""
    p1 = nn.Parameter(torch.zeros(3))
    p2 = nn.Parameter(torch.zeros(3))
    base = torch.optim.SGD(
        [{"params": [p1], "lr": 1e-2}, {"params": [p2], "lr": 1e-3}],
    )
    sam = SAM(
        [{"params": [p1]}, {"params": [p2]}],
        base_optimizer=base, rho=0.05,
    )
    p1.grad = torch.tensor([1.0, 0.0, 0.0])
    p2.grad = torch.tensor([0.0, 1.0, 0.0])

    # Should not raise
    sam.first_step(zero_grad=False)
    sam.second_step(zero_grad=False)
