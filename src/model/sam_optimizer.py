"""
src/model/sam_optimizer.py — Sharpness-Aware Minimization (SAM).

Foret et al. 2021 (ICLR) — "Sharpness-Aware Minimization for Efficiently
Improving Generalization". https://arxiv.org/abs/2010.01412

SAM seeks parameters whose entire neighborhood has uniformly low loss
(a *flat* minimum) rather than just a single low-loss point. This
generalizes much better, especially on small/imbalanced datasets — the
canonical use case is exactly our 35-sample CWE-502.

Algorithm (per training step):
  1. Compute gradient g₁ = ∇L(θ) at current point.
  2. Compute the worst-case neighbor:
        ε* = ρ · g₁ / ‖g₁‖₂
        θ' = θ + ε*
  3. Compute gradient g₂ = ∇L(θ') at the perturbed point.
  4. Take a base-optimizer step using g₂ from the *original* θ:
        θ ← BaseOptimizer(θ, g₂)

Cost: 2× per-step compute (two forwards + two backwards). Memory: ~1×
parameter footprint extra (we save θ before perturbing).

Usage in a training loop::

    base_opt = torch.optim.AdamW(model.parameters(), lr=2e-5)
    sam = SAM(model.parameters(), base_optimizer=base_opt, rho=0.05)

    for batch in loader:
        # First forward/backward — compute g₁
        loss = compute_loss(model, batch)
        loss.backward()
        sam.first_step(zero_grad=True)

        # Second forward/backward — compute g₂ at perturbed θ'
        loss = compute_loss(model, batch)
        loss.backward()
        sam.second_step(zero_grad=True)

Or with a closure::

    def closure():
        sam.zero_grad()
        loss = compute_loss(model, batch)
        loss.backward()
        return loss

    sam.step(closure)

Implementation note
-------------------
Our SAM is a *per-parameter-group* implementation (the "ρ" wraps each
group with the same value), which is the standard formulation and
matches the original paper. Adaptive variants (ASAM, GSAM) can be added
later if the empirical results call for them.
"""

from __future__ import annotations

import torch
from torch.optim import Optimizer


class SAM(Optimizer):
    """SAM optimizer wrapper. Holds an inner ``base_optimizer`` and adds
    the two-step neighbor-perturbation logic on top."""

    def __init__(
        self,
        params,
        base_optimizer: Optimizer,
        rho: float = 0.05,
        adaptive: bool = False,
        eps: float = 1e-12,
    ):
        if rho < 0:
            raise ValueError(f"rho must be non-negative, got {rho}")

        # Don't bleed our `eps` into the param_group defaults — it would
        # collide with AdamW's own `eps`. We store it as an instance attr.
        self._sam_eps = eps
        # Use distinct keys so SAM's per-group settings don't shadow AdamW's
        defaults = {
            "sam_rho":      rho,
            "sam_adaptive": adaptive,
            **base_optimizer.defaults,
        }
        super().__init__(params, defaults)

        self.base_optimizer = base_optimizer
        # Mirror our param_groups onto the base optimizer so they share state
        self.base_optimizer.param_groups = self.param_groups

    # ---- core --------------------------------------------------------

    def _grad_norm(self) -> torch.Tensor:
        """Compute ‖∇L(θ)‖₂ across all parameters (treating them as one
        flat vector). ASAM-style adaptive scaling multiplies each param's
        grad by |θ| before computing the norm."""
        # Find a tensor's device to host the running norm
        shared_device = self.param_groups[0]["params"][0].device
        norms: list[torch.Tensor] = []
        for group in self.param_groups:
            adaptive = group["sam_adaptive"]
            for p in group["params"]:
                if p.grad is None:
                    continue
                g = p.grad
                if adaptive:
                    g = g * p.detach().abs()
                norms.append(g.norm(p=2).to(shared_device))
        if not norms:
            return torch.zeros((), device=shared_device)
        return torch.stack(norms).norm(p=2)

    @torch.no_grad()
    def first_step(self, zero_grad: bool = False) -> None:
        """Compute ε* and move to θ + ε* (the worst-case neighbor)."""
        grad_norm = self._grad_norm()
        for group in self.param_groups:
            scale = group["sam_rho"] / (grad_norm + self._sam_eps)
            for p in group["params"]:
                if p.grad is None:
                    continue
                # Save original parameter so second_step can restore it
                state = self.state[p]
                state["e_w"] = p.grad * scale.to(p.device)
                if group["sam_adaptive"]:
                    state["e_w"] = state["e_w"] * p.abs()
                p.add_(state["e_w"])  # θ' = θ + ε*
        if zero_grad:
            self.zero_grad()

    @torch.no_grad()
    def second_step(self, zero_grad: bool = False) -> None:
        """Restore the original θ, then take a base-optimizer step using
        the gradient computed at θ + ε*."""
        for group in self.param_groups:
            for p in group["params"]:
                if p.grad is None:
                    continue
                state = self.state[p]
                if "e_w" not in state:
                    continue
                p.sub_(state["e_w"])  # restore θ
        # Take the base optimizer step (uses g₂)
        self.base_optimizer.step()
        if zero_grad:
            self.zero_grad()

    @torch.no_grad()
    def step(self, closure=None):
        """One-shot training step using a closure that recomputes the loss.

        The closure must:
          • zero gradients
          • forward + backward to populate `.grad`
          • return the loss tensor
        """
        if closure is None:
            raise RuntimeError(
                "SAM.step() requires a closure that recomputes the loss "
                "and gradients. Alternatively, call first_step() and "
                "second_step() explicitly."
            )

        # First forward+backward (caller may have done this already, but
        # we redo it to be safe-by-default)
        with torch.enable_grad():
            closure()
        self.first_step(zero_grad=True)

        # Second forward+backward at perturbed θ
        with torch.enable_grad():
            loss = closure()
        self.second_step(zero_grad=True)
        return loss


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def make_sam_adamw(
    params,
    lr: float = 2e-5,
    weight_decay: float = 0.01,
    rho: float = 0.05,
    adaptive: bool = False,
    **adamw_kwargs,
) -> SAM:
    """Build SAM-wrapped AdamW with reasonable defaults for fine-tuning
    GraphCodeBERT (lr=2e-5, weight_decay=0.01, rho=0.05).

    Note: returns a single SAM instance (which also exposes the inner
    AdamW via ``sam.base_optimizer``).
    """
    # Wrap params so that both AdamW and SAM see the same param groups.
    # We materialize params as a list to avoid generator-exhaustion issues.
    param_list = list(params)
    base = torch.optim.AdamW(
        param_list, lr=lr, weight_decay=weight_decay, **adamw_kwargs,
    )
    return SAM(param_list, base_optimizer=base, rho=rho, adaptive=adaptive)
