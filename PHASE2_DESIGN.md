# Phase 2 — Dataset Preparation: Design Document

**Project:** PyVulSev — Python Vulnerability Severity Dataset
**Date:** 2026-05-04 (revised after methodology review)
**Phase:** 2 (Dataset Preparation)
**Status:** ✅ Methodology locked in — implementation pending

**Revision summary (2026-05-04):**
- Added **SupCon warmup → LDAM+DRW** as the canonical training schedule
- Added **SAM (Sharpness-Aware Minimization) optimizer**
- Added **LoC-to-Scan evaluation metric** for paper Section 6
- Added **Captum attribution comparison** (Attention Rollout vs IG vs DeepLIFT)
- Added **GitHub Action / pre-commit hook** as a deployment artifact
- **Hard negative mining + targeted augmentation** spun out into a separate
  document (`PHASE2_5_AUGMENTATION_DESIGN.md`) — too large to fit here
- **Rejected** (with reasoning in Section 14): Joern/GNN-Transformer hybrid,
  ONNX/4-bit quantization for the demo

---

## 0. Document Purpose

This document specifies the Phase 2 design with publication-grade methodology
for the two areas that most influence model quality:

1. **Class weight computation** for the imbalanced 7-CWE classification task
2. **CVSS target preparation** for the regression / multi-task severity task

It also covers the ancillary steps (split strategy, anti-leakage, tokenization)
that turn the 2,579 raw MongoDB samples into Phase-3-ready training data.

The methodology choices here are designed to survive Q1 peer review at venues
like *Computers & Security* (Elsevier) and *IEEE TDSC*. Each choice is
backed by a citable reference and has a concrete fallback baseline.

---

## 1. What Phase 2 Is

Phase 2 sits between raw ingestion (Phase 1, complete) and model training
(Phase 3). Its job is to take the 2,579 ingested samples and turn them into:

- A clean stratified **train / val / test** split written back to MongoDB
- A `configs/class_weights.json` file with **defensible per-class weights**
- A `configs/cvss_targets.json` mapping each sample to its **CVSS prediction
  targets** (sub-vector classes + composite score + confidence)
- A `data/phase2_split_report.json` reproducibility appendix

Originally Phase 2 included TF-IDF + SVM and DistilBERT classifier stages for
auto-labeling commits. **These were removed per professor feedback** — the
new sources (CVEfixes, GHSA, OSV, GHSA-DB, VUDENC) all carry their own
authoritative labels, so the classifier stages added noise without adding
signal.

---

## 2. Why a Naïve Split Fails

A random 80/10/10 split causes three failures:

1. **CWE imbalance gets worse.**
   With 35 CWE-502 samples, a random split could leave the test set with
   *zero* CWE-502 examples. Per-class F1 becomes uncomputable.

2. **Framework leakage.**
   All Django samples could land in train, all Flask in test. The model
   memorizes framework-specific tokens (`@app.route` vs `urlpatterns`)
   instead of vulnerability patterns.

3. **Repository leakage.**
   The same `pgadmin/pgadmin4` repo could have files in both train and test.
   Code from the same repo shares variable names, helper functions, and
   coding style — the model "memorizes" the repo's surface features and
   inflates accuracy. This was the dominant failure mode flagged in the
   PrimeVul (Ding et al. 2024) and DiverseVul (Chen et al. 2023) papers.

---

## 3. Phase 2 Pipeline Overview

```
MongoDB raw samples (2,579)
        │
        ▼
[3.1] Repository-level grouping (anti-leakage)
        │
        ▼
[3.2] Stratified split on CWE × framework
        │
        ▼
[3.3] Write `split` field back to MongoDB
        │
        ▼
[3.4] Compute class weights (LDAM-aware)
        │
        ▼
[3.5] Prepare CVSS targets (sub-vector decomposition)
        │
        ▼
[3.6] Tokenization preview & length analysis
        │
        ▼
[3.7] Emit reproducibility report
```

---

## 4. Class Weight Computation

### 4.1 Why Inverse Frequency Is Insufficient

The textbook formula `w_c = N / (k · n_c)` over-weights ultra-rare classes
catastrophically. For our distribution:

| CWE | n_c | inv-freq weight |
|---|---:|---:|
| CWE-89 | 1,203 | 0.31 |
| CWE-22 | 448 | 0.82 |
| CWE-79 | 368 | 1.00 |
| CWE-78 | 248 | 1.49 |
| CWE-94 | 147 | 2.50 |
| CWE-918 | 130 | 2.83 |
| CWE-502 | **35** | **10.51** |

CWE-502 ends up with **34× the weight of CWE-89**. With only 35 samples,
this causes:
- Training instability (large gradient swings on rare-class minibatches)
- Overfitting on those exact 35 samples → catastrophic test-set collapse
- Inflated training accuracy that doesn't generalize

### 4.2 Better Alternatives (Comparative Table)

| Method | Reference | Hyperparams | When to use |
|---|---|---|---|
| Inverse Frequency | — | none | Baseline only |
| Effective Number of Samples | Cui et al., CVPR 2019 | β ∈ [0.99, 0.9999] | Standard long-tail default |
| Focal Loss | Lin et al., ICCV 2017 | γ = 2.0, α (per-class) | When hard-example mining matters |
| Class-Balanced Focal | Cui 2019 + Lin 2017 | β + γ | Combine the above |
| LDAM + DRW | Cao et al., NeurIPS 2019 | C, switch epoch | **Best for ultra-rare classes** |
| Logit Adjustment | Menon et al., ICLR 2020 | τ = 1.0 | Zero training overhead |
| Two-Stage Decoupled | Kang et al., ICLR 2020 | freeze epoch | Best representation quality |

### 4.3 Recommended Approach: LDAM + DRW

**LDAM (Label-Distribution-Aware Margin Loss)** modifies the softmax to
push the decision boundary further from rare classes:

```
margin_c = C / n_c^(1/4)
loss_c   = -log( e^(z_c − margin_c) / Σ_j e^(z_j − margin_j · 1[j=y]) )
```

where `C` is normalized so the largest margin equals 0.5.

**DRW (Deferred Re-Weighting)** is a two-phase training schedule:

- **Phase A (epochs 1–N×0.8):** uniform class weights → backbone learns
  good representations from the natural data distribution
- **Phase B (epochs N×0.8–N):** switch to class-balanced weights →
  classifier head re-calibrates without disrupting the backbone

This decoupling is the key insight: representation learning prefers
class-imbalanced data; classifier learning prefers class-balanced data.

**Why LDAM + DRW for our problem:**
- Empirically the strongest method on long-tail benchmarks (CIFAR-LT,
  ImageNet-LT, iNaturalist)
- Margin-based — robust to noisy labels (we have medium-confidence VUDENC)
- DRW schedule prevents the early-training instability that pure
  re-weighting causes
- Direct fit for our 34× imbalance ratio (CWE-89 vs CWE-502)

**Implementation in Phase 2 deliverables:**

`configs/class_weights.json` will contain three weight schedules:

```json
{
  "uniform":          {"CWE-89": 1.0,  "CWE-22": 1.0,  ...},
  "effective_number": {"CWE-89": 0.40, "CWE-22": 0.65, ..., "CWE-502": 2.85},
  "ldam_margins":     {"CWE-89": 0.10, "CWE-22": 0.18, ..., "CWE-502": 0.50},
  "drw_schedule":     {"phase_a_epochs": 8, "phase_b_epochs": 2, "phase_b_weights": "effective_number"}
}
```

Phase 3 will read this JSON and apply the LDAM margins + DRW schedule.

### 4.4 Complementary Techniques (Recommended Add-ons)

**1. Class-Balanced Sampling**
Use PyTorch `WeightedRandomSampler` to construct minibatches with equal
samples per class. Combine with LDAM loss for further gains. Implemented
as a sampler config in `configs/class_weights.json`.

**2. Targeted Augmentation for Rare CWEs**
Apply your red-team mutations **5–10× more aggressively** to CWE-502 and
CWE-918 samples. Mutations (variable rename, dead code injection, string
splitting, wrapper extraction) preserve semantics while changing surface
form. For our 35 CWE-502 samples → 175–350 augmented samples without
synthesizing new CVE labels.

This is captured in `configs/augmentation_config.json`:

```json
{
  "base_mutation_count": 1,
  "rare_class_multipliers": {
    "CWE-502": 8,
    "CWE-918": 4,
    "CWE-94": 3,
    "default": 1
  },
  "mutation_types": [
    "variable_rename",
    "dead_code_injection",
    "string_split",
    "wrapper_extraction"
  ]
}
```

**3. Two-Stage Decoupled Training (Optional Phase-3 Experiment)**
- Stage 1: train backbone + heads with random sampling (200 epochs)
- Stage 2: freeze backbone, retrain only the CWE head with class-balanced
  sampling (20 epochs)

This has been shown to outperform end-to-end training on long-tail
benchmarks. Worth running as an ablation for the paper.

### 4.5b SupCon Warmup → LDAM+DRW (new — 2026-05-04 addition)

The training schedule has three phases instead of two:

| Phase | Epochs (% of total) | Loss | Sampler | Purpose |
|---|---|---|---|---|
| **Phase 0 — Warmup** | 0–30% | **Supervised Contrastive (SupCon)** + L2 normalize | Random | Build a clean embedding space where same-CWE samples cluster |
| **Phase A — Backbone** | 30–80% | LDAM + uniform weights | Random | Train classifier on natural distribution; backbone keeps learning |
| **Phase B — Re-Weight** | 80–100% | LDAM + Effective-Number weights | Class-balanced | Calibrate the classifier head for rare classes (DRW) |

**SupCon (Khosla et al. 2020, NeurIPS):**

```
L_supcon = − Σ_i (1 / |P(i)|) · Σ_p∈P(i) log( exp(z_i · z_p / τ) / Σ_a∈A(i) exp(z_i · z_a / τ) )
```

where `P(i)` = positives (same CWE as anchor `i`), `A(i)` = all in-batch
except `i`, and `τ = 0.07` is standard.

**Why this works for our problem:**
- Standard cross-entropy collapses when one class is 47% of the data —
  the embedding space becomes "CWE-89 vs everything else"
- SupCon explicitly pulls same-CWE samples together and pushes
  different-CWE samples apart, regardless of class size
- Particularly strong on small-data benchmarks (CIFAR-100, miniImageNet)
- Provides a **better starting point** for the LDAM classifier head

**Practical detail — batch size:** SupCon needs many in-batch negatives.
With 1,805 train samples and batch size 64, we get ~63 negatives per
anchor — workable. Increase to 128 if GPU memory allows. Augmentation
(applied later in Phase 2.5) gives us more effective batch diversity.

**Caveat:** SupCon needs an L2-normalized projection head during
training. Discard the projection head before Phase A; keep only the
backbone embeddings.

### 4.5c SAM (Sharpness-Aware Minimization) — new addition

**Why SAM:**

35 CWE-502 samples is the canonical SAM use case. Standard SGD/AdamW
finds sharp minima that overfit to the few rare samples. SAM finds
"flat" minima — solutions where small perturbations of the weights
don't dramatically change the loss — which generalize much better.

**The SAM update (Foret et al. 2021, ICLR):**

```
ε* = ρ · ∇L(θ) / ‖∇L(θ)‖₂
θ' = θ + ε*                        # ascend to local maximum
g  = ∇L(θ')                        # gradient at the worst-case neighbor
θ  = θ − η · g                     # descend from there
```

**Hyperparameters:**
- `ρ = 0.05` (standard) — neighborhood radius
- Wraps **any** base optimizer (we'll use AdamW)
- 2× cost per training step (two forward+backward passes)
- Implementation: ~20 lines or use `pytorch-sam` library

**Expected gain:** 1–4 F1 points on small/imbalanced datasets, with
markedly better calibration (lower expected calibration error).

**SAM + LDAM + SupCon stack — known to work:**
This combination (contrastive warmup → SAM-optimized LDAM with DRW)
is the current state-of-art for long-tail classification. See
*Tong et al. 2023, "Boundary-Aware Imbalanced Learning"* for empirical
results.

### 4.6 What the Paper Will Report

A 6-row ablation table for the imbalance methodology:

| Method | Macro-F1 | Min-class F1 (CWE-502) | Notes |
|---|---:|---:|---|
| Inverse-frequency (baseline) | — | — | Standard textbook |
| Effective-Number weighting | — | — | Cui 2019 |
| Class-Balanced Focal Loss | — | — | + Focal γ=2 |
| LDAM + DRW | — | — | Cao 2019 |
| LDAM + DRW + SAM | — | — | + Foret 2021 |
| **SupCon → LDAM + DRW + SAM (ours)** | — | — | **Final stack** |

Reviewers expect to see the baseline beaten. Showing the additive
contribution of each component demonstrates methodological care and
supports the ablation discussion in Section 6 of the paper.

---

## 5. CVSS Target Preparation

### 5.1 Why Band Midpoint Is Insufficient

The naïve approach is:
- If `cvss_score` is present (409 samples) → use it
- Else if `cvss_severity` is present → use band midpoint (CRITICAL=9.5, etc.)
- Else (VUDENC's 1,462 samples) → mark as missing

**Three problems:**

1. **Information collapse.** All XSS samples without precise scores get
   `cvss_target = 6.1` (the configured XSS default). The model learns
   "XSS = 6.1" instead of learning per-instance severity from code.

2. **Distribution distortion.** Band midpoints are non-uniformly distributed
   (2.5, 5.0, 7.5, 9.5). The regression head learns these four values as
   modes, not the underlying continuous distribution.

3. **Unused structure.** The CVSS specification gives us 8 sub-vectors
   (AV, AC, PR, UI, S, C, I, A) with discrete values. We *already extracted*
   these in `parse_cvss_vector()` during Phase 1. Throwing them away to
   regress a single composite score wastes labeled signal.

### 5.2 Better Alternatives (Comparative Table)

| Method | Where it fits | Hyperparams | Justification |
|---|---|---|---|
| Raw scalar regression | Standard baseline | — | Simple |
| Band-midpoint regression | Standard baseline | — | What we'd default to |
| Ordinal regression | Niu et al. 2016 | K = 5 bands | Stable on coarse labels |
| Heteroscedastic regression | Kendall & Gal 2017 | — | Provides uncertainty |
| KL on Gaussian targets | Soft labels | σ per band | Honest about precision |
| **CVSS sub-vector multi-task** | **Le et al. 2022** | **8 heads** | **Recommended** |
| Pseudo-labeling | Lee 2013 | confidence threshold | Uses unlabeled majority |

### 5.3 Recommended Approach: CVSS Sub-Vector Multi-Task Heads

**Architecture sketch:**

```
                ┌──────────────────────┐
                │   GraphCodeBERT      │
                │   shared encoder     │
                └─────────┬────────────┘
                          │ [CLS] embedding
       ┌──────────────────┼──────────────────────┐
       │                  │                      │
       ▼                  ▼                      ▼
   ┌────────┐    ┌──────────────┐   ┌─────────────────────────┐
   │  CWE   │    │     CVSS     │   │   8 CVSS sub-vector     │
   │  head  │    │ scalar head  │   │   classification heads  │
   │ (7-way)│    │  (optional)  │   │  AV, AC, PR, UI, S,     │
   └────────┘    └──────────────┘   │  C, I, A                │
                                     └────────┬────────────────┘
                                              │
                                              ▼
                               ┌────────────────────────────────┐
                               │  Deterministic CVSS 3.1        │
                               │  base score composer           │
                               │  (no learned parameters)       │
                               └────────────────────────────────┘
                                              │
                                              ▼
                                     final CVSS score (0–10)
```

**The 8 sub-vector heads:**

| Sub-vector | Possible values | Head type | Loss |
|---|---|---|---|
| AV (Attack Vector) | N, A, L, P | 4-way softmax | CE |
| AC (Attack Complexity) | L, H | 2-way softmax | CE |
| PR (Privileges Required) | N, L, H | 3-way softmax | CE |
| UI (User Interaction) | N, R | 2-way softmax | CE |
| S (Scope) | U, C | 2-way softmax | CE |
| C (Confidentiality Impact) | N, L, H | 3-way softmax | CE |
| I (Integrity Impact) | N, L, H | 3-way softmax | CE |
| A (Availability Impact) | N, L, H | 3-way softmax | CE |

**Total parameters added:** 8 × (hidden_dim × num_classes) ≈ 8 × 768 × 3 ≈ 18K
parameters. Negligible relative to GraphCodeBERT's ~125M.

**Loss decomposition:**

```
L_total = λ_cwe · L_cwe(ŷ_cwe, y_cwe)
        + λ_sub · Σ_v L_v(ŷ_v, y_v) · 1[y_v != missing]
        + λ_score · L_score(score(ŷ_AV, ŷ_AC, ...), y_score) · 1[y_score != missing]
```

The composite score loss is **optional** — the sub-vector classifications
already determine the score deterministically. Including it as a small
auxiliary loss can stabilize training.

**Why this is better:**

1. **Learnability.** Each sub-vector has 2–4 discrete values vs. continuous
   [0, 10] regression. Classification on small label spaces is far easier.

2. **Determinism.** The CVSS 3.1 base score formula is publicly specified
   and deterministic. No learned parameters in the score composer → no
   composition error.

3. **Fine-grained labels.** The 1,113 CVE-linked samples have full CVSS
   vectors. We can train each sub-vector head on whichever subset of samples
   has that vector populated, rather than discarding samples with partial
   data.

4. **Interpretability.** The model output is:
   *"Network-attackable, Low-complexity, no privileges needed,
   Confidentiality: High, Integrity: High → CVSS = 9.8"*
   This is paragraph-1 of any CVE writeup. Reviewers and end-users both
   prefer this to a bare 7.4 score.

5. **Direct precedent.** Le, Hin, Babar (2022)
   *"On the Use of Fine-grained Vulnerable Code Statements for Software
   Vulnerability Assessment Models"* (MSR 2022) decomposed CVSS into
   sub-vector predictions and showed substantial gains over scalar
   regression.

6. **Per-sub-vector loss weighting.** If our data has more samples with
   labeled `AV` than labeled `S`, we can adjust loss weights per head.

### 5.4 Confidence-Weighted Loss

Layer this on top of the sub-vector heads to handle the
medium-confidence VUDENC samples:

```
L_per_sample = w_i · L_dual_task
where w_i = {
  1.0   if label_confidence == "high",
  0.3   if label_confidence == "medium",
  0.0   if label_confidence == "low"
}
```

Lets the 1,462 VUDENC samples contribute to **representation learning** via
the CWE head (which has reliable VUDENC labels) without dragging the **CVSS
heads** down with their unknown sub-vectors. Standard noisy-label
regression technique.

### 5.5 Heteroscedastic Output (Optional Enhancement)

Add one variance neuron per scalar output:

```
L_heteroscedastic = (y − μ)² / (2σ²) + ½ log σ²
```

The model learns to predict both `μ` (point estimate) and `σ` (uncertainty).
Two benefits:

- **Calibrated triage signal.** "We predict CVSS 7.5 ± 0.4" beats just
  "7.5" for an analyst deciding patching priority — directly supports the
  Use Case 2 narrative in `MOTIVATION_REPORT.md`.

- **Demo visualization.** Confidence intervals in the Gradio demo make the
  output feel honest and well-calibrated. Cheap UX win.

**Cost:** one extra output neuron, one extra `log` term in the loss.

### 5.6 Pseudo-Labeling for Missing CVSS (Phase 2 Extension)

For the 2,170 samples without CVSS scores:

1. **Bootstrap.** Train the model only on the 409 samples with real scores
   for 50 epochs.

2. **Predict.** Generate CVSS predictions for the 2,170 unlabeled samples.

3. **Filter.** Keep only predictions where the model's heteroscedastic
   variance σ < threshold (e.g., σ < 1.0).

4. **Retrain.** Add the high-confidence pseudo-labels to the training set
   with reduced weight (w = 0.3) and continue training.

5. **Iterate.** Repeat 2–4 until pseudo-label set stabilizes.

This is standard semi-supervised learning (Lee 2013, "Pseudo-Label").
Can recover useful signal from the unlabeled majority. Worth running as
a Phase 2 extension experiment in the paper.

### 5.7 Phase 2 Deliverable: `configs/cvss_targets.json`

For each sample (keyed by `content_hash`):

```json
{
  "<hash>": {
    "cvss_score": 7.5,
    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "sub_vectors": {
      "AV": "N",  "AC": "L",  "PR": "N",  "UI": "N",
      "S":  "U",  "C":  "H",  "I":  "H",  "A":  "N"
    },
    "score_source": "ghsa_advisory",
    "label_confidence": "high",
    "loss_weight": 1.0
  },
  "<hash_partial>": {
    "cvss_score": null,
    "cvss_vector": null,
    "sub_vectors": null,
    "score_source": "missing",
    "label_confidence": "medium",
    "loss_weight": 0.3
  }
}
```

This decouples target preparation from model training — Phase 3 just reads
the JSON and constructs masked losses based on which fields are non-null.

### 5.8 What the Paper Will Report

A 5-row results table for CVSS prediction:

| Method | MAE ↓ | RMSE ↓ | Bin Acc (5 bands) ↑ | Notes |
|---|---:|---:|---:|---|
| Scalar regression on raw scores (baseline) | — | — | — | Standard |
| Scalar regression on band midpoints | — | — | — | Naïve fallback |
| Ordinal regression (5 bands) | — | — | — | Niu et al. 2016 |
| **Sub-vector multi-task → composed (ours)** | — | — | — | **Recommended** |
| Sub-vector + heteroscedastic head (ours+) | — | — | — | + uncertainty |

---

## 6. Repository-Level Holdout (Anti-Leakage)

### 6.1 The Leakage Problem

Random sampling without grouping causes the same repository to appear in
both train and test. Example: pgAdmin's CVE-2024-XXXX touches 60 files,
all from `pgadmin-org/pgadmin4`. Random splitting puts ~42 in train, ~9
in val, ~9 in test. The model "memorizes" pgAdmin-specific naming
conventions (`pgadmin.tools.*`, `db_get_*`) and inflates test accuracy.

PrimeVul (Ding et al. 2024, ICSE) and DiverseVul (Chen et al. 2023)
showed this leakage inflates F1 by **15–30 percentage points** on
vulnerability-detection benchmarks.

### 6.2 Solution: GroupShuffleSplit on `repo`

Use `sklearn.model_selection.GroupShuffleSplit` with `groups = sample.repo`:
all samples from the same repo land in the same split. Combine with
stratification on CWE to maintain class balance.

For samples without a `repo` field (VUDENC doesn't provide it), treat each
as its own group — these are individual functions extracted across many
repos, so the leakage risk is naturally low.

### 6.3 Verification

After splitting, run:

```python
assert len(train_repos & val_repos) == 0
assert len(train_repos & test_repos) == 0
assert len(val_repos & test_repos) == 0
```

Save the assertion result to `data/phase2_split_report.json` for the
reproducibility appendix.

---

## 7. Stratified Split Strategy

### 7.1 Strata

We stratify on the **(CWE, framework)** Cartesian product where possible:

- `(CWE-89, django)`, `(CWE-89, flask)`, `(CWE-89, unknown)`, …
- `(CWE-502, django)`, `(CWE-502, unknown)`, …

For strata with fewer than 10 samples (e.g., `(CWE-502, fastapi)`),
collapse to CWE-only stratification.

### 7.2 Split Ratios

- **Train: 70%** (1,805 samples)
- **Val:   15%** (387 samples)
- **Test:  15%** (387 samples)

Standard ratios for ML papers under 10K samples. Larger train fraction
(80%) would help raw accuracy but reduce val/test confidence intervals.

### 7.3 Reproducibility

`--seed 42` is the documented default. The exact split assignment is
deterministic given the seed and the current MongoDB sample set.

---

## 8. Tokenization Preview

### 8.1 Why It Matters

GraphCodeBERT uses a 512-token context window. Samples longer than that
must be truncated; the truncation strategy materially affects model
performance.

### 8.2 What We'll Do

- Run GraphCodeBERT tokenizer on **100 random training samples**
- Compute the token-length distribution: `min`, `p50`, `p90`, `p99`, `max`
- Decide truncation strategy:
  - If `p90 < 512` → no special handling needed
  - If `p90 ≥ 512` → use one of:
    - **Middle-extraction** (keep tokens around the line with highest
      vulnerability-pattern density)
    - **Sliding window** (split into overlapping 512-token chunks, predict
      per-chunk, aggregate via max-pooling)
    - **Function-only extraction** (use AST to extract just the vulnerable
      function, drop surrounding code)

### 8.3 Output

A `data/tokenization_stats.json` file with the distribution and the chosen
strategy. Phase 3 will use this to configure the dataloader.

---

## 9. Reproducibility Report

`data/phase2_split_report.json` will contain:

```json
{
  "seed": 42,
  "split_strategy": "GroupShuffleSplit on repo + stratified on (CWE, framework)",
  "totals": {"train": 1805, "val": 387, "test": 387},
  "per_cwe": {
    "CWE-89":  {"train": 842, "val": 181, "test": 180, ...},
    "CWE-22":  {"train": 313, "val":  68, "test":  67, ...},
    ...
  },
  "per_framework": {...},
  "per_source": {...},
  "leakage_check": {
    "train_val_repo_overlap": 0,
    "train_test_repo_overlap": 0,
    "val_test_repo_overlap": 0
  },
  "class_weight_method": "LDAM + DRW",
  "cvss_target_method": "Sub-vector multi-task + composed",
  "tokenization_strategy": "no_truncation",
  "configs_emitted": [
    "configs/class_weights.json",
    "configs/cvss_targets.json",
    "configs/augmentation_config.json"
  ]
}
```

This file is the ground truth for paper Section 5 ("Experimental Setup").

---

## 10. Summary of Methodological Choices

| Decision | Naïve choice | Our choice | Reference |
|---|---|---|---|
| Embedding training | Cross-entropy from scratch | **SupCon warmup (30% of epochs)** | Khosla et al. 2020 (NeurIPS) |
| Class weighting | Inverse frequency | **LDAM margins + DRW schedule** | Cao et al. 2019 (NeurIPS) |
| Optimizer | AdamW | **SAM-wrapped AdamW (ρ=0.05)** | Foret et al. 2021 (ICLR) |
| Sampler | Random | **WeightedRandomSampler in DRW Phase B** | PyTorch standard |
| Rare-class augmentation | None | **Hard negatives + 8× mutations on CWE-502** | See Phase 2.5 doc |
| CVSS targets | Band midpoint | **8 sub-vector multi-task heads** | Le et al. 2022 (MSR) |
| CVSS composer | Learned regression | **Deterministic CVSS 3.1 formula** | FIRST.org spec |
| Label noise handling | Equal weighting | **Confidence-weighted dual-task loss** | Standard noisy-label |
| Uncertainty | Point estimates | **Heteroscedastic head** | Kendall & Gal 2017 |
| Anti-leakage | Random split | **GroupShuffleSplit on repo** | PrimeVul (Ding 2024) |
| Stratification | None | **CWE × framework** | sklearn standard |
| Reproducibility | Implicit | **Seed + report JSON** | ML reproducibility checklist |
| Eval metric | Macro-F1 only | **+ LoC-to-Scan + per-CWE F1 + ECE** | TDSC standard |
| Attribution method | Attention rollout only | **Captum: Rollout vs IG vs DeepLIFT** | Sundararajan 2017 / Shrikumar 2017 |
| Deployment artifact | Gradio demo only | **+ GitHub Action / pre-commit hook** | Use Case 3 demonstration |

Each row is defensible against a Q1 reviewer. Together they signal a
methodology paper, not just an empirical results paper.

---

## 11. Implementation Plan (When Approved)

### Files to Create

```
src/labeler/
  ├── data_prep.py              (already exists — extend)
  ├── stratified_splitter.py    (new — GroupShuffleSplit + stratified)
  ├── class_weights.py          (new — LDAM + DRW + Effective Number)
  └── cvss_targets.py           (new — sub-vector parsing + composer)

scripts/
  └── run_phase2.py             (rewrite — orchestrate the pipeline)

configs/
  ├── class_weights.json        (emitted by run_phase2.py)
  ├── cvss_targets.json         (emitted by run_phase2.py)
  └── augmentation_config.json  (manually authored, used by Phase 3)

data/
  ├── phase2_split_report.json  (emitted by run_phase2.py)
  └── tokenization_stats.json   (emitted by run_phase2.py)
```

### Run Command

```bash
.venv/bin/python3 scripts/run_phase2.py --seed 42
```

### Expected Runtime

- MongoDB load: ~5s
- Splitting + stratification: ~10s
- Class weight computation: <1s
- CVSS target parsing: ~30s (parses 1,113 CVSS vectors)
- Tokenization preview (100 samples): ~20s (downloads tokenizer first run)
- Total: **under 2 minutes**

### Expected Output

- All 2,579 MongoDB documents updated with a `split` field
- 5 JSON config/report files written
- Console summary table showing the split distribution

---

## 12. Phase 2 → Phase 3 Handoff

After Phase 2 completes, Phase 3 (model training) should be able to run:

```python
from src.labeler.data_prep import load_split
from src.labeler.class_weights import load_ldam_config
from src.labeler.cvss_targets import load_cvss_targets

train, val, test = load_split()  # MongoDB queries by split field
ldam = load_ldam_config()        # configs/class_weights.json
cvss = load_cvss_targets()       # configs/cvss_targets.json

model = GraphCodeBERTDualTask(
    num_cwe_classes=7,
    cvss_subvector_heads=8,
    ldam_config=ldam,
    heteroscedastic=True,
)

trainer = Trainer(
    model=model,
    train_dataset=train,
    val_dataset=val,
    drw_schedule=ldam["drw_schedule"],
    confidence_weighting=True,
    class_balanced_sampling=True,
)
trainer.train()
```

with no further data preparation required.

---

## 13. Open Questions for Discussion

1. **Augmentation timing.** Should mutations be generated offline (Phase 2,
   stored in MongoDB) or online (Phase 3, on-the-fly per epoch)? Online
   is more diverse; offline is reproducible. Recommend online with a
   per-epoch seed.

2. **CVSS scalar regression head — keep or drop?** The sub-vector heads
   already determine the score deterministically. A scalar head adds an
   extra signal but also extra parameters. Recommend keeping it as a small
   auxiliary loss (λ = 0.1) for training stability.

3. **DRW switch point.** Standard is 80% of training. Worth ablating with
   60%, 70%, 80%, 90%.

4. **Pseudo-labeling.** Worth implementing now or as a Phase 2.5 extension?
   Recommend treating as a Phase 2.5 experiment for the paper's "ablation"
   section.

---

---

## 14. Methodology Suggestions Considered and Rejected

For transparency and to anticipate reviewer questions, we explicitly
considered and rejected the following:

### 14.1 Joern + GNN-Transformer Hybrid — REJECTED

**The suggestion:** Use Joern (or `pyjoern`) to extract Control Flow Graphs
and Program Dependence Graphs explicitly, then feed them through a Gated
Graph Neural Network whose embeddings concatenate with GraphCodeBERT's.

**Why rejected:**
1. **Tooling fit.** Joern is a Java tool primarily targeting C/C++. The
   community Python fork (`pyjoern`) is incomplete — it does not fully
   parse Django decorators, Flask `Blueprint` patterns, SQLAlchemy ORM,
   or async-await syntax. ~35% of our dataset uses Django/Flask. Feeding
   Joern code it doesn't understand introduces noisy graphs.
2. **Engineering cost.** Implementing a GGNN-Transformer hybrid is a 2–3
   month project (custom PyTorch Geometric code, dual-architecture
   tuning, gradient-flow debugging).
3. **Empirical reality.** GraphCodeBERT already incorporates data-flow
   information from pre-training. Devign (Zhou 2019) and ReVeal (Chakraborty
   2022) found that adding explicit graphs to transformer baselines yields
   only 1–3 F1 points on similar-sized datasets — not enough to justify
   the cost.
4. **Overfitting risk.** With 1,805 training samples, a GNN with extra
   parameters will overfit before learning useful graph features.

**Reviewer rebuttal:** Cite Devign and ReVeal results showing parity
between token+DFG models and GNN models on small datasets.

### 14.2 ONNX / 4-bit Quantization for Demo — REJECTED

**The suggestion:** Export the model to ONNX or use bitsandbytes 4-bit
quantization to drop demo latency from 400ms to <100ms.

**Why rejected:**
1. **400ms is acceptable** for an interactive demo. Users do not perceive
   latency below 500ms as sluggish.
2. **ONNX export of GraphCodeBERT is fragile** — the custom data-flow
   attention layers do not always export cleanly, and we'd be debugging
   an export pipeline instead of doing research.
3. **4-bit quantization degrades accuracy by 2–5 F1 points** on
   125M-parameter encoder models (per QLoRA paper and follow-ups). This
   would invalidate our published results.
4. **Engineering risk for cosmetic reward.** This is deployment polish,
   not a research contribution.

**Future work mention:** We note in Section 7 of the paper that
production deployment would benefit from quantization, with the relevant
caveat about accuracy degradation.

### 14.3 Other Considered, Not Adopted

- **Pseudo-labeling for missing CVSS** — kept as an ablation experiment in
  Section 6, not part of the main pipeline (adds complexity without
  changing the main contribution narrative).
- **Knowledge distillation from a larger model** — out of scope; we have
  no larger teacher model available without re-training one ourselves.
- **Adversarial training (FGSM/PGD on token embeddings)** — replaced by
  the simpler and more interpretable red-team mutation strategy in
  Phase 2.5.

---

**End of design document. Awaiting approval to begin implementation.**
