# Training the GraphCodeBERT model on Kaggle (free GPU)

A step-by-step guide to train the Phase 3 dual-task GraphCodeBERT model
on Kaggle's free GPU, with no local GPU and no cost. The output is
`best.pt` — the trained checkpoint that becomes the project's learned
detector row in the evaluation.

**Verified ready (2026-05-18):** the training pipeline runs cleanly
against the current 607 / 127 / 132 dataset (8 labels: 7 CWEs + safe);
`configs/class_weights.json` and `configs/cvss_targets.json` match the
current dataset; the model builds at 126.65M parameters.

**Expected wall-clock on a Kaggle T4:** roughly 1.5–4 hours for the full
10-epoch schedule — comfortably inside Kaggle's 12-hour session limit
and well within the 30 GPU-hours/week free quota.

---

## Before you start

1. A free Kaggle account — <https://www.kaggle.com>.
2. **Verify your phone number** in Kaggle account settings. This is
   required to enable notebook **Internet access**, which the training
   job needs to download the `microsoft/graphcodebert-base` weights from
   Hugging Face. Do this first — it is the most common blocker.

---

## Step 1 — Build the upload bundle (on your Mac)

Kaggle needs the code, configs, and dataset. `data/raw/` is gitignored,
so a `git clone` on Kaggle would not include it — you must upload a
bundle. From the project root:

```bash
cd /Users/saaraunnathi/Projects/sec_code
zip -r sec_code_train_bundle.zip \
  src scripts configs data/raw requirements.txt \
  -x '*__pycache__*' '*.pyc' '*.DS_Store'
```

This produces `sec_code_train_bundle.zip` (~150 MB). It contains
everything the trainer reads and nothing else (no `.venv`, no `runs/`,
no git history).

---

## Step 2 — Upload it as a Kaggle Dataset

1. Go to <https://www.kaggle.com/datasets> → **New Dataset**.
2. Drag in `sec_code_train_bundle.zip`. Kaggle auto-extracts the zip, so
   the files land as `src/`, `scripts/`, `configs/`, `data/`,
   `requirements.txt` inside the dataset.
3. Give it a title, e.g. **`sec-code-train-bundle`**. Note the **slug**
   Kaggle assigns (shown in the URL: `kaggle.com/datasets/<you>/sec-code-train-bundle`).
4. Click **Create**. Wait for processing to finish.

---

## Step 3 — Create the training notebook

1. <https://www.kaggle.com/code> → **New Notebook**.
2. In the notebook's right-hand **Settings** panel:
   - **Accelerator:** `GPU T4 x2` (or `GPU P100` — either is fine; the
     trainer uses one GPU).
   - **Internet:** **On** (needs the phone-verified account).
   - **Persistence:** not needed.
3. **Add Input** → **Datasets** → search for and attach your
   `sec-code-train-bundle` dataset. It mounts read-only at
   `/kaggle/input/sec-code-train-bundle/`.

---

## Step 4 — The notebook cells

Paste each block into its own cell. **Edit `DATASET` in Cell 1** to your
dataset's slug if you named it differently.

### Cell 1 — copy the bundle into the writable working dir

```python
import shutil, os

DATASET = "/kaggle/input/sec-code-train-bundle"   # <-- your dataset path
WORK = "/kaggle/working/sec_code"

if not os.path.exists(WORK):
    shutil.copytree(DATASET, WORK)
os.chdir(WORK)
print("cwd:", os.getcwd())
print("contents:", sorted(os.listdir(".")))
```

### Cell 2 — install the few dependencies Kaggle lacks

Kaggle's image already has CUDA-enabled PyTorch — **do not reinstall
torch.** Only the project's smaller deps are needed.

```python
!pip install -q transformers black jsonlines python-dotenv
```

### Cell 3 — confirm the GPU is visible

```python
import torch
print("CUDA available:", torch.cuda.is_available())
if torch.cuda.is_available():
    print("Device:", torch.cuda.get_device_name(0))
```

Expect `CUDA available: True` and a Tesla T4 (or P100).

### Cell 4 — dry run (build everything, train nothing)

```python
!python scripts/run_phase3_train.py --device cuda --dry-run
```

Expect lines reporting `Train samples: 607`, `Val samples: 127`,
`Model: 126.65M params`, then `--dry-run: skipping training`. If this
fails, fix it before spending GPU hours (usually a missing pip package
— install it and re-run).

### Cell 5 — the real training run

```python
!python scripts/run_phase3_train.py \
  --device cuda \
  --batch-size 16 --eval-batch-size 32 --num-workers 2 \
  --warmup-epochs 3 --phase-a-epochs 5 --phase-b-epochs 2 \
  --output-dir /kaggle/working/runs/phase3_v1 \
  --no-tensorboard
```

Per-epoch lines look like
`Epoch 3 (phase_a): loss=0.98 val_macro_f1=0.64 (...)`. Watch for the
macro-F1 jump at the warmup→phase_a transition.

### Cell 6 — check the result

```python
import json, os
out = "/kaggle/working/runs/phase3_v1"
print("files:", os.listdir(out))
hist = json.load(open(f"{out}/history.json"))
print("final epoch:", hist[-1] if isinstance(hist, list) else hist)
```

You want to see `best.pt`, `last.pt`, `history.json`.

---

## Step 5 — Run it and download the checkpoint

For a multi-hour job, use **Save Version → Save & Run All (Commit)**
(top-right). This runs the whole notebook in the background — you can
close the tab; it does not need to stay open.

When the committed run finishes:

1. Open the completed version → **Output** tab.
2. Download `runs/phase3_v1/best.pt` (~500 MB) and `history.json`
   (tiny).
3. On your Mac, put the checkpoint at
   `runs/phase3_v1/best.pt` in the project (the `runs/` directory is
   gitignored — the checkpoint stays local).

---

## Notes & troubleshooting

- **Session limit.** Kaggle caps a notebook session at 12 hours; this
  run needs far less. If you ever see it running long, add `--no-sam` to
  Cell 5 — it disables the Sharpness-Aware Minimization double-pass,
  roughly halving runtime at a small generalization cost.
- **`CUDA out of memory`.** Lower `--batch-size` to 8 (and
  `--eval-batch-size` to 16). The T4 has 16 GB; batch 16 should fit, but
  8 is the safe fallback.
- **HF download hangs / fails.** Internet is off — re-check Step 3
  settings and that your account is phone-verified.
- **`ModuleNotFoundError`** during the dry run — `pip install` the named
  module in Cell 2 and re-run from Cell 4.
- **Reproducibility.** The run is seeded (`--seed 42`); re-running gives
  the same trajectory.
- **Expectations.** The training split is small (607 samples) for a
  126M-parameter model, so expect a *modest*, somewhat variable
  macro-F1 — that is still a legitimate, reportable result. The point of
  this row is the **robustness drop**: a learned detector should lose F1
  under the mutators, unlike the SAST tools which lost ~0. That contrast
  is what validates the benchmark's adversarial methodology.

---

## After training — what to send back

Once `best.pt` is on your Mac, the remaining work is to wire it into the
evaluation harness (`src/eval/detectors/`) as a `Detector` so it
produces a row alongside Bandit and Semgrep. Share `history.json` (the
per-epoch metrics) and confirm `best.pt`'s location, and that
integration can be done locally — it needs only CPU for inference on the
132-sample test set.
