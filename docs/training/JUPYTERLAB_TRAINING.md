# Phase 3 Training on JupyterLab (V100 GPU)

End-to-end guide to train the dual-task GraphCodeBERT vulnerability
model in a JupyterLab environment with a V100. Produces `best.pt` —
the trained checkpoint that becomes the learned-detector row in the
evaluation harness.

---

## What gets trained

- **Model:** GraphCodeBERT (126.65M params), dual-task head — CWE
  classification + CVSS regression on a shared encoder.
- **Loss:** weighted cross-entropy (CWE, class weights from Phase 2)
  + Huber (CVSS), summed with configurable α/β.
- **Optimizer:** SAM (Sharpness-Aware Minimization) wrapping AdamW
  (lr=2e-5, ρ=0.05).
- **Schedule:** SupCon warmup (3 ep) → LDAM Phase A (5 ep) →
  DRW Phase B with Effective-Number weights + class-balanced sampler
  (2 ep). Total: **10 epochs**.
- **Online augmentation:** 3 mutators applied during training; the 4th
  (`string_split`) is held out for the test-time robustness probe.
- **Dataset:** 8 classes (7 active CWEs + safe) — `CWE-89, 78, 22,
  79, 94, 918, 502, safe`. Splits: **607 train / 127 val / 132 test**,
  already baked into each sample's `.meta.json`.
- **Outputs:** `best.pt`, `last.pt`, `history.json`, TensorBoard events.

**Estimated wall-clock on a V100 16 GB:** ~3–6 hours for the full
10-epoch schedule. The SAM double-pass is the bottleneck — add
`--no-sam` to roughly halve it at a small generalization cost.

---

## Step 1 — Upload the bundle

Upload `sec_code_train_bundle.zip` (11 MB) to your JupyterLab
environment. Use the file-browser **Upload** button, or drag-and-drop
into the JupyterLab tab. Put it next to where you want the project to
live (typically your home directory).

---

## Step 2 — Create a notebook

Open a new Python 3 notebook in the same directory as the uploaded
zip. Set the kernel to whatever JupyterLab provides with CUDA — the
default Python 3 kernel is usually fine if the host has GPU drivers
installed.

---

## Step 3 — Notebook cells

Paste each block into its own cell. Run them top-to-bottom.

### Cell 1 — unpack the bundle

```python
import os, zipfile, pathlib

ZIP = "sec_code_train_bundle.zip"        # adjust if you put it elsewhere
WORK = pathlib.Path.home() / "sec_code"

if not WORK.exists():
    WORK.mkdir()
    with zipfile.ZipFile(ZIP) as zf:
        zf.extractall(WORK)

os.chdir(WORK)
print("cwd:", os.getcwd())
print("contents:", sorted(os.listdir(".")))
```

Expect to see `src`, `scripts`, `configs`, `data`, `requirements.txt`.

### Cell 2 — install Python dependencies

V100 hosts almost always ship with a CUDA-enabled PyTorch already
installed — **do not reinstall `torch`** unless you have to. Install
only the model deps:

```python
!pip install -q transformers black jsonlines python-dotenv tensorboard
```

If `import torch` later fails, install PyTorch matching the host's
CUDA version (check with `nvidia-smi`):

```python
# Example for CUDA 12.1 hosts — adjust if nvidia-smi says different
!pip install -q torch>=2.2.0 --index-url https://download.pytorch.org/whl/cu121
```

### Cell 3 — confirm the V100 is visible

```python
import torch
print("CUDA available:", torch.cuda.is_available())
if torch.cuda.is_available():
    print("Device:", torch.cuda.get_device_name(0))
    print("VRAM (GB):", round(torch.cuda.get_device_properties(0).total_memory / 1e9, 1))
```

Expect `CUDA available: True`, device `Tesla V100-...`, and ~16 GB
(PCIe variant) or ~32 GB (SXM2 variant). Note which one — it
determines the batch size in Cell 5.

### Cell 4 — dry run (build everything, train nothing)

```python
!python scripts/run_phase3_train.py --device cuda --dry-run
```

Expect log lines reporting:
- `Train samples: ...` / `Val samples: ...`
- `Model: 126.65M params total`
- `Schedule: 10 epochs total (warmup=3, A=5, B=2)`
- `--dry-run: skipping training`

If it fails here, fix it before spending hours of GPU time. The
usual culprit is a missing pip package — install it and re-run from
Cell 4.

### Cell 5 — the real training run

Pick the line that matches your V100:

**V100 16 GB (PCIe):**

```python
!python scripts/run_phase3_train.py \
  --device cuda \
  --batch-size 16 --eval-batch-size 32 --num-workers 4 \
  --warmup-epochs 3 --phase-a-epochs 5 --phase-b-epochs 2 \
  --output-dir runs/phase3_v1
```

**V100 32 GB (SXM2):**

```python
!python scripts/run_phase3_train.py \
  --device cuda \
  --batch-size 32 --eval-batch-size 64 --num-workers 4 \
  --warmup-epochs 3 --phase-a-epochs 5 --phase-b-epochs 2 \
  --output-dir runs/phase3_v1
```

Per-epoch lines look like:

```
Epoch 0 (warmup):  loss=2.4118  val_macro_f1=0.2210  (...)
Epoch 3 (phase_a): loss=0.9821  val_macro_f1=0.6443  (...)
Epoch 9 (phase_b): loss=0.4112  val_macro_f1=0.7891  (...)
```

Watch for a macro-F1 jump at the warmup→phase_a transition (SupCon +
LDAM kicks in) and again at phase_a→phase_b (Effective-Number weights
help rare classes — the per-class CWE-502 F1 should climb).

### Cell 6 — verify outputs

```python
import json, os
out = "runs/phase3_v1"
print("files:", os.listdir(out))
hist = json.load(open(f"{out}/history.json"))
print("final epoch:", hist[-1] if isinstance(hist, list) else hist)
```

Expect `best.pt`, `last.pt`, `history.json`, and a `tb/` directory.

---

## Long-running tip — survive a kernel disconnect

JupyterLab cells stop running if the browser tab loses its websocket.
For a 3–6 hour job, launch the training as a background process from
a terminal cell instead, so the kernel can disconnect freely:

```python
!nohup python scripts/run_phase3_train.py \
  --device cuda \
  --batch-size 16 --eval-batch-size 32 --num-workers 4 \
  --warmup-epochs 3 --phase-a-epochs 5 --phase-b-epochs 2 \
  --output-dir runs/phase3_v1 \
  > runs/phase3_v1.log 2>&1 &
```

Then tail it from any cell:

```python
!tail -n 30 runs/phase3_v1.log
```

Or open a JupyterLab terminal (**File → New → Terminal**) and run:

```bash
tail -f ~/sec_code/runs/phase3_v1.log
watch -n 2 nvidia-smi
```

---

## Download the checkpoint

Once `runs/phase3_v1/` contains `best.pt` + `history.json`:

1. In the file browser, right-click `best.pt` → **Download** (~500 MB).
2. Also download `history.json` (tiny).
3. On your Mac, place them at `runs/phase3_v1/best.pt` and
   `runs/phase3_v1/history.json` inside the project. `runs/` is
   gitignored, so the checkpoint stays local.

---

## Troubleshooting

- **`CUDA out of memory`** — halve `--batch-size` (and
  `--eval-batch-size`). Add `--no-sam` for a further ~25% VRAM cut at
  a generalization cost.
- **HF tokenizer download fails** — pre-download once:
  ```python
  !python -c "from transformers import AutoTokenizer, AutoModel; \
    AutoTokenizer.from_pretrained('microsoft/graphcodebert-base'); \
    AutoModel.from_pretrained('microsoft/graphcodebert-base')"
  ```
  Cached under `~/.cache/huggingface/`.
- **`ModuleNotFoundError`** during dry run — `pip install` the named
  module and re-run from Cell 4.
- **Slow data loading (GPU under-utilized)** — bump `--num-workers`
  to 8. Augmentation is CPU-bound.
- **Want a smoke test first** — drop to 1 of each phase:
  `--warmup-epochs 1 --phase-a-epochs 1 --phase-b-epochs 1 --output-dir runs/smoke`.
  Should finish in ~15 min on V100. Confirms the full pipeline works
  before you commit several hours.
- **Reproducibility** — the run is seeded (`--seed 42`); re-running
  gives the same trajectory.

---

## What happens next (back on the Mac)

With `best.pt` local, the next milestone is wiring it into the
evaluation harness (`src/eval/detectors/`) as a `Detector` so it
produces a row alongside Bandit and Semgrep. Then run the held-out
`string_split` robustness eval — the headline CASTLE-rebuttal
experiment. Inference on the 132-sample test set is CPU-only.
