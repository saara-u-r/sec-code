# Phase 3 Training — GPU Handoff Instructions

This document is a self-contained guide to running the Phase 3 training
job on a remote GPU machine. Follow it top-to-bottom.

---

## What we are doing

Train the dual-task GraphCodeBERT vulnerability model end-to-end, using:

- **3-phase schedule** — SupCon warmup (3 ep) → LDAM Phase A (5 ep) →
  DRW Phase B with Effective-Number weights + class-balanced sampler
  (2 ep). Total: **10 epochs**.
- **SAM optimizer** wrapping AdamW (lr=2e-5, ρ=0.05).
- **Online augmentation** — 3 mutators applied during training; the
  4th (`string_split`) is held out as the test-time robustness probe.
- **Inputs (after Phase 2B re-scope, 2026-05-13):** **905 train / 185 val
  / 182 test** = 1,272 trainable samples across **11 classes** (10 active
  CWEs + safe). Split is repo-group stratified, anti-leakage verified.
  See `PHASE_2B_RESCOPE_2026-05-13.md` for the per-CWE breakdown.
- **Outputs:** `best.pt` (highest val/cwe_macro_f1), `last.pt`,
  `history.json` (per-epoch metrics), TensorBoard event files.

**Estimated wall-clock:** 2–6 hr on A100 80 GB; 4–8 hr on a 3090/4090;
8–14 hr on a T4. The model is 126.65M parameters; the bottleneck is
the SAM double-pass.

**Class vocabulary (11 outputs):** see `src/model/dataset.py:INDEX_TO_CWE`.
Index order: CWE-89, 78, 22, 79, 94, 918, 502, 77, 434, 798, safe. v1/v2
checkpoints are NOT compatible — the classifier head expanded from
8 → 11 outputs.

---

## Files to copy to the GPU machine

Only the code, configs, and pre-split dataset. **Skip** `.venv/`,
`runs/`, `logs/`, `__pycache__`, `.git/`, the various `*.md` design
docs, and the intermediate data dirs (`data/cvefixes`, `data/datasets`,
etc.).

| Path                                    | Size        | Why |
|-----------------------------------------|------------:|-----|
| `src/`                                  | small       | All Python source |
| `scripts/run_phase3_train.py`           | small       | Training entry point |
| `configs/class_weights.json`            | 1.6 KB      | LDAM margins + DRW schedule |
| `configs/cvss_targets.json`             | 531 KB      | Per-sample CVSS targets |
| `configs/augmentation_config.json`      | small       | Mutator config |
| `configs/config.yaml`                   | small       | Project-wide constants |
| `data/raw/`                             | **~100 MB** | 1,275 `.meta.json` + 1,275 `.py` (split assignments populated by Phase 2 re-run on 2026-05-13) |
| `requirements.txt`                      | small       | Python deps |
| `tests/` *(optional)*                   | small       | For a post-install sanity run |

**Recommended one-shot rsync from your laptop:**

```bash
# Run from the repo root on this Mac
rsync -avz --progress \
  --exclude='.venv' --exclude='runs' --exclude='logs' \
  --exclude='__pycache__' --exclude='*.pyc' \
  --exclude='.git' --exclude='*.md' --exclude='.pytest_cache' \
  --exclude='data/cvefixes' --exclude='data/datasets' \
  --exclude='data/github_advisory_db' --exclude='data/pypa_advisory_db' \
  --exclude='data/labeled' --exclude='data/adversarial' \
  src scripts configs data tests requirements.txt \
  USER@GPU_HOST:/path/to/sec_code/
```

Total transfer: ~155 MB.

---

## One-time GPU machine setup

1. **Clone or `mkdir`** the project directory and `cd` into it
   (matching where you rsynced to).

2. **Create a Python 3.10+ venv:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install PyTorch with CUDA support first** (the version in
   `requirements.txt` is CPU-only on most installs). Pick the index URL
   matching your CUDA version — see <https://pytorch.org/get-started/locally/>:
   ```bash
   # CUDA 12.1 example
   pip install torch>=2.2.0 --index-url https://download.pytorch.org/whl/cu121
   ```

4. **Install everything else:**
   ```bash
   pip install -r requirements.txt
   pip install tensorboard          # for SummaryWriter logging
   pip install black                # used by the augmenter to format mutated code
   ```

5. **Sanity-check that GPU is visible:**
   ```bash
   python -c "import torch; print('cuda:', torch.cuda.is_available(), torch.cuda.get_device_name(0))"
   ```
   Expect: `cuda: True NVIDIA A100 80GB PCIe` (or your card).

6. **(Optional but recommended)** Run the test suite to confirm the
   install is healthy:
   ```bash
   python -m pytest tests/ -q
   ```
   Expect: **354 passed**.

7. **Pre-flight dry-run** — assembles every component (loads
   tokenizer, builds model on GPU, reads splits) without spending
   epochs:
   ```bash
   python scripts/run_phase3_train.py --device cuda --dry-run
   ```
   Expect: log lines saying "Train samples: 905", "Val samples: 185",
   "Model: 126.65M params", "Schedule: 10 epochs total (warmup=0, A=8,
   B=2)", followed by "--dry-run: skipping training".

---

## The training command

Pick the line that matches your GPU:

**A100 / H100 (40+ GB VRAM)** — recommended:
```bash
python scripts/run_phase3_train.py \
  --device cuda \
  --batch-size 64 \
  --eval-batch-size 128 \
  --num-workers 4 \
  --warmup-epochs 3 \
  --phase-a-epochs 5 \
  --phase-b-epochs 2 \
  --output-dir runs/phase3_v1
```

**3090 / 4090 / A10 (~24 GB VRAM)**:
```bash
python scripts/run_phase3_train.py \
  --device cuda \
  --batch-size 32 \
  --eval-batch-size 64 \
  --num-workers 4 \
  --warmup-epochs 3 \
  --phase-a-epochs 5 \
  --phase-b-epochs 2 \
  --output-dir runs/phase3_v1
```

**T4 / 4060 Ti (~16 GB VRAM)**:
```bash
python scripts/run_phase3_train.py \
  --device cuda \
  --batch-size 16 \
  --eval-batch-size 32 \
  --num-workers 4 \
  --warmup-epochs 3 \
  --phase-a-epochs 5 \
  --phase-b-epochs 2 \
  --output-dir runs/phase3_v1
```

### Run it in the background so SSH disconnect doesn't kill it

```bash
nohup python scripts/run_phase3_train.py \
  --device cuda --batch-size 32 --eval-batch-size 64 --num-workers 4 \
  --warmup-epochs 3 --phase-a-epochs 5 --phase-b-epochs 2 \
  --output-dir runs/phase3_v1 \
  > runs/phase3_v1.log 2>&1 &
echo $!  # remember this PID
```

Or in a `tmux` / `screen` session:
```bash
tmux new -s train
# run the command above (without nohup), then Ctrl-b d to detach
```

---

## What to expect during training

Per-epoch console line will look like:
```
Epoch 0 (warmup): loss=2.4118  val_macro_f1=0.2210  (148.3s)
Epoch 1 (warmup): loss=1.8842  val_macro_f1=0.3104  (146.1s)
Epoch 2 (warmup): loss=1.5390  val_macro_f1=0.3812  (144.8s)
Epoch 3 (phase_a): loss=0.9821  val_macro_f1=0.6443  (149.0s)
...
Epoch 9 (phase_b): loss=0.4112  val_macro_f1=0.7891  (148.7s)
```

Big macro-F1 jump should happen at the **warmup → phase_a** transition
(SupCon embeddings + LDAM kicks in) and again at the
**phase_a → phase_b** transition (Effective-Number weights help the
rare classes — look for the per-class CWE-502 F1 to climb in the JSON).

### Live monitoring

```bash
# Tail the log
tail -f runs/phase3_v1.log

# Inspect the current history (rewritten each epoch)
cat runs/phase3_v1/history.json | python -m json.tool | tail -50

# TensorBoard (in another terminal) — port-forward if remote
tensorboard --logdir runs/phase3_v1/tb --bind_all --port 6006
# then on your laptop: ssh -L 6006:localhost:6006 USER@GPU_HOST
# open http://localhost:6006
```

### nvidia-smi watch (sanity-check the GPU is actually busy)

```bash
watch -n 2 nvidia-smi
```
You should see the Python process pinned at near-100% GPU utilization
during forward/backward, with VRAM usage stable (no leak).

---

## When training finishes

The `runs/phase3_v1/` directory will contain:

```
runs/phase3_v1/
├── best.pt          # best checkpoint by val/cwe_macro_f1 — use this for eval
├── last.pt          # final-epoch checkpoint
├── history.json     # every epoch's train + val metrics
└── tb/              # TensorBoard event files
```

### Copy results back to this Mac

From your laptop:
```bash
rsync -avz --progress \
  USER@GPU_HOST:/path/to/sec_code/runs/phase3_v1/ \
  ./runs/phase3_v1/
```

Each `.pt` checkpoint is ~500 MB (model weights + optimizer state).
Total: ~1.1 GB.

If you only need `best.pt` for evaluation, rsync just that file
(skip `last.pt` and the optimizer state would still be in there but
this is the minimum you need to do downstream eval).

---

## Troubleshooting

**`CUDA out of memory`** — drop `--batch-size`. Each halving roughly
halves VRAM. Also consider `--no-sam` (cuts memory by ~25% and runtime
in half, at the cost of generalization).

**`ModuleNotFoundError: tensorboard`** — install it:
```bash
pip install tensorboard
```
Or disable TB logging entirely with `--no-tensorboard` (history.json
still gets written).

**Slow data loading (GPU under-utilized)** — bump `--num-workers` to
8. The dataset uses on-the-fly augmentation which can be CPU-bound.

**Tokenizer download fails / hangs** — pre-download once on the GPU
box:
```bash
python -c "from transformers import AutoTokenizer, AutoModel; \
  AutoTokenizer.from_pretrained('microsoft/graphcodebert-base'); \
  AutoModel.from_pretrained('microsoft/graphcodebert-base')"
```
Cached under `~/.cache/huggingface/`.

**Want to resume from a checkpoint after a crash** — the trainer has a
`load_checkpoint()` method but no built-in resume CLI flag yet. The
fastest path is to just re-run; with seed 42 the loss trajectory is
deterministic.

**Want to run a shorter test first** — drop to 1 of each phase:
```bash
... --warmup-epochs 1 --phase-a-epochs 1 --phase-b-epochs 1 \
    --output-dir runs/smoke_test
```
Should complete in ~7 min on A100. Confirms the full pipeline works
before you commit several hours.

---

## What happens after training (back on your Mac)

Once `best.pt` is back on this machine, the next milestone is the
**held-out `string_split` robustness eval** — the headline
CASTLE-rebuttal experiment. That eval script doesn't exist yet; it's
the next thing to build. Success criterion from the design doc:
**≤ 3 F1 drop** between the standard test set and the
`string_split`-mutated test set.
