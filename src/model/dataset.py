"""
src/model/dataset.py — PyTorch Dataset for the dual-task model.

Each ``__getitem__`` produces a single training example:
  • Tokenized code (input_ids, attention_mask) — possibly mutated by
    the on-the-fly augmenter
  • CWE class label (integer)
  • 8 CVSS sub-vector class labels (integers, with -100 for "missing"
    so PyTorch's CrossEntropyLoss with ignore_index=-100 ignores them)
  • CVSS scalar regression target (float, or NaN if unavailable)
  • Per-sample loss weight (float in [0, 1]) for confidence-weighted loss
  • is_hard_negative flag — used by the trainer for sampler logic

The dataset is built from disk meta files and the JSON configs emitted
by Phase 2/2b. It can be re-used unchanged for train/val/test by
filtering on ``split``.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import torch
from torch.utils.data import Dataset

from src.labeler.cvss_targets import SUBVECTOR_CODES
from src.utils.cwe_taxonomy import BLOCKED_SOURCE_CWE
from src.utils.file_utils import has_cwe_sink
from src.utils.logger import get_logger

_logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constants matching labeler/data_prep.py
# ---------------------------------------------------------------------------

# CWE → class index. Hard negatives carry cwe="safe" (last index).
#
# Indices 0-6 preserve the v1/v2 ordering. Phase 2B (2026-05-13) made
# multiple narrowings: dropped CWE-77 (merged into CWE-78), then dropped
# CWE-434 after the Stage-1 audit found its sink patterns produced 100% FPs.
# Final benchmark vocabulary: 7 sink-shaped Top-25 Python CWEs + safe = 8 classes.
CWE_TO_INDEX: dict[str, int] = {
    "CWE-89":  0,
    "CWE-78":  1,
    "CWE-22":  2,
    "CWE-79":  3,
    "CWE-94":  4,
    "CWE-918": 5,
    "CWE-502": 6,
    "safe":    7,
}
INDEX_TO_CWE: list[str] = [
    "CWE-89", "CWE-78", "CWE-22", "CWE-79",
    "CWE-94", "CWE-918", "CWE-502",
    "safe",
]

# Sub-vector code → class index for each of the 8 heads.
# Must match SUBVECTOR_CODES from labeler/cvss_targets.
SUBVECTOR_CODE_TO_INDEX: dict[str, dict[str, int]] = {
    key: {code: i for i, code in enumerate(codes)}
    for key, codes in SUBVECTOR_CODES.items()
}

# Sentinel for "no label available" — PyTorch's CE loss ignores -100 by default
IGNORE_INDEX = -100


# ---------------------------------------------------------------------------
# Sample loading
# ---------------------------------------------------------------------------

def load_samples_from_disk(
    raw_dir: str,
    split: str | None = None,
    *,
    apply_sink_filter: bool = True,
) -> list[dict]:
    """
    Walk ``raw_dir/*.meta.json`` and return sample dicts. If ``split`` is
    given, filter to samples with that split assignment.

    Phase 2B sink filter (apply_sink_filter=True, default):
      • Hard negatives and cwe="safe" samples pass through unfiltered.
      • Samples whose (source, cwe) is in BLOCKED_SOURCE_CWE are dropped.
      • Other samples must have either has_cwe_sink=True in meta (schema
        2.1+) or must pass has_cwe_sink() recomputed on the fly (older
        schema 2.0 samples that pre-date Phase 2B).

    Pass apply_sink_filter=False for ablation runs where you explicitly
    want to train on the unfiltered dataset.
    """
    raw = Path(raw_dir)
    if not raw.exists():
        return []

    out: list[dict] = []
    filtered_sink = 0
    filtered_blocked = 0
    for meta_path in sorted(raw.glob("*.meta.json")):
        try:
            m = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if split is not None and m.get("split") != split:
            continue

        # Locate the corresponding .py file with the source code
        py_path = meta_path.with_suffix("").with_suffix(".py")
        code = ""
        if py_path.exists():
            try:
                code = py_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass
        else:
            code = m.get("code_before", "")

        if not code or not m.get("cwe"):
            continue

        # Phase 2B training-time gate. Hard negatives and "safe" samples
        # pass; original-CWE positives must have a category-defining sink.
        if apply_sink_filter and not m.get("is_hard_negative") and m.get("cwe") != "safe":
            cwe = m["cwe"]
            source = m.get("source", "unknown")
            if (source, cwe) in BLOCKED_SOURCE_CWE:
                filtered_blocked += 1
                continue
            cached = m.get("has_cwe_sink")
            if cached is False:
                filtered_sink += 1
                continue
            if cached is None:
                # Pre-Phase-2B sample — compute on the fly
                ok, _ = has_cwe_sink(code, cwe, file_path=m.get("file_path"))
                if not ok:
                    filtered_sink += 1
                    continue

        out.append({
            "id":               m["id"],
            "content_hash":     m.get("content_hash"),
            "code":             code,
            "cwe":              m["cwe"],
            "split":            m.get("split"),
            "framework":        m.get("framework"),
            "source":           m.get("source"),
            "is_hard_negative": m.get("is_hard_negative", False),
            "label_confidence": m.get("label_confidence"),
        })

    if apply_sink_filter and (filtered_sink or filtered_blocked):
        _logger.info(
            f"Phase 2B gate filtered {filtered_sink + filtered_blocked} samples "
            f"from {raw_dir}"
            + (f" (split={split})" if split else "")
            + f" — sink_absent={filtered_sink}, blocked_source={filtered_blocked}"
        )
    return out


def load_cvss_targets(path: str) -> dict[str, dict]:
    """Load the configs/cvss_targets.json blob and return its ``targets`` map."""
    blob = json.loads(Path(path).read_text(encoding="utf-8"))
    return blob.get("targets", {})


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

class DualTaskDataset(Dataset):
    """
    Returns one tokenized + labelled example per ``__getitem__``.

    Output schema::

        {
          "input_ids":         LongTensor [max_len]
          "attention_mask":    LongTensor [max_len]
          "cwe_label":         LongTensor (scalar int)
          "subvector_labels":  dict[str, LongTensor]   — 8 entries; missing → IGNORE_INDEX
          "cvss_score":        FloatTensor (scalar float; NaN if missing)
          "loss_weight":       FloatTensor (scalar)
          "is_hard_negative":  BoolTensor
          "sample_id":         str
        }
    """

    def __init__(
        self,
        samples: list[dict],
        cvss_targets: dict[str, dict],
        tokenizer: Any,
        max_length: int = 512,
        augmenter: Any | None = None,
        epoch: int = 0,
    ):
        self.samples = list(samples)
        self.cvss_targets = cvss_targets
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.augmenter = augmenter
        self.epoch = epoch

    def set_epoch(self, epoch: int) -> None:
        """Update the epoch — used by the augmenter to vary mutations."""
        self.epoch = epoch

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> dict[str, Any]:
        sample = self.samples[idx]
        code = sample["code"]

        # Apply on-the-fly augmentation if configured
        if self.augmenter is not None:
            code = self.augmenter.augment(
                source=code,
                sample_id=sample["id"],
                epoch=self.epoch,
                is_hard_negative=sample.get("is_hard_negative", False),
            )

        # Tokenize. truncation=True will cut at max_length tokens.
        toks = self.tokenizer(
            code,
            truncation=True,
            max_length=self.max_length,
            padding="max_length",
            return_tensors="pt",
        )
        input_ids = toks["input_ids"].squeeze(0).long()
        attention_mask = toks["attention_mask"].squeeze(0).long()

        # CWE label
        cwe = sample["cwe"]
        cwe_label = torch.tensor(
            CWE_TO_INDEX.get(cwe, CWE_TO_INDEX["safe"]),
            dtype=torch.long,
        )

        # Look up CVSS targets via content_hash (fallback to id)
        target_key = sample.get("content_hash") or sample["id"]
        target = self.cvss_targets.get(target_key, {})
        sub_vectors = target.get("sub_vectors") or {}

        subvector_labels: dict[str, torch.Tensor] = {}
        for key, codes in SUBVECTOR_CODES.items():
            code_letter = sub_vectors.get(key)
            if code_letter and code_letter in SUBVECTOR_CODE_TO_INDEX[key]:
                idx_val = SUBVECTOR_CODE_TO_INDEX[key][code_letter]
            else:
                idx_val = IGNORE_INDEX
            subvector_labels[key] = torch.tensor(idx_val, dtype=torch.long)

        # CVSS scalar regression target — NaN signals "no target"
        score = target.get("cvss_score")
        cvss_score = torch.tensor(
            float(score) if score is not None else float("nan"),
            dtype=torch.float32,
        )

        loss_weight = torch.tensor(
            float(target.get("loss_weight", 0.0)),
            dtype=torch.float32,
        )

        return {
            "input_ids":         input_ids,
            "attention_mask":    attention_mask,
            "cwe_label":         cwe_label,
            "subvector_labels":  subvector_labels,
            "cvss_score":        cvss_score,
            "loss_weight":       loss_weight,
            "is_hard_negative":  torch.tensor(
                bool(sample.get("is_hard_negative", False)), dtype=torch.bool,
            ),
            "sample_id":         sample["id"],
        }


# ---------------------------------------------------------------------------
# Collate function
# ---------------------------------------------------------------------------

def collate_dual_task(batch: list[dict]) -> dict[str, Any]:
    """
    Collate a list of dataset items into a batched dict suitable for the
    model's forward pass.

    Stacks tensor fields, lists everything else.
    """
    out: dict[str, Any] = {}
    out["input_ids"]      = torch.stack([b["input_ids"]      for b in batch])
    out["attention_mask"] = torch.stack([b["attention_mask"] for b in batch])
    out["cwe_label"]      = torch.stack([b["cwe_label"]      for b in batch])
    out["cvss_score"]     = torch.stack([b["cvss_score"]     for b in batch])
    out["loss_weight"]    = torch.stack([b["loss_weight"]    for b in batch])
    out["is_hard_negative"] = torch.stack([b["is_hard_negative"] for b in batch])
    out["sample_id"]      = [b["sample_id"] for b in batch]

    # Stack each sub-vector head's labels separately
    out["subvector_labels"] = {
        key: torch.stack([b["subvector_labels"][key] for b in batch])
        for key in SUBVECTOR_CODES
    }
    return out


# ---------------------------------------------------------------------------
# Factory: end-to-end builder
# ---------------------------------------------------------------------------

def build_dataset(
    raw_dir: str,
    split: str,
    cvss_targets_path: str,
    tokenizer: Any,
    max_length: int = 512,
    augmenter: Any | None = None,
    epoch: int = 0,
    *,
    apply_sink_filter: bool = True,
) -> DualTaskDataset:
    """One-line construction of a dataset for a given split.

    Pass apply_sink_filter=False to bypass the Phase 2B sink-presence gate
    (used only for ablation — defaults to on)."""
    samples = load_samples_from_disk(raw_dir, split=split, apply_sink_filter=apply_sink_filter)
    cvss = load_cvss_targets(cvss_targets_path)
    return DualTaskDataset(
        samples=samples,
        cvss_targets=cvss,
        tokenizer=tokenizer,
        max_length=max_length,
        augmenter=augmenter,
        epoch=epoch,
    )


# ---------------------------------------------------------------------------
# Distribution diagnostics
# ---------------------------------------------------------------------------

def per_split_stats(samples: list[dict]) -> dict[str, dict[str, int]]:
    """Return {split → {cwe → count}} for sanity-check logging."""
    out: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for s in samples:
        out[s.get("split") or "unknown"][s.get("cwe") or "unknown"] += 1
    return {k: dict(v) for k, v in out.items()}
