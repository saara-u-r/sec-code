"""
test_dataset.py — tests for the PyTorch Dataset.

Covers:
  • Sample loading (disk → list of dicts), split filtering
  • Tokenization shape, label assignment, sub-vector indexing
  • IGNORE_INDEX masking when targets are missing
  • Augmenter integration (if-given, called per __getitem__)
  • collate_dual_task batching
"""

from __future__ import annotations

import json

import pytest
import torch

from src.model.dataset import (
    CWE_TO_INDEX,
    IGNORE_INDEX,
    SUBVECTOR_CODE_TO_INDEX,
    DualTaskDataset,
    collate_dual_task,
    load_cvss_targets,
    load_samples_from_disk,
    per_split_stats,
)
from src.labeler.cvss_targets import SUBVECTOR_CODES


# ---------------------------------------------------------------------------
# Constants alignment
# ---------------------------------------------------------------------------

def test_cwe_index_mapping_complete():
    """All 7 target CWEs + safe → 8 indices, no holes."""
    expected = {"CWE-89", "CWE-78", "CWE-22", "CWE-79",
                "CWE-94", "CWE-918", "CWE-502", "safe"}
    assert set(CWE_TO_INDEX.keys()) == expected
    assert set(CWE_TO_INDEX.values()) == set(range(8))


def test_subvector_code_indices_match_codes_module():
    for key, codes in SUBVECTOR_CODES.items():
        for i, code in enumerate(codes):
            assert SUBVECTOR_CODE_TO_INDEX[key][code] == i


# ---------------------------------------------------------------------------
# load_samples_from_disk
# ---------------------------------------------------------------------------

def _write_meta(tmp_path, name, meta, code):
    (tmp_path / f"{name}.meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (tmp_path / f"{name}.py").write_text(code, encoding="utf-8")


def test_load_samples_filters_by_split(tmp_path):
    # Code must carry a category-defining sink to survive the Phase 2B gate.
    _write_meta(tmp_path, "s1",
        {"id": "s1", "cwe": "CWE-89", "split": "train", "framework": "django"},
        "def f(uid):\n    cursor.execute('SELECT * FROM users WHERE id = ' + uid)")
    _write_meta(tmp_path, "s2",
        {"id": "s2", "cwe": "CWE-79", "split": "test", "framework": "flask"},
        "def g(s):\n    return Markup(s)")

    train = load_samples_from_disk(str(tmp_path), split="train")
    assert len(train) == 1
    assert train[0]["id"] == "s1"

    test = load_samples_from_disk(str(tmp_path), split="test")
    assert len(test) == 1
    assert test[0]["id"] == "s2"


def test_load_samples_skips_missing_cwe(tmp_path):
    _write_meta(tmp_path, "s1",
        {"id": "s1", "cwe": None, "split": "train"}, "def f(): return 1")
    out = load_samples_from_disk(str(tmp_path), split="train")
    assert out == []


def test_load_samples_skips_missing_code(tmp_path):
    """Meta exists, .py missing, no embedded code_before — skip."""
    (tmp_path / "s1.meta.json").write_text(json.dumps({
        "id": "s1", "cwe": "CWE-89", "split": "train",
    }))
    out = load_samples_from_disk(str(tmp_path), split="train")
    assert out == []


# ---------------------------------------------------------------------------
# load_cvss_targets
# ---------------------------------------------------------------------------

def test_load_cvss_targets_round_trips(tmp_path):
    blob = {
        "_summary": {"total": 1},
        "targets": {
            "hash_a": {"cvss_score": 7.5, "sub_vectors": None, "loss_weight": 0.3},
        },
    }
    p = tmp_path / "targets.json"
    p.write_text(json.dumps(blob), encoding="utf-8")
    out = load_cvss_targets(str(p))
    assert "hash_a" in out
    assert out["hash_a"]["cvss_score"] == 7.5


# ---------------------------------------------------------------------------
# DualTaskDataset
# ---------------------------------------------------------------------------

def test_dataset_len(synthetic_samples, synthetic_cvss_targets, stub_tokenizer):
    ds = DualTaskDataset(
        samples=synthetic_samples,
        cvss_targets=synthetic_cvss_targets,
        tokenizer=stub_tokenizer,
        max_length=64,
    )
    assert len(ds) == 3


def test_dataset_item_shape(synthetic_samples, synthetic_cvss_targets, stub_tokenizer):
    ds = DualTaskDataset(
        samples=synthetic_samples,
        cvss_targets=synthetic_cvss_targets,
        tokenizer=stub_tokenizer,
        max_length=64,
    )
    item = ds[0]
    assert item["input_ids"].shape == (64,)
    assert item["attention_mask"].shape == (64,)
    assert item["cwe_label"].shape == ()
    assert item["cvss_score"].shape == ()
    assert item["loss_weight"].shape == ()
    # 8 sub-vector heads
    assert len(item["subvector_labels"]) == 8


def test_dataset_cwe_labels(synthetic_samples, synthetic_cvss_targets, stub_tokenizer):
    ds = DualTaskDataset(
        synthetic_samples, synthetic_cvss_targets, stub_tokenizer, max_length=64,
    )
    assert ds[0]["cwe_label"].item() == CWE_TO_INDEX["CWE-89"]
    assert ds[1]["cwe_label"].item() == CWE_TO_INDEX["CWE-502"]
    assert ds[2]["cwe_label"].item() == CWE_TO_INDEX["safe"]


def test_dataset_subvector_labels_full(synthetic_samples, synthetic_cvss_targets, stub_tokenizer):
    """Sample with full vector → all 8 sub-vector labels populated."""
    ds = DualTaskDataset(
        synthetic_samples, synthetic_cvss_targets, stub_tokenizer, max_length=64,
    )
    s1_labels = ds[0]["subvector_labels"]
    # AV:N → index 0 in SUBVECTOR_CODES["AV"]
    assert s1_labels["AV"].item() == 0
    # AC:L → index 0 in SUBVECTOR_CODES["AC"]
    assert s1_labels["AC"].item() == 0
    # C:H → index 2 in SUBVECTOR_CODES["C"] (N, L, H)
    assert s1_labels["C"].item() == 2


def test_dataset_subvector_labels_missing_uses_ignore_index(
    synthetic_samples, synthetic_cvss_targets, stub_tokenizer,
):
    """Sample with no vector → all 8 sub-vector labels = IGNORE_INDEX."""
    ds = DualTaskDataset(
        synthetic_samples, synthetic_cvss_targets, stub_tokenizer, max_length=64,
    )
    s2 = ds[1]  # CWE-502 sample with sub_vectors=None
    for key in SUBVECTOR_CODES:
        assert s2["subvector_labels"][key].item() == IGNORE_INDEX


def test_dataset_hardneg_no_targets_uses_ignore(
    synthetic_samples, synthetic_cvss_targets, stub_tokenizer,
):
    """Hardneg sample with no entry in targets dict → all IGNORE."""
    ds = DualTaskDataset(
        synthetic_samples, synthetic_cvss_targets, stub_tokenizer, max_length=64,
    )
    s3 = ds[2]
    for key in SUBVECTOR_CODES:
        assert s3["subvector_labels"][key].item() == IGNORE_INDEX
    # And cvss_score should be NaN
    assert torch.isnan(s3["cvss_score"])
    # loss_weight defaults to 0 when no entry
    assert s3["loss_weight"].item() == 0.0


def test_dataset_loss_weight_passes_through(
    synthetic_samples, synthetic_cvss_targets, stub_tokenizer,
):
    ds = DualTaskDataset(
        synthetic_samples, synthetic_cvss_targets, stub_tokenizer, max_length=64,
    )
    assert ds[0]["loss_weight"].item() == 1.0
    assert ds[1]["loss_weight"].item() == pytest.approx(0.3, rel=1e-6)


def test_dataset_is_hard_negative_flag(
    synthetic_samples, synthetic_cvss_targets, stub_tokenizer,
):
    ds = DualTaskDataset(
        synthetic_samples, synthetic_cvss_targets, stub_tokenizer, max_length=64,
    )
    assert not ds[0]["is_hard_negative"].item()
    assert ds[2]["is_hard_negative"].item()


# ---------------------------------------------------------------------------
# Augmenter integration
# ---------------------------------------------------------------------------

def test_dataset_calls_augmenter_when_given(
    synthetic_samples, synthetic_cvss_targets, stub_tokenizer,
):
    """If an augmenter is configured, __getitem__ must call .augment()."""
    calls = []

    class _SpyAugmenter:
        def augment(self, source, sample_id, epoch, is_hard_negative):
            calls.append((sample_id, epoch, is_hard_negative))
            return "def replaced(): return 0\n"

    ds = DualTaskDataset(
        synthetic_samples, synthetic_cvss_targets, stub_tokenizer,
        max_length=64, augmenter=_SpyAugmenter(), epoch=5,
    )
    _ = ds[0]
    assert calls == [("s1", 5, False)]


def test_dataset_set_epoch_propagates(
    synthetic_samples, synthetic_cvss_targets, stub_tokenizer,
):
    """set_epoch updates the epoch passed to the augmenter."""
    calls = []

    class _SpyAugmenter:
        def augment(self, source, sample_id, epoch, is_hard_negative):
            calls.append(epoch)
            return source

    ds = DualTaskDataset(
        synthetic_samples, synthetic_cvss_targets, stub_tokenizer,
        max_length=64, augmenter=_SpyAugmenter(), epoch=0,
    )
    _ = ds[0]
    ds.set_epoch(7)
    _ = ds[0]
    assert calls == [0, 7]


# ---------------------------------------------------------------------------
# collate_dual_task
# ---------------------------------------------------------------------------

def test_collate_stacks_correctly(
    synthetic_samples, synthetic_cvss_targets, stub_tokenizer,
):
    ds = DualTaskDataset(
        synthetic_samples, synthetic_cvss_targets, stub_tokenizer, max_length=64,
    )
    batch = collate_dual_task([ds[0], ds[1], ds[2]])
    assert batch["input_ids"].shape == (3, 64)
    assert batch["attention_mask"].shape == (3, 64)
    assert batch["cwe_label"].shape == (3,)
    assert batch["cvss_score"].shape == (3,)
    assert batch["loss_weight"].shape == (3,)
    assert batch["is_hard_negative"].shape == (3,)
    assert batch["sample_id"] == ["s1", "s2", "s3_hardneg"]
    # Sub-vector labels: each key → tensor of shape [3]
    for key in SUBVECTOR_CODES:
        assert batch["subvector_labels"][key].shape == (3,)


# ---------------------------------------------------------------------------
# per_split_stats
# ---------------------------------------------------------------------------

def test_per_split_stats():
    samples = [
        {"split": "train", "cwe": "CWE-89"},
        {"split": "train", "cwe": "CWE-89"},
        {"split": "train", "cwe": "CWE-502"},
        {"split": "val",   "cwe": "CWE-89"},
        {"split": "test",  "cwe": "CWE-79"},
    ]
    stats = per_split_stats(samples)
    assert stats["train"]["CWE-89"] == 2
    assert stats["train"]["CWE-502"] == 1
    assert stats["val"]["CWE-89"] == 1
    assert stats["test"]["CWE-79"] == 1
