"""Tests for src.eval.samples — test-variant loading."""

import json
from pathlib import Path

import pytest

from src.eval.samples import (
    SINGLE_MUTATORS,
    VARIANTS,
    load_labels,
    load_variant,
)


def _make_dataset(tmp_path: Path) -> tuple[Path, Path]:
    """Build a minimal test_variants/ + raw/ layout.

    2 positives (CWE-89, CWE-79) across all variants, 1 safe sample in raw.
    """
    variants_dir = tmp_path / "test_variants"
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()

    positives = {
        "pos_sqli_01": "CWE-89",
        "pos_xss_02": "CWE-79",
    }
    for variant in VARIANTS:
        vdir = variants_dir / variant
        vdir.mkdir(parents=True)
        for sid in positives:
            (vdir / f"{sid}.py").write_text(f"# {variant}\nx = 1\n")
    # Labels live only in clean/.
    for sid, cwe in positives.items():
        (variants_dir / "clean" / f"{sid}.meta.json").write_text(
            json.dumps({"id": sid, "cwe": cwe}))

    # One safe test sample in raw/.
    (raw_dir / "safe_01.meta.json").write_text(json.dumps({
        "id": "safe_01", "cwe": "safe", "split": "test",
        "is_hard_negative": True,
    }))
    (raw_dir / "safe_01.py").write_text("y = 2\n")
    # A non-test safe sample that must be ignored.
    (raw_dir / "safe_train.meta.json").write_text(json.dumps({
        "id": "safe_train", "cwe": "safe", "split": "train",
    }))
    (raw_dir / "safe_train.py").write_text("z = 3\n")

    return variants_dir, raw_dir


def test_load_labels(tmp_path):
    variants_dir, _ = _make_dataset(tmp_path)
    labels = load_labels(variants_dir)
    assert labels == {"pos_sqli_01": "CWE-89", "pos_xss_02": "CWE-79"}


def test_load_clean_includes_safe(tmp_path):
    variants_dir, raw_dir = _make_dataset(tmp_path)
    samples = load_variant("clean", variants_dir, raw_dir)
    assert len(samples) == 3  # 2 positives + 1 safe
    by_id = {s.id: s for s in samples}
    assert by_id["pos_sqli_01"].cwe == "CWE-89"
    assert by_id["safe_01"].cwe == "safe"
    assert all(s.variant == "clean" for s in samples)
    # The train-split safe sample is excluded.
    assert "safe_train" not in by_id


def test_load_clean_can_exclude_safe(tmp_path):
    variants_dir, raw_dir = _make_dataset(tmp_path)
    samples = load_variant("clean", variants_dir, raw_dir, include_safe=False)
    assert len(samples) == 2
    assert all(s.cwe != "safe" for s in samples)


@pytest.mark.parametrize("mutator", SINGLE_MUTATORS + ("composed",))
def test_load_mutator_variant_is_positives_only(tmp_path, mutator):
    variants_dir, raw_dir = _make_dataset(tmp_path)
    samples = load_variant(mutator, variants_dir, raw_dir)
    assert len(samples) == 2  # no safe samples in mutator variants
    assert {s.cwe for s in samples} == {"CWE-89", "CWE-79"}
    assert all(s.variant == mutator for s in samples)
    # Code is the variant-specific file, not the clean source.
    assert all(mutator in s.code for s in samples)


def test_load_variant_rejects_unknown_name(tmp_path):
    variants_dir, raw_dir = _make_dataset(tmp_path)
    with pytest.raises(ValueError, match="unknown variant"):
        load_variant("bogus", variants_dir, raw_dir)


def test_load_variant_raises_on_missing_file(tmp_path):
    variants_dir, raw_dir = _make_dataset(tmp_path)
    (variants_dir / "string_split" / "pos_sqli_01.py").unlink()
    with pytest.raises(FileNotFoundError):
        load_variant("string_split", variants_dir, raw_dir)


# --------------------------------------------------------------------------
# Smoke test against the real dataset (skipped if it is not present).
# --------------------------------------------------------------------------

def test_real_dataset_smoke():
    if not Path("data/test_variants/clean").is_dir():
        pytest.skip("data/test_variants not present")
    clean = load_variant("clean")
    positives = [s for s in clean if s.cwe != "safe"]
    assert len(positives) == 67
    for mutator in SINGLE_MUTATORS:
        assert len(load_variant(mutator)) == 67
