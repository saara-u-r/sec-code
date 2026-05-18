"""
test_augmenter.py — tests for the OnlineAugmenter and sampling helpers.

Contract:
  1. ``stable_seed`` is deterministic across sessions (uses SHA-256, not Python's
     PYTHONHASHSEED-randomized hash())
  2. Same (sample_id, epoch) → same augment() output
  3. Different epochs → (usually) different augment() output
  4. Hard negatives are NOT mutated when skip_hard_negatives=True
  5. Empty mutator list is a no-op (returns input unchanged)
  6. Hold-out mutators are excluded from train-time augment() but applied
     by augment_test()
  7. ``compute_sample_weights`` honors per-CWE multipliers and falls back
     to "default" for unknown labels
  8. ``expanded_index_list`` repeats each index per its multiplier
  9. ``AugmentationConfig.from_json_file`` round-trips correctly
"""

from __future__ import annotations

import json
import random
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from src.red_team.augmenter import (
    AugmentationConfig,
    OnlineAugmenter,
    compute_sample_weights,
    expanded_index_list,
    stable_seed,
)
from src.red_team.base import validate_round_trip
from src.red_team.mutators.dead_code import DEAD_CODE_INJECTOR
from src.red_team.mutators.string_split import STRING_SPLITTER
from src.red_team.mutators.variable_rename import VARIABLE_RENAMER
from src.red_team.mutators.wrapper_extraction import WRAPPER_EXTRACTOR


# ---------------------------------------------------------------------------
# stable_seed
# ---------------------------------------------------------------------------

def test_stable_seed_same_inputs_same_output():
    a = stable_seed("sample_42", epoch=0)
    b = stable_seed("sample_42", epoch=0)
    assert a == b


def test_stable_seed_different_epochs_differ():
    a = stable_seed("sample_42", epoch=0)
    b = stable_seed("sample_42", epoch=1)
    assert a != b


def test_stable_seed_different_sample_ids_differ():
    a = stable_seed("sample_a", epoch=0)
    b = stable_seed("sample_b", epoch=0)
    assert a != b


def test_stable_seed_returns_32bit_int():
    s = stable_seed("anything", epoch=0)
    assert isinstance(s, int)
    assert 0 <= s < 2 ** 32


def test_stable_seed_cross_session_reproducibility():
    """
    Re-run a fresh Python interpreter with PYTHONHASHSEED disabled and
    confirm the seed for a known input matches the value computed here.
    """
    expected = stable_seed("checkpoint_input", epoch=7)
    # Spawn a subprocess to verify the same value comes out across sessions
    code = textwrap.dedent("""
        import sys
        sys.path.insert(0, '.')
        from src.red_team.augmenter import stable_seed
        print(stable_seed("checkpoint_input", epoch=7))
    """)
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, cwd=Path.cwd(),
    )
    assert proc.returncode == 0, f"Subprocess failed: {proc.stderr}"
    assert int(proc.stdout.strip()) == expected


# ---------------------------------------------------------------------------
# OnlineAugmenter — basic behavior
# ---------------------------------------------------------------------------

def test_augmenter_empty_mutator_list_is_noop():
    aug = OnlineAugmenter(mutators=[], config=AugmentationConfig())
    src = "def f(x): return x + 1"
    out = aug.augment(src, sample_id="s1", epoch=0)
    assert out == src


def test_augmenter_deterministic_per_sample_epoch():
    aug = OnlineAugmenter(
        mutators=[DEAD_CODE_INJECTOR, STRING_SPLITTER, VARIABLE_RENAMER],
        config=AugmentationConfig(),
    )
    src = (
        "def get_user(user_id):\n"
        "    return cursor.execute(f'SELECT * FROM x WHERE id = {user_id}')\n"
    )
    a = aug.augment(src, sample_id="abc", epoch=0)
    b = aug.augment(src, sample_id="abc", epoch=0)
    assert a == b


def test_augmenter_different_epochs_produce_different_output():
    aug = OnlineAugmenter(
        mutators=[DEAD_CODE_INJECTOR, STRING_SPLITTER, VARIABLE_RENAMER],
        config=AugmentationConfig(),
    )
    src = (
        "def get_user(user_id):\n"
        "    return cursor.execute(f'SELECT * FROM x WHERE id = {user_id}')\n"
    )
    outputs = {aug.augment(src, sample_id="abc", epoch=e) for e in range(5)}
    # 5 different epochs should produce at least 3 distinct outputs in
    # practice (some collisions are possible but not 5/5 identical)
    assert len(outputs) >= 3, (
        f"Different epochs producing identical output is suspicious; got {len(outputs)} unique"
    )


def test_augmenter_skips_hard_negatives_by_default():
    aug = OnlineAugmenter(
        mutators=[DEAD_CODE_INJECTOR, STRING_SPLITTER, VARIABLE_RENAMER],
        config=AugmentationConfig(skip_hard_negatives=True),
    )
    src = "def f(x):\n    return x + 1\n"
    out = aug.augment(src, sample_id="hn1", epoch=0, is_hard_negative=True)
    assert out == src


def test_augmenter_does_mutate_hard_negatives_when_disabled():
    aug = OnlineAugmenter(
        mutators=[DEAD_CODE_INJECTOR, VARIABLE_RENAMER],
        config=AugmentationConfig(skip_hard_negatives=False),
    )
    src = (
        "def f(user_id):\n"
        "    return user_id + 1\n"
    )
    # Try several epochs; at least one should produce a change
    changed = False
    for e in range(10):
        out = aug.augment(src, sample_id="hn_test", epoch=e, is_hard_negative=True)
        if out.strip() != src.strip():
            changed = True
            break
    assert changed


def test_augmenter_output_is_valid_python():
    aug = OnlineAugmenter(
        mutators=[DEAD_CODE_INJECTOR, STRING_SPLITTER, VARIABLE_RENAMER, WRAPPER_EXTRACTOR],
        config=AugmentationConfig(),
    )
    src = (
        "def fetch(user_id, limit):\n"
        "    sql = f'SELECT * FROM users WHERE id = {user_id} LIMIT {limit}'\n"
        "    return cursor.execute(sql)\n"
    )
    for e in range(5):
        out = aug.augment(src, sample_id="abc", epoch=e)
        assert validate_round_trip(out), f"epoch {e} produced invalid Python:\n{out}"


# ---------------------------------------------------------------------------
# Hold-out mutators
# ---------------------------------------------------------------------------

def test_holdout_mutators_excluded_from_train_augment():
    """When `holdout_mutators` includes string_split, train augment() must
    not produce string-split BinOp chains (the unique surface marker)."""
    aug = OnlineAugmenter(
        mutators=[STRING_SPLITTER, DEAD_CODE_INJECTOR],
        holdout_mutators=[STRING_SPLITTER],
        config=AugmentationConfig(min_per_pass=1, max_per_pass=2),
    )
    src = "def f():\n    return 'SELECT * FROM users WHERE id = 1'\n"
    # Train should not split the string. Run multiple epochs to confirm.
    for e in range(20):
        out = aug.augment(src, sample_id="x", epoch=e)
        # The literal string "SELECT * FROM users WHERE id = 1" should be
        # present unchanged (no split via BinOp + Constant chain).
        assert "SELECT * FROM users WHERE id = 1" in out, (
            f"String-split appears to have been applied during training "
            f"(epoch {e}):\n{out}"
        )


def test_holdout_mutators_applied_at_test_time():
    """augment_test() should use ONLY the held-out mutators."""
    aug = OnlineAugmenter(
        mutators=[DEAD_CODE_INJECTOR],
        holdout_mutators=[STRING_SPLITTER],
        config=AugmentationConfig(),
    )
    # The held-out mutator should produce a BinOp-style split
    src = "def f():\n    return 'SELECT * FROM users WHERE id = 1'\n"
    out = aug.augment_test(src, sample_id="x")
    # After string_split, the literal is broken into "+"-concatenated
    # pieces. The original literal substring should be gone.
    assert "SELECT * FROM users WHERE id = 1" not in out, (
        f"Hold-out string_split didn't fire:\n{out}"
    )


def test_augment_test_noop_when_no_holdout():
    """If no hold-out mutators configured, augment_test() returns input."""
    aug = OnlineAugmenter(
        mutators=[DEAD_CODE_INJECTOR],
        holdout_mutators=[],
        config=AugmentationConfig(),
    )
    src = "def f(): return 1"
    assert aug.augment_test(src, sample_id="x") == src


# ---------------------------------------------------------------------------
# AugmentationConfig
# ---------------------------------------------------------------------------

def test_default_config_has_rare_class_multipliers():
    cfg = AugmentationConfig()
    assert cfg.multipliers["CWE-502"] >= 4.0
    assert cfg.multipliers["CWE-918"] >= 2.0
    assert cfg.multipliers["default"] == 1.0


def test_config_round_trip_via_json(tmp_path):
    cfg = AugmentationConfig(
        min_per_pass=2, max_per_pass=2, format_output=False,
        multipliers={"CWE-502": 10.0, "default": 1.0},
        skip_hard_negatives=False,
    )
    path = tmp_path / "config.json"
    path.write_text(json.dumps(cfg.to_dict()))

    loaded = AugmentationConfig.from_json_file(path)
    assert loaded.min_per_pass == 2
    assert loaded.max_per_pass == 2
    assert loaded.format_output is False
    assert loaded.multipliers["CWE-502"] == 10.0
    assert loaded.skip_hard_negatives is False


def test_default_augmentation_config_json_loads():
    """The shipped configs/augmentation_config.json must load cleanly."""
    cfg_path = Path("configs/augmentation_config.json")
    if not cfg_path.exists():
        pytest.skip("Default config file not present")
    cfg = AugmentationConfig.from_json_file(cfg_path)
    assert "CWE-502" in cfg.multipliers
    assert cfg.min_per_pass >= 1
    assert cfg.max_per_pass <= len([
        DEAD_CODE_INJECTOR, STRING_SPLITTER, VARIABLE_RENAMER, WRAPPER_EXTRACTOR,
    ])


# ---------------------------------------------------------------------------
# compute_sample_weights
# ---------------------------------------------------------------------------

def test_compute_sample_weights_basic():
    cwes = ["CWE-89", "CWE-502", "CWE-89", "safe", "CWE-918"]
    multipliers = {"CWE-502": 8.0, "CWE-918": 4.0, "default": 1.0}
    weights = compute_sample_weights(cwes, multipliers)
    assert weights == [1.0, 8.0, 1.0, 1.0, 4.0]


def test_compute_sample_weights_unknown_label_uses_default():
    cwes = ["CWE-XXX"]
    multipliers = {"default": 2.5}
    assert compute_sample_weights(cwes, multipliers) == [2.5]


def test_compute_sample_weights_accepts_config():
    cwes = ["CWE-502"] * 3
    cfg = AugmentationConfig()
    weights = compute_sample_weights(cwes, cfg)
    assert all(w == cfg.multipliers["CWE-502"] for w in weights)


def test_compute_sample_weights_default_when_none():
    cwes = ["CWE-89", "CWE-502"]
    weights = compute_sample_weights(cwes, multipliers=None)
    # Defaults to AugmentationConfig() multipliers
    cfg = AugmentationConfig()
    assert weights == [cfg.multipliers["CWE-89"], cfg.multipliers["CWE-502"]]


# ---------------------------------------------------------------------------
# expanded_index_list
# ---------------------------------------------------------------------------

def test_expanded_index_list_repeats_per_multiplier():
    cwes = ["CWE-89", "CWE-502"]
    multipliers = {"CWE-89": 1.0, "CWE-502": 5.0, "default": 1.0}
    indices = expanded_index_list(cwes, multipliers, seed=0)
    # Index 0 (CWE-89) appears 1×, index 1 (CWE-502) appears 5×
    assert indices.count(0) == 1
    assert indices.count(1) == 5
    assert len(indices) == 6


def test_expanded_index_list_shuffled_deterministically():
    cwes = ["CWE-89"] * 5 + ["CWE-502"] * 5
    multipliers = {"CWE-89": 1.0, "CWE-502": 2.0, "default": 1.0}
    a = expanded_index_list(cwes, multipliers, seed=42)
    b = expanded_index_list(cwes, multipliers, seed=42)
    assert a == b


def test_expanded_index_list_different_seeds_differ():
    cwes = ["CWE-89"] * 5 + ["CWE-502"] * 5
    multipliers = {"CWE-89": 1.0, "CWE-502": 2.0, "default": 1.0}
    a = expanded_index_list(cwes, multipliers, seed=1)
    b = expanded_index_list(cwes, multipliers, seed=999)
    assert a != b


def test_expanded_index_list_minimum_one_repeat():
    """A multiplier of 0.5 should still produce at least 1 repeat per sample
    (we don't drop samples — only oversample)."""
    cwes = ["CWE-89", "CWE-502"]
    multipliers = {"CWE-89": 0.5, "CWE-502": 0.0, "default": 1.0}
    indices = expanded_index_list(cwes, multipliers, seed=0)
    assert indices.count(0) >= 1
    assert indices.count(1) >= 1


# ---------------------------------------------------------------------------
# Integration: augment + sampling weights
# ---------------------------------------------------------------------------

def test_realistic_workflow():
    """
    Simulate one epoch of a Phase 3 dataloader:
      - Compute weights from a list of CWEs
      - Augment each sample once
      - Verify everything parses and is reproducible
    """
    cwes = ["CWE-89", "CWE-502", "CWE-79", "safe"]
    samples = [
        ("s1", "def f(uid): return cursor.execute(f'SELECT * FROM x WHERE id = {uid}')\n"),
        ("s2", "import yaml\ndef g(s): return yaml.load(s)\n"),
        ("s3", "from flask import Markup\ndef h(t): return Markup(t)\n"),
        ("s4", "def safe(x): return x.strip()\n"),  # a "safe" sample (hardneg or non-vuln)
    ]
    weights = compute_sample_weights(cwes)
    assert weights[1] > weights[0]  # CWE-502 weighted heavier than CWE-89

    aug = OnlineAugmenter(
        mutators=[DEAD_CODE_INJECTOR, VARIABLE_RENAMER],
        config=AugmentationConfig(),
    )
    epoch = 3
    is_hardneg = [False, False, False, True]  # last sample is a hard negative

    for (sid, src), hn in zip(samples, is_hardneg):
        out = aug.augment(src, sample_id=sid, epoch=epoch, is_hard_negative=hn)
        assert validate_round_trip(out)
        if hn:
            # Hard negative must be unchanged
            assert out == src
