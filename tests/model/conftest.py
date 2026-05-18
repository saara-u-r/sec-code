"""
conftest.py — shared fixtures for src/model tests.

Avoids downloading the 500MB GraphCodeBERT weights on every test run
by providing a stub backbone with the same forward-pass API.
"""

from __future__ import annotations

import torch
import torch.nn as nn
import pytest


class _StubBackbone(nn.Module):
    """Minimal stand-in for GraphCodeBERT — has just enough surface to
    make GraphCodeBERTDualTask's forward pass work."""

    def __init__(self, hidden_dim: int = 768, vocab_size: int = 50000):
        super().__init__()
        self.embeddings = nn.Embedding(vocab_size, hidden_dim)
        self.encoder = nn.Linear(hidden_dim, hidden_dim)

    def forward(self, input_ids=None, attention_mask=None, return_dict=True):
        emb = self.embeddings(input_ids)            # [B, T, H]
        out = self.encoder(emb)                      # [B, T, H]
        # Match HuggingFace's BaseModelOutput shape
        return type("StubOut", (), {
            "last_hidden_state": out,
            "pooler_output": out[:, 0],
        })()


@pytest.fixture
def stub_backbone():
    return _StubBackbone(hidden_dim=64)  # tiny dim for fast tests


@pytest.fixture
def stub_tokenizer():
    """A toy tokenizer that returns deterministic small tensors."""
    class _StubTokenizer:
        def __call__(
            self, code, truncation=True, max_length=512,
            padding="max_length", return_tensors="pt",
        ):
            # Convert code to byte-ids (mod 50000) for variety, then pad
            ids = [b % 50000 for b in code.encode("utf-8", errors="ignore")][:max_length]
            mask = [1] * len(ids)
            if padding == "max_length" and len(ids) < max_length:
                pad_n = max_length - len(ids)
                ids.extend([0] * pad_n)
                mask.extend([0] * pad_n)
            ids = ids[:max_length]
            mask = mask[:max_length]
            return {
                "input_ids":      torch.tensor([ids],  dtype=torch.long),
                "attention_mask": torch.tensor([mask], dtype=torch.long),
            }

    return _StubTokenizer()


@pytest.fixture
def synthetic_samples():
    """A small synthetic dataset matching the on-disk schema."""
    return [
        {
            "id":               "s1",
            "content_hash":     "hash_1",
            "code":             "def get(uid):\n    return cursor.execute(f'SELECT * FROM x WHERE id = {uid}')\n",
            "cwe":              "CWE-89",
            "split":            "train",
            "framework":        "django",
            "source":           "ghsa_db",
            "is_hard_negative": False,
            "label_confidence": "high",
        },
        {
            "id":               "s2",
            "content_hash":     "hash_2",
            "code":             "import yaml\ndef cfg(s):\n    return yaml.load(s)\n",
            "cwe":              "CWE-502",
            "split":            "train",
            "framework":        "flask",
            "source":           "cvefixes",
            "is_hard_negative": False,
            "label_confidence": "high",
        },
        {
            "id":               "s3_hardneg",
            "content_hash":     "hash_3",
            "code":             "def safe_get(uid):\n    return cursor.execute('SELECT ?', (uid,))\n",
            "cwe":              "safe",
            "split":            "train",
            "framework":        "django",
            "source":           "hardneg_ghsa_db",
            "is_hard_negative": True,
            "label_confidence": "high",
        },
    ]


@pytest.fixture
def synthetic_cvss_targets():
    """CVSS targets matching the synthetic sample hashes."""
    return {
        "hash_1": {
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "sub_vectors": {
                "AV": "N", "AC": "L", "PR": "N", "UI": "N",
                "S":  "U", "C":  "H", "I":  "H", "A":  "H",
            },
            "score_source": "advisory",
            "label_confidence": "high",
            "loss_weight": 1.0,
        },
        "hash_2": {
            "cvss_score": 7.5,
            "cvss_vector": None,
            "sub_vectors": None,
            "score_source": "band_midpoint",
            "label_confidence": "medium",
            "loss_weight": 0.3,
        },
        # hash_3 (hardneg) → no entry; should produce IGNORE_INDEX labels
    }
