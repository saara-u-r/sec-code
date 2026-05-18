"""
data_prep.py — Phase 2, Stage 1

Loads commit messages + CWE labels from MongoDB Atlas, performs a
stratified 70/15/15 train/val/test split, writes the split assignment
back to each document, and returns the three splits as lists of dicts.

Each returned record has:
  text  — the commit message
  label — integer class index (see LABEL_MAP)
  cwe   — original CWE string
  id    — document _id for MongoDB updates
"""

from __future__ import annotations

import random
from collections import defaultdict
from typing import NamedTuple

from src.utils.logger import get_logger
from src.utils.mongo_writer import get_collection

logger = get_logger(__name__)

TARGET_CWES = {"CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-94", "CWE-918", "CWE-502"}

LABEL_MAP: dict[str, int] = {
    "CWE-89":  0,   # SQL Injection
    "CWE-78":  1,   # OS Command Injection
    "CWE-22":  2,   # Path Traversal
    "CWE-79":  3,   # Cross-site Scripting
    "CWE-94":  4,   # Code Injection
    "CWE-918": 5,   # SSRF
    "CWE-502": 6,   # Insecure Deserialization
    "other":   7,
}

LABEL_NAMES = ["CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-94", "CWE-918", "CWE-502", "other"]


class Split(NamedTuple):
    train: list[dict]
    val:   list[dict]
    test:  list[dict]


def load_and_split(seed: int = 42) -> Split:
    """
    Pull all usable samples from MongoDB, split stratified by CWE,
    write split assignments back to Atlas, and return (train, val, test).
    """
    col = get_collection()
    if col is None:
        raise RuntimeError("MongoDB not connected — check MONGODB_URI in .env")

    cursor = col.find(
        {
            "commit_message": {"$exists": True, "$nin": [None, ""]},
            "cwe":            {"$exists": True, "$ne": None},
        },
        {"_id": 1, "commit_message": 1, "cwe": 1},
    )

    by_cwe: dict[str, list[dict]] = defaultdict(list)
    for doc in cursor:
        msg = (doc.get("commit_message") or "").strip()
        if not msg:
            continue
        cwe = doc["cwe"] if doc["cwe"] in TARGET_CWES else "other"
        by_cwe[cwe].append({
            "id":    doc["_id"],
            "text":  msg,
            "label": LABEL_MAP[cwe],
            "cwe":   cwe,
        })

    total = sum(len(v) for v in by_cwe.values())
    logger.info(f"Loaded {total} usable samples from MongoDB")
    for cwe, samples in sorted(by_cwe.items()):
        logger.info(f"  {cwe}: {len(samples)}")

    rng = random.Random(seed)
    train_all, val_all, test_all = [], [], []

    for cwe, samples in by_cwe.items():
        rng.shuffle(samples)
        n = len(samples)
        n_val  = max(1, round(n * 0.15))
        n_test = max(1, round(n * 0.15))
        n_train = n - n_val - n_test

        if n_train < 1:
            # Too few samples for this class — put everything in train
            logger.warning(f"  {cwe} has only {n} samples — all assigned to train")
            train_all.extend(samples)
            continue

        train_all.extend(samples[:n_train])
        val_all.extend(samples[n_train:n_train + n_val])
        test_all.extend(samples[n_train + n_val:])

    logger.info(
        f"Split: train={len(train_all)}, val={len(val_all)}, test={len(test_all)}"
    )

    _write_splits_to_mongo(col, train_all, val_all, test_all)

    return Split(train=train_all, val=val_all, test=test_all)


def _write_splits_to_mongo(col, train, val, test) -> None:
    """Write split='train'/'val'/'test' back to each Atlas document."""
    from pymongo import UpdateOne

    ops = []
    for split_name, samples in [("train", train), ("val", val), ("test", test)]:
        for s in samples:
            ops.append(UpdateOne({"_id": s["id"]}, {"$set": {"split": split_name}}))

    if ops:
        result = col.bulk_write(ops, ordered=False)
        logger.info(f"Split labels written to MongoDB: {result.modified_count} docs updated")
