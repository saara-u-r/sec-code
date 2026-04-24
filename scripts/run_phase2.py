"""
run_phase2.py — Phase 2 orchestrator

Runs the full commit message → CWE classification pipeline:
  Stage 1 — Load data from MongoDB, stratified split, write splits back
  Stage 2 — TF-IDF + SVM baseline: train, evaluate, update Atlas
  Stage 3 — DistilBERT fine-tune: train, evaluate, update Atlas

Usage:
  .venv/bin/python3 scripts/run_phase2.py              # all stages
  .venv/bin/python3 scripts/run_phase2.py --svm-only   # baseline only
  .venv/bin/python3 scripts/run_phase2.py --bert-only  # fine-tune only (needs saved split)
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.labeler.data_prep import load_and_split
from src.labeler.commit_classifier import train as svm_train, evaluate as svm_eval, predict_and_update as svm_update
from src.utils.logger import get_logger

logger = get_logger("run_phase2")


def run_svm(train_s, val_s, test_s):
    logger.info("=== Stage 2: TF-IDF + SVM Baseline ===")
    pipe = svm_train(train_s)
    logger.info("--- Validation set ---")
    svm_eval(pipe, val_s, "val")
    logger.info("--- Test set ---")
    svm_eval(pipe, test_s, "test")
    all_samples = train_s + val_s + test_s
    svm_update(pipe, all_samples)
    return pipe


def run_bert(train_s, val_s, test_s):
    from src.labeler.distilbert_classifier import (
        train as bert_train,
        evaluate as bert_eval,
        predict_and_update as bert_update,
    )
    logger.info("=== Stage 3: DistilBERT Fine-tune ===")
    bert_train(train_s, val_s)
    bert_eval(test_s)
    bert_update(train_s + val_s + test_s)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--svm-only",  action="store_true", help="Run Stage 2 only")
    parser.add_argument("--bert-only", action="store_true", help="Run Stage 3 only")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for split")
    args = parser.parse_args()

    logger.info("=== Phase 2: Commit Message CWE Classifier ===")

    logger.info("=== Stage 1: Data Preparation ===")
    split = load_and_split(seed=args.seed)
    logger.info(
        f"Split sizes — train: {len(split.train)}, "
        f"val: {len(split.val)}, test: {len(split.test)}"
    )

    if not split.train:
        logger.error("No training samples found. Ensure MongoDB has documents with commit_message + cwe fields.")
        sys.exit(1)

    if args.bert_only:
        run_bert(split.train, split.val, split.test)
    elif args.svm_only:
        run_svm(split.train, split.val, split.test)
    else:
        run_svm(split.train, split.val, split.test)
        run_bert(split.train, split.val, split.test)

    logger.info("=== Phase 2 complete ===")


if __name__ == "__main__":
    main()
