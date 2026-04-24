"""
commit_classifier.py — Phase 2, Stage 2

TF-IDF + SVM baseline for commit message → CWE classification.

Usage:
  from src.labeler.commit_classifier import train, evaluate, predict_and_update

Architecture (per literature — Koenders 2024, JCIS 2024):
  TfidfVectorizer(ngram=(1,2), max_features=10000)
  → SVC(kernel='rbf', class_weight='balanced')

class_weight='balanced' is critical: CWE-89 has ~5x more samples than CWE-78.
"""

from __future__ import annotations

import os
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.svm import SVC

from src.labeler.data_prep import LABEL_NAMES
from src.utils.logger import get_logger
from src.utils.mongo_writer import get_collection

logger = get_logger(__name__)

MODEL_PATH = Path("models/tfidf_svm_cwe.pkl")


def _build_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=10_000,
            sublinear_tf=True,     # log(1+tf) — improves results on short texts
            strip_accents="unicode",
            analyzer="word",
            token_pattern=r"[a-zA-Z_\-][a-zA-Z0-9_\-]+",
        )),
        ("svm", SVC(
            kernel="rbf",
            C=10.0,
            gamma="scale",
            class_weight="balanced",
            probability=True,      # needed for confidence scores
        )),
    ])


def train(train_samples: list[dict]) -> Pipeline:
    """Fit and save the TF-IDF + SVM pipeline. Returns the fitted pipeline."""
    texts  = [s["text"]  for s in train_samples]
    labels = [s["label"] for s in train_samples]

    logger.info(f"Training TF-IDF+SVM on {len(texts)} samples…")
    pipe = _build_pipeline()
    pipe.fit(texts, labels)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, MODEL_PATH)
    logger.info(f"Model saved → {MODEL_PATH}")
    return pipe


def evaluate(pipe: Pipeline, samples: list[dict], split_name: str = "test") -> dict:
    """Print and return classification metrics for the given samples."""
    texts  = [s["text"]  for s in samples]
    labels = [s["label"] for s in samples]

    preds = pipe.predict(texts)

    present_labels = sorted(set(labels) | set(preds))
    target_names   = [LABEL_NAMES[i] for i in present_labels]

    report = classification_report(
        labels, preds,
        labels=present_labels,
        target_names=target_names,
        output_dict=True,
        zero_division=0,
    )
    report_str = classification_report(
        labels, preds,
        labels=present_labels,
        target_names=target_names,
        zero_division=0,
    )
    cm = confusion_matrix(labels, preds, labels=present_labels)

    logger.info(f"\n--- TF-IDF+SVM [{split_name}] ---\n{report_str}")
    logger.info(f"Confusion matrix (rows=true, cols=pred):\n{cm}")
    logger.info(f"Macro F1: {report['macro avg']['f1-score']:.4f}")

    return report


def load() -> Pipeline:
    """Load a previously saved pipeline from disk."""
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"No saved model at {MODEL_PATH} — run train() first")
    return joblib.load(MODEL_PATH)


def predict_and_update(pipe: Pipeline, samples: list[dict]) -> None:
    """
    Run predictions on samples and write classifier_cwe + classifier_confidence
    back to MongoDB for every sample.
    """
    col = get_collection()
    if col is None:
        logger.warning("MongoDB not connected — skipping Atlas update")
        return

    from pymongo import UpdateOne

    texts = [s["text"] for s in samples]
    preds  = pipe.predict(texts)
    probas = pipe.predict_proba(texts)

    ops = []
    for sample, pred, proba in zip(samples, preds, probas):
        confidence = float(np.max(proba))
        ops.append(UpdateOne(
            {"_id": sample["id"]},
            {"$set": {
                "classifier_cwe":        LABEL_NAMES[pred],
                "classifier_confidence": round(confidence, 4),
            }},
        ))

    if ops:
        result = col.bulk_write(ops, ordered=False)
        logger.info(
            f"predict_and_update: wrote classifier results for {result.modified_count} docs"
        )
