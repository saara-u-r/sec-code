"""
demo_classifier.py — Phase 2 live demo

Takes a commit message (typed interactively or passed as --message)
and shows predictions from both the SVM baseline and DistilBERT.

Usage:
  .venv/bin/python3 scripts/demo_classifier.py
  .venv/bin/python3 scripts/demo_classifier.py --message "Fix SQL injection in login"
  .venv/bin/python3 scripts/demo_classifier.py --examples   # run preset examples
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np

from src.labeler.data_prep import LABEL_NAMES

EXAMPLES = [
    ("CWE-89",  "Fix SQL injection vulnerability in user authentication query"),
    ("CWE-78",  "Sanitize shell command input to prevent command injection"),
    ("CWE-22",  "Prevent path traversal attack in file download endpoint"),
    ("CWE-502", "Replace pickle deserialization with safe JSON loader"),
    ("CWE-89",  "Parameterize raw SQL query in search handler to fix injection bug"),
    ("CWE-78",  "Escape user input before passing to subprocess in backup script"),
    ("CWE-22",  "Use secure_filename to block directory traversal in upload route"),
    ("CWE-502", "Remove yaml.load, use yaml.safe_load to prevent deserialization RCE"),
]


def _svm_predict(pipe, message: str) -> tuple[str, float]:
    proba = pipe.predict_proba([message])[0]
    idx   = int(np.argmax(proba))
    return LABEL_NAMES[idx], float(proba[idx])


def _bert_predict(tokenizer, model, device, message: str) -> tuple[str, float]:
    import torch
    enc = tokenizer(
        message,
        truncation=True,
        padding="max_length",
        max_length=128,
        return_tensors="pt",
    )
    with torch.no_grad():
        out   = model(
            input_ids=enc["input_ids"].to(device),
            attention_mask=enc["attention_mask"].to(device),
        )
        probs = torch.softmax(out.logits, dim=-1).cpu().numpy()[0]
    idx = int(np.argmax(probs))
    return LABEL_NAMES[idx], float(probs[idx])


def _print_result(message: str, svm_cwe: str, svm_conf: float,
                  bert_cwe: str, bert_conf: float, true_cwe: str | None = None):
    print()
    print("=" * 60)
    print(f"  Commit: {message}")
    if true_cwe:
        print(f"  True CWE : {true_cwe}")
    print(f"  SVM      : {svm_cwe:<10}  confidence={svm_conf:.2%}")
    print(f"  DistilBERT: {bert_cwe:<10}  confidence={bert_conf:.2%}")

    if true_cwe:
        svm_ok  = "✓" if svm_cwe  == true_cwe else "✗"
        bert_ok = "✓" if bert_cwe == true_cwe else "✗"
        print(f"  SVM correct: {svm_ok}    DistilBERT correct: {bert_ok}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--message",  type=str, help="Single commit message to classify")
    parser.add_argument("--examples", action="store_true", help="Run preset demo examples")
    args = parser.parse_args()

    # Load SVM
    from src.labeler.commit_classifier import load as svm_load
    try:
        pipe = svm_load()
        print("[SVM] Model loaded.")
    except FileNotFoundError:
        print("[SVM] No trained model found. Run run_phase2.py --svm-only first.")
        sys.exit(1)

    # Load DistilBERT
    import torch
    from transformers import DistilBertForSequenceClassification, DistilBertTokenizerFast
    from src.labeler.distilbert_classifier import MODEL_DIR, _get_device

    if not MODEL_DIR.exists():
        print("[DistilBERT] No saved model found. Run run_phase2.py first.")
        sys.exit(1)

    device    = _get_device()
    tokenizer = DistilBertTokenizerFast.from_pretrained(MODEL_DIR)
    model     = DistilBertForSequenceClassification.from_pretrained(MODEL_DIR).to(device)
    model.eval()
    print(f"[DistilBERT] Model loaded (device: {device}).")

    if args.examples:
        print("\n--- Running preset demo examples ---")
        for true_cwe, msg in EXAMPLES:
            s_cwe, s_conf = _svm_predict(pipe, msg)
            b_cwe, b_conf = _bert_predict(tokenizer, model, device, msg)
            _print_result(msg, s_cwe, s_conf, b_cwe, b_conf, true_cwe=true_cwe)
        return

    if args.message:
        s_cwe, s_conf = _svm_predict(pipe, args.message)
        b_cwe, b_conf = _bert_predict(tokenizer, model, device, args.message)
        _print_result(args.message, s_cwe, s_conf, b_cwe, b_conf)
        return

    # Interactive mode
    print("\nInteractive mode — type a commit message and press Enter.")
    print("Type 'quit' to exit.\n")
    while True:
        try:
            msg = input("Commit message > ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if msg.lower() in ("quit", "exit", "q"):
            break
        if not msg:
            continue
        s_cwe, s_conf = _svm_predict(pipe, msg)
        b_cwe, b_conf = _bert_predict(tokenizer, model, device, msg)
        _print_result(msg, s_cwe, s_conf, b_cwe, b_conf)


if __name__ == "__main__":
    main()
