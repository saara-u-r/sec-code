#!/usr/bin/env python3
"""
run_phase2b_configs.py — Phase 2b: Class weights + CVSS targets.

Computes the two configuration artifacts that Phase 3 model training
consumes:

  1. ``configs/class_weights.json`` — uniform / effective_number / LDAM
     weights and the DRW schedule. Computed from train-split counts only.
  2. ``configs/cvss_targets.json`` — per-sample CVSS regression and
     sub-vector classification targets, plus confidence-weighted loss
     weights.

Reads from MongoDB (preferred) or the disk meta files in ``data/raw/``
as a fallback.

Usage:
    python scripts/run_phase2b_configs.py
    python scripts/run_phase2b_configs.py --beta 0.9999       # less aggressive eff-num
    python scripts/run_phase2b_configs.py --total-epochs 20    # longer DRW schedule
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.labeler.class_weights import build_weight_schedules  # noqa: E402
from src.labeler.cvss_targets import build_targets  # noqa: E402
from src.model.dataset import INDEX_TO_CWE  # noqa: E402
from src.utils.logger import get_logger  # noqa: E402

# Use the authoritative model label vocab (CWE_TO_INDEX ordering) rather
# than legacy data_prep.LABEL_NAMES — keeps the class_weights.json
# label_order aligned with the model's classifier-head ordering.
LABEL_NAMES = list(INDEX_TO_CWE)

logger = get_logger("phase2b")


# ---------------------------------------------------------------------------
# Sample loading (MongoDB primary, disk fallback)
# ---------------------------------------------------------------------------

def _load_from_mongo() -> list[dict] | None:
    try:
        from src.utils.mongo_writer import get_collection
        col = get_collection()
        if col is None:
            return None
        projection = {
            "id": 1, "content_hash": 1, "cwe": 1, "split": 1,
            "cvss_score": 1, "cvss_severity": 1, "cvss_vector": 1,
            "label_confidence": 1, "_id": 0,
        }
        return list(col.find({"id": {"$exists": True}}, projection))
    except Exception as e:
        logger.warning(f"MongoDB read failed: {e}")
        return None


def _load_from_disk(raw_dir: str) -> list[dict]:
    raw = Path(raw_dir)
    if not raw.exists():
        return []
    out: list[dict] = []
    for p in sorted(raw.glob("*.meta.json")):
        try:
            m = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not m.get("id"):
            continue
        out.append({
            "id":              m["id"],
            "content_hash":    m.get("content_hash"),
            "cwe":             m.get("cwe"),
            "split":           m.get("split"),
            "cvss_score":      m.get("cvss_score"),
            "cvss_severity":   m.get("cvss_severity"),
            "cvss_vector":     m.get("cvss_vector"),
            "label_confidence": m.get("label_confidence"),
        })
    return out


def load_samples(raw_dir: str) -> tuple[list[dict], str]:
    samples = _load_from_mongo()
    if samples:
        return samples, "mongo"
    logger.warning("MongoDB unavailable — falling back to disk")
    return _load_from_disk(raw_dir), "disk"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Phase 2b — class weights + CVSS targets")
    p.add_argument("--raw-dir", default="data/raw")
    p.add_argument("--class-weights-out", default="configs/class_weights.json")
    p.add_argument("--cvss-targets-out", default="configs/cvss_targets.json")
    p.add_argument("--beta", type=float, default=0.999, help="Effective-number β")
    p.add_argument(
        "--ldam-max-margin", type=float, default=0.5, help="Largest LDAM margin",
    )
    p.add_argument(
        "--total-epochs", type=int, default=10, help="Total training epochs for DRW",
    )
    p.add_argument(
        "--phase-a-fraction", type=float, default=0.8,
        help="Fraction of training spent in DRW Phase A (uniform weighting)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logger.info("=== Phase 2b — Class Weights + CVSS Targets ===")
    logger.info("")

    samples, source_label = load_samples(args.raw_dir)
    if not samples:
        logger.error(
            "No samples found. Run scripts/run_generator.py and "
            "scripts/run_phase2.py first."
        )
        sys.exit(1)
    logger.info(f"Loaded {len(samples)} samples from {source_label}")

    # ---- Class weights from TRAIN split only ---------------------------------
    train_samples = [s for s in samples if s.get("split") == "train"]
    if not train_samples:
        logger.error(
            "No samples with split='train' found. Run scripts/run_phase2.py first."
        )
        sys.exit(1)

    cwe_counts: dict[str, int] = Counter()
    for s in train_samples:
        cwe = s.get("cwe")
        if cwe:
            cwe_counts[cwe] += 1

    logger.info("Train-split CWE counts (used for class weights):")
    for c, n in sorted(cwe_counts.items()):
        logger.info(f"  {c:8s}: {n}")

    # Use the canonical label order from data_prep
    # (LABEL_NAMES = the 7 target CWEs + "other"; we add "safe" for hardnegs)
    label_order = list(LABEL_NAMES)
    if "safe" not in label_order and any(s.get("cwe") == "safe" for s in train_samples):
        label_order.append("safe")

    weights = build_weight_schedules(
        cwe_counts,
        label_order=label_order,
        beta=args.beta,
        ldam_max_margin=args.ldam_max_margin,
        drw_total_epochs=args.total_epochs,
        drw_phase_a_fraction=args.phase_a_fraction,
    )

    logger.info("")
    logger.info("Computed weight schedules:")
    logger.info("  effective_number weights (β=%.4f):" % args.beta)
    for c in label_order:
        if c in weights["effective_number"]:
            logger.info(
                f"    {c:8s}: count={weights['raw_counts'][c]:>4}  "
                f"weight={weights['effective_number'][c]:.4f}"
            )
    logger.info("  ldam_margins (max=%.2f):" % args.ldam_max_margin)
    for c in label_order:
        if c in weights["ldam_margins"]:
            logger.info(
                f"    {c:8s}: margin={weights['ldam_margins'][c]:.4f}"
            )
    logger.info(
        f"  drw_schedule: phase_a={weights['drw_schedule']['phase_a_epochs']} "
        f"epochs, phase_b={weights['drw_schedule']['phase_b_epochs']} "
        f"({weights['drw_schedule']['phase_b_weights']} weights)"
    )

    # ---- CVSS targets for ALL samples (train, val, test) ---------------------
    cvss = build_targets(samples)
    logger.info("")
    logger.info(f"CVSS targets built for {cvss['_summary']['total']} samples:")
    logger.info(
        f"  Score coverage:      {cvss['_summary']['score_coverage']} "
        f"({cvss['_summary']['score_coverage'] / cvss['_summary']['total']:.0%})"
    )
    logger.info(
        f"  Sub-vector coverage: {cvss['_summary']['subvector_coverage']} "
        f"({cvss['_summary']['subvector_coverage'] / cvss['_summary']['total']:.0%})"
    )
    logger.info("  Score sources:")
    for k, v in sorted(cvss['_summary']['score_sources'].items(), key=lambda x: -x[1]):
        logger.info(f"    {k}: {v}")
    logger.info("  Label confidence:")
    for k, v in sorted(cvss['_summary']['label_confidence'].items(), key=lambda x: -x[1]):
        logger.info(f"    {k}: {v}")

    # ---- Write both config files --------------------------------------------
    Path(args.class_weights_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.class_weights_out).write_text(json.dumps(weights, indent=2), encoding="utf-8")
    logger.info(f"\nWrote {args.class_weights_out}")

    Path(args.cvss_targets_out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.cvss_targets_out).write_text(json.dumps(cvss, indent=2), encoding="utf-8")
    size_kb = Path(args.cvss_targets_out).stat().st_size / 1024
    logger.info(f"Wrote {args.cvss_targets_out} ({size_kb:.1f} KB)")

    logger.info("\n=== Phase 2b complete ===")


if __name__ == "__main__":
    main()
