#!/usr/bin/env python3
"""
build_split.py — Phase 2B Day 3

Applies the per-CVE cap and produces a stratified train/val/test split.
Writes the split assignment back into each `*.meta.json` so that the
training pipeline (`src.model.dataset.load_samples_from_disk`) reads the
right split from disk without needing MongoDB.

Pipeline:
  1. Load all clean samples (`apply_sink_filter=True` — uses the Phase 2B
     gate so any sink-less leftovers are excluded).
  2. Per-CVE cap: for each (cwe, cve_id) group, retain at most N samples
     (deterministic — seed 42, sort by sample id first). Samples without
     a cve_id (vudenc, hardcoded_creds, hard negatives) are not capped.
  3. Stratified 70/15/15 split per CWE class. Classes with fewer than the
     RARE_THRESHOLD post-cap samples follow a special rule: at least 1
     sample goes to val and at least 1 to test, with the remainder
     assigned to train. This guarantees every CWE has SOMETHING in val.
  4. Write the split string ("train" / "val" / "test") into each
     sample's `*.meta.json`.
  5. Emit `filtered_manifest.json` with per-CWE pre/post counts,
     per-CVE counts that hit the cap, and the seed for reproducibility.

Usage:
  python scripts/build_split.py                    # dry run, prints stats
  python scripts/build_split.py --apply            # write `split` to meta.json
  python scripts/build_split.py --cap 3 --seed 7   # tune knobs
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.model.dataset import load_samples_from_disk
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Per-CWE counts below this threshold get the "rare class" allocation
# (guarantee >=1 val + >=1 test) instead of standard 70/15/15.
RARE_THRESHOLD = 10


def _load_meta(meta_path: Path) -> dict | None:
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _enrich_samples_with_cve(samples: list[dict], raw_dir: Path) -> list[dict]:
    """Add cve_id and meta_path to each sample dict (load_samples_from_disk
    doesn't include them by default)."""
    out = []
    for s in samples:
        meta_path = raw_dir / f"{s['id']}.meta.json"
        m = _load_meta(meta_path) or {}
        s["cve_id"]    = m.get("cve_id")
        s["meta_path"] = str(meta_path)
        out.append(s)
    return out


def _apply_cve_cap(samples: list[dict], cap: int, seed: int) -> tuple[list[dict], dict]:
    """
    Apply per-CVE cap. Samples without a cve_id pass through. Returns
    (kept_samples, cap_report) where cap_report maps cve_id → (cwe, kept, dropped).
    """
    rng = random.Random(seed)
    # Group: (cwe, cve_id) → list of samples
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    untouched: list[dict] = []

    for s in samples:
        cve = s.get("cve_id")
        if not cve:
            untouched.append(s)
            continue
        groups[(s["cwe"], cve)].append(s)

    kept: list[dict] = list(untouched)
    # Keyed by "<cve>::<cwe>" so the same CVE labelled under multiple CWEs
    # doesn't get its entries overwritten (was producing an under-count).
    cap_report: dict[str, dict] = {}
    for (cwe, cve), group in groups.items():
        if len(group) <= cap:
            kept.extend(group)
            continue
        # Deterministic sample by sorted id
        group_sorted = sorted(group, key=lambda s: s["id"])
        chosen = group_sorted[:cap]
        kept.extend(chosen)
        cap_report[f"{cve}::{cwe}"] = {
            "cve_id":  cve,
            "cwe":     cwe,
            "kept":    cap,
            "dropped": len(group) - cap,
            "dropped_ids": [s["id"] for s in group_sorted[cap:]],
        }
        rng.random()  # advance RNG so different runs have different state
    return kept, cap_report


def _stratified_split(
    samples: list[dict],
    seed: int,
    train_pct: float = 0.70,
    val_pct: float = 0.15,
) -> dict[str, str]:
    """
    Stratified split by CWE. Returns {sample_id: split} where split is
    "train" / "val" / "test". Rare classes (<RARE_THRESHOLD) get a guarantee
    of at least 1 in val and 1 in test, remainder goes to train.
    """
    rng = random.Random(seed)
    by_cwe: dict[str, list[dict]] = defaultdict(list)
    for s in samples:
        by_cwe[s["cwe"]].append(s)

    assignment: dict[str, str] = {}
    for cwe, group in by_cwe.items():
        rng.shuffle(group)
        n = len(group)

        if n < RARE_THRESHOLD:
            # Rare class: 1 to test, 1 to val (if possible), rest to train.
            for i, s in enumerate(group):
                if   i == 0 and n >= 3: split = "test"
                elif i == 1 and n >= 2: split = "val"
                else:                   split = "train"
                assignment[s["id"]] = split
        else:
            n_train = round(n * train_pct)
            n_val   = round(n * val_pct)
            # Force at least 1 in each
            n_train = max(n_train, 1)
            n_val   = max(n_val,   1)
            n_test  = max(n - n_train - n_val, 1)
            # Re-balance if rounding bumped us over n
            while n_train + n_val + n_test > n:
                n_train -= 1
            for i, s in enumerate(group):
                if   i < n_train:           split = "train"
                elif i < n_train + n_val:   split = "val"
                else:                        split = "test"
                assignment[s["id"]] = split
    return assignment


def main() -> int:
    parser = argparse.ArgumentParser(description="Per-CVE cap + stratified split")
    parser.add_argument("--raw-dir",     default="data/raw")
    parser.add_argument("--cap",  type=int, default=2, help="Max samples per CVE (default: 2)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--apply", action="store_true", help="Write split assignment to meta.json")
    parser.add_argument("--manifest", default=None,
                        help="Output manifest path (default: data/phase2b_filtered_manifest_<ts>.json)")
    args = parser.parse_args()

    raw_dir = Path(args.raw_dir)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    manifest_path = Path(args.manifest) if args.manifest else \
        Path(f"data/phase2b_filtered_manifest_{timestamp}.json")

    # ── 1. Load clean samples ─────────────────────────────────────────
    samples = load_samples_from_disk(str(raw_dir), apply_sink_filter=True)
    logger.info(f"Loaded {len(samples)} clean samples from {raw_dir}")
    samples = _enrich_samples_with_cve(samples, raw_dir)

    pre_cap_counts: dict[str, int] = defaultdict(int)
    for s in samples:
        pre_cap_counts[s["cwe"]] += 1

    # ── 2. Per-CVE cap ────────────────────────────────────────────────
    kept, cap_report = _apply_cve_cap(samples, cap=args.cap, seed=args.seed)
    post_cap_counts: dict[str, int] = defaultdict(int)
    for s in kept:
        post_cap_counts[s["cwe"]] += 1

    n_capped_cves = len(cap_report)
    n_dropped_by_cap = sum(r["dropped"] for r in cap_report.values())

    # ── 3. Stratified split ───────────────────────────────────────────
    assignment = _stratified_split(kept, seed=args.seed)
    split_counts: dict[tuple[str, str], int] = defaultdict(int)
    for s in kept:
        split = assignment[s["id"]]
        split_counts[(s["cwe"], split)] += 1

    # ── 4. Report ─────────────────────────────────────────────────────
    print()
    print(f"=== build_split — {'APPLY' if args.apply else 'DRY RUN'} ===")
    print(f"raw-dir: {raw_dir}")
    print(f"cap per CVE: {args.cap}    seed: {args.seed}")
    print(f"pre-cap samples:  {sum(pre_cap_counts.values())}")
    print(f"post-cap samples: {sum(post_cap_counts.values())}")
    print(f"CVEs that hit cap: {n_capped_cves}   samples dropped by cap: {n_dropped_by_cap}")
    print()
    print(f"{'CWE':<10} {'pre-cap':>9} {'post-cap':>10} {'train':>7} {'val':>5} {'test':>6}")
    print("-" * 55)
    for cwe in sorted(set(pre_cap_counts) | set(post_cap_counts)):
        pre  = pre_cap_counts.get(cwe, 0)
        post = post_cap_counts.get(cwe, 0)
        tr = split_counts.get((cwe, "train"), 0)
        va = split_counts.get((cwe, "val"),   0)
        te = split_counts.get((cwe, "test"),  0)
        print(f"{cwe:<10} {pre:>9} {post:>10} {tr:>7} {va:>5} {te:>6}")

    # ── 5. Write manifest ─────────────────────────────────────────────
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps({
        "schema": "phase2b_split_manifest_v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "raw_dir": str(raw_dir),
        "params":  {"cap": args.cap, "seed": args.seed, "rare_threshold": RARE_THRESHOLD},
        "counts": {
            "pre_cap":       dict(pre_cap_counts),
            "post_cap":      dict(post_cap_counts),
            "per_split_cwe": {f"{c}/{s}": n for (c, s), n in split_counts.items()},
            "capped_cves":   n_capped_cves,
            "dropped_by_cap": n_dropped_by_cap,
        },
        "capped_cve_detail": cap_report,
    }, indent=2))
    print()
    print(f"Manifest: {manifest_path}")

    # ── 6. Apply: write split to meta.json ────────────────────────────
    if not args.apply:
        print()
        print("DRY RUN — meta.json files not modified. Use --apply to write splits.")
        return 0

    updated = 0
    cleared = 0
    for meta_path in raw_dir.glob("*.meta.json"):
        m = _load_meta(meta_path)
        if m is None:
            continue
        sid = m.get("id")
        if not sid:
            continue
        if sid in assignment:
            if m.get("split") != assignment[sid]:
                m["split"] = assignment[sid]
                meta_path.write_text(json.dumps(m, indent=2), encoding="utf-8")
                updated += 1
        else:
            # Sample didn't survive the cap → clear any pre-existing split label
            if m.get("split") is not None:
                m["split"] = None
                meta_path.write_text(json.dumps(m, indent=2), encoding="utf-8")
                cleared += 1

    print()
    print(f"Applied. Wrote split to {updated} meta.json files; cleared {cleared} dropped samples.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
