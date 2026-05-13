#!/usr/bin/env python3
"""
build_mutator_variants.py — materialize the adversarial test set.

For every test-split positive sample (\texttt{split=test}, \texttt{cwe != safe},
\texttt{source != canonical}), produce five variants:

  clean/                — the unmodified \texttt{code\_before}
  dead_code/            — dead_code_injection mutator applied
  string_split/         — string_split mutator applied
  variable_rename/      — variable_rename mutator applied
  wrapper_extraction/   — wrapper_extraction mutator applied
  composed/             — random 2-3 mutators applied (deterministic seed)

Each variant is saved as ``data/test_variants/{variant}/{sample_id}.py``
alongside the original ``.meta.json`` (copied from data/raw). Variants
that fail to mutate (e.g. no function to wrap, no string to split) fall
back to the clean source; the manifest records which mutators applied
successfully per sample.

The seed is the sample_id hash, so re-running this script produces
byte-identical variants — the evaluation is fully reproducible.

Usage:
  python scripts/build_mutator_variants.py                    # dry-run summary
  python scripts/build_mutator_variants.py --apply            # actually write
  python scripts/build_mutator_variants.py --apply --include-canonical
                                                              # include canonicals too
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.red_team import all_mutators, apply_mutators, get_mutator  # noqa: E402
from src.utils.logger import get_logger  # noqa: E402

logger = get_logger("build_mutator_variants")

MUTATOR_NAMES = [
    "dead_code_injection",
    "string_split",
    "variable_rename",
    "wrapper_extraction",
]


def stable_seed(sample_id: str, salt: str = "") -> int:
    """Stable 32-bit seed derived from sample_id + salt. Same inputs always
    produce the same seed."""
    h = hashlib.sha256((sample_id + "::" + salt).encode()).digest()
    return int.from_bytes(h[:4], "big")


def apply_one(source: str, mutator_name: str, seed: int) -> tuple[str, bool]:
    """Apply a single mutator. Return (output_source, applied_successfully)."""
    mutator = get_mutator(mutator_name)
    rng = random.Random(seed)
    out, results = apply_mutators(
        source, [mutator], rng=rng, min_per_pass=1, max_per_pass=1,
    )
    applied = any(r.success for r in results)
    return out, applied


def apply_composed(source: str, seed: int) -> tuple[str, list[str]]:
    """Apply 2-3 randomly-selected mutators (deterministic). Return
    (output_source, [mutator_name, ...] for those that applied)."""
    rng = random.Random(seed)
    out, results = apply_mutators(
        source, all_mutators(), rng=rng, min_per_pass=2, max_per_pass=3,
    )
    applied = [r.mutator for r in results if r.success]
    return out, applied


def load_test_samples(raw_dir: Path, include_canonical: bool) -> list[dict]:
    out: list[dict] = []
    for meta_path in sorted(raw_dir.glob("*.meta.json")):
        try:
            m = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if m.get("split") != "test":
            continue
        if m.get("cwe") in (None, "safe"):
            continue
        if m.get("is_hard_negative"):
            continue
        if not include_canonical and m.get("source") == "canonical":
            continue
        py_path = meta_path.with_suffix("").with_suffix(".py")
        if not py_path.exists():
            continue
        out.append({
            "id":        m["id"],
            "cwe":       m["cwe"],
            "source":    m.get("source"),
            "meta_path": str(meta_path),
            "py_path":   str(py_path),
            "meta":      m,
        })
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--out-dir", default="data/test_variants")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--include-canonical", action="store_true",
                        help="Also process canonical hand-curated samples (default skip).")
    args = parser.parse_args()

    raw = Path(args.raw_dir)
    out = Path(args.out_dir)

    samples = load_test_samples(raw, args.include_canonical)
    logger.info(f"Loaded {len(samples)} test samples "
                f"(cwe != safe, is_hard_negative != True"
                + (", incl. canonicals" if args.include_canonical else "")
                + ")")

    # Pre-flight count by CWE
    by_cwe = Counter(s["cwe"] for s in samples)
    print("\nTest-split positives by CWE:")
    for cwe in sorted(by_cwe):
        print(f"  {cwe}: {by_cwe[cwe]}")
    print(f"  Total: {sum(by_cwe.values())}")

    if not args.apply:
        print("\nDRY RUN — no files written. Re-run with --apply.")
        n_variants = 1 + len(MUTATOR_NAMES) + 1  # clean + per-mutator + composed
        print(f"Would produce {len(samples)} samples × {n_variants} variants = "
              f"{len(samples) * n_variants} mutator-variant files.")
        return 0

    # Prepare output structure
    variants = ["clean"] + MUTATOR_NAMES + ["composed"]
    for v in variants:
        (out / v).mkdir(parents=True, exist_ok=True)

    manifest_entries = []
    per_variant_success = Counter()

    for i, s in enumerate(samples, 1):
        src = Path(s["py_path"]).read_text(encoding="utf-8")
        sample_id = s["id"]
        seed_base = stable_seed(sample_id)

        # 1. Clean: just copy
        (out / "clean" / f"{sample_id}.py").write_text(src, encoding="utf-8")
        per_variant_success["clean"] += 1
        per_variant_meta = {"clean": True}

        # 2. Each mutator individually
        per_variant_applied = {}
        for mname in MUTATOR_NAMES:
            mseed = stable_seed(sample_id, mname)
            try:
                mutated, applied = apply_one(src, mname, mseed)
            except Exception as e:
                logger.warning(f"  {sample_id} :: {mname} raised: {e}")
                mutated, applied = src, False
            (out / mname / f"{sample_id}.py").write_text(mutated, encoding="utf-8")
            per_variant_applied[mname] = applied
            if applied:
                per_variant_success[mname] += 1
            per_variant_meta[mname] = applied

        # 3. Composed
        cseed = stable_seed(sample_id, "composed")
        try:
            mutated, applied_list = apply_composed(src, cseed)
        except Exception as e:
            logger.warning(f"  {sample_id} :: composed raised: {e}")
            mutated, applied_list = src, []
        (out / "composed" / f"{sample_id}.py").write_text(mutated, encoding="utf-8")
        per_variant_meta["composed_applied"] = applied_list
        if applied_list:
            per_variant_success["composed"] += 1

        # Also copy the meta.json into clean/ for downstream loaders
        shutil.copy(s["meta_path"], out / "clean" / f"{sample_id}.meta.json")

        manifest_entries.append({
            "id": sample_id,
            "cwe": s["cwe"],
            "source": s["source"],
            **per_variant_meta,
        })

        if i % 20 == 0:
            logger.info(f"  processed {i}/{len(samples)}")

    # Write manifest
    manifest = {
        "schema": "mutator_variant_manifest_v1",
        "test_samples": len(samples),
        "by_cwe": dict(by_cwe),
        "per_variant_success_rate": {
            k: f"{per_variant_success[k]}/{len(samples)} = "
               f"{per_variant_success[k] / max(len(samples),1):.1%}"
            for k in ["clean"] + MUTATOR_NAMES + ["composed"]
        },
        "entries": manifest_entries,
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    print(f"\nWrote {len(samples)} samples × {len(variants)} variants "
          f"= {len(samples) * len(variants)} files to {out}/")
    print(f"\nPer-variant successful-mutation rate:")
    for k in ["clean"] + MUTATOR_NAMES + ["composed"]:
        print(f"  {k:<22} {per_variant_success[k]:>4}/{len(samples)} "
              f"= {per_variant_success[k] / max(len(samples),1):.1%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
