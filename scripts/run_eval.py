#!/usr/bin/env python3
"""run_eval.py — evaluate SAST detectors against the adversarial test set.

For each detector and each of the 6 test-set variants (clean + 4 single
mutators + composed), this runs the tool, scores its predictions with
the one-vs-rest macro-F1 metric, and reports the headline table plus
the robustness drop.

Outputs (under --out-dir, default reports/eval/):
  {tool}_predictions.jsonl   one PredictionRecord per (variant, sample)
  {tool}_summary.json        macro-F1 per variant, per-CWE F1, robustness

Usage:
  python scripts/run_eval.py                      # all available tools
  python scripts/run_eval.py --tool bandit        # one tool
  python scripts/run_eval.py --variants clean dead_code_injection
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.eval.cwe_map import TARGET_CWES  # noqa: E402
from src.eval.detectors import DETECTORS  # noqa: E402
from src.eval.samples import SINGLE_MUTATORS, VARIANTS, load_variant  # noqa: E402
from src.eval.scoring import (  # noqa: E402
    PredictionRecord,
    robustness_drop,
    score_variant,
)
from src.utils.logger import get_logger  # noqa: E402

logger = get_logger("run_eval")

#: Short column labels for the headline table.
_VARIANT_ABBR = {
    "clean": "Clean",
    "dead_code_injection": "DC",
    "string_split": "SS",
    "variable_rename": "VR",
    "wrapper_extraction": "WE",
    "composed": "Comp",
}


def run_tool(
    detector,
    variants: list[str],
    variants_dir: str,
    raw_dir: str,
) -> list[PredictionRecord]:
    """Run one detector over every requested variant; return all records."""
    records: list[PredictionRecord] = []
    version = detector.version
    for variant in variants:
        samples = load_variant(variant, variants_dir, raw_dir)
        logger.info(f"  {detector.name} :: {variant} — {len(samples)} samples")
        predictions = detector.run(samples)
        for s in samples:
            pred = predictions.get(s.id)
            records.append(PredictionRecord(
                tool=detector.name,
                variant=variant,
                sample_id=s.id,
                ground_truth=s.cwe,
                predicted=sorted(pred.predicted) if pred else [],
                raw_output=pred.raw if pred else None,
                latency_ms=pred.latency_ms if pred else 0,
                tool_version=version,
            ))
    return records


def build_summary(tool: str, records: list[PredictionRecord]) -> dict:
    """Compute macro-F1 per variant, per-CWE F1 (clean), robustness drop."""
    by_variant: dict[str, list[PredictionRecord]] = {}
    for r in records:
        by_variant.setdefault(r.variant, []).append(r)

    variant_scores = {v: score_variant(rs) for v, rs in by_variant.items()}

    drops = {}
    if "clean" in by_variant:
        for m in SINGLE_MUTATORS:
            if m in by_variant:
                drops[m] = robustness_drop(by_variant["clean"], by_variant[m])
    mean_drop = sum(drops.values()) / len(drops) if drops else None

    return {
        "tool": tool,
        "tool_version": records[0].tool_version if records else "",
        "macro_f1": {v: s.macro_f1 for v, s in variant_scores.items()},
        "n_samples": {v: s.n_samples for v, s in variant_scores.items()},
        "per_cwe_f1": {
            v: {cwe: s.per_cwe[cwe].f1 for cwe in TARGET_CWES}
            for v, s in variant_scores.items()
        },
        "robustness_drop": drops,
        "mean_single_mutator_drop": mean_drop,
        "_variant_scores": variant_scores,  # stripped before JSON dump
    }


def print_report(summary: dict) -> None:
    """Pretty-print the headline table and per-CWE breakdown."""
    tool = summary["tool"]
    scores = summary["_variant_scores"]
    print(f"\n{'=' * 64}")
    print(f"  {tool}  (v{summary['tool_version']})")
    print(f"{'=' * 64}")

    ordered = [v for v in VARIANTS if v in scores]
    cols = "  ".join(f"{_VARIANT_ABBR[v]:>6}" for v in ordered)
    print(f"\nHeadline — macro-F1 across {len(TARGET_CWES)} CWE classes:")
    print(f"  {'':<10}{cols}")
    vals = "  ".join(f"{summary['macro_f1'][v]:>6.3f}" for v in ordered)
    print(f"  {'macro-F1':<10}{vals}")
    ns = "  ".join(f"{summary['n_samples'][v]:>6}" for v in ordered)
    print(f"  {'n':<10}{ns}")

    if summary["robustness_drop"]:
        print("\nRobustness drop  (macro-F1 clean - mutator, positives-only):")
        for m, d in summary["robustness_drop"].items():
            print(f"  {m:<22} {d:+.3f}")
        print(f"  {'mean single-mutator':<22} "
              f"{summary['mean_single_mutator_drop']:+.3f}")

    if "clean" in scores:
        print("\nPer-CWE breakdown (clean variant):")
        print(f"  {'CWE':<10}{'P':>7}{'R':>7}{'F1':>7}{'supp':>7}"
              f"{'TP':>5}{'FP':>5}{'FN':>5}")
        for cwe in TARGET_CWES:
            c = scores["clean"].per_cwe[cwe]
            print(f"  {cwe:<10}{c.precision:>7.3f}{c.recall:>7.3f}"
                  f"{c.f1:>7.3f}{c.support:>7}{c.tp:>5}{c.fp:>5}{c.fn:>5}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", choices=[*DETECTORS, "all"], default="all")
    parser.add_argument("--variants", nargs="+", choices=VARIANTS,
                        default=list(VARIANTS))
    parser.add_argument("--variants-dir", default="data/test_variants")
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--out-dir", default="reports/eval")
    args = parser.parse_args()

    tools = list(DETECTORS) if args.tool == "all" else [args.tool]
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    exit_code = 0
    for tool_name in tools:
        detector = DETECTORS[tool_name]()
        if not detector.is_available():
            logger.warning(
                f"{tool_name}: not installed — skipping. "
                f"Install with `pip install {tool_name}`."
            )
            exit_code = 1
            continue

        logger.info(f"Running {tool_name} (v{detector.version})")
        records = run_tool(detector, args.variants,
                           args.variants_dir, args.raw_dir)

        pred_path = out_dir / f"{tool_name}_predictions.jsonl"
        with pred_path.open("w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r.to_json()) + "\n")

        summary = build_summary(tool_name, records)
        print_report(summary)

        summary.pop("_variant_scores")
        (out_dir / f"{tool_name}_summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8")
        logger.info(f"  wrote {pred_path} and {tool_name}_summary.json")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
