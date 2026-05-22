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

_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from dotenv import load_dotenv  # noqa: E402

# Load the project .env so ANTHROPIC_API_KEY (and other secrets) are
# available without an explicit `export` each shell session.
load_dotenv(_PROJECT_ROOT / ".env")

from src.eval.cwe_map import TARGET_CWES  # noqa: E402
from src.eval.detectors import DETECTORS, SAST_TOOLS  # noqa: E402
from src.eval.detectors.graphcodebert import GraphCodeBERTDetector  # noqa: E402
from src.eval.detectors.llm import LLMDetector  # noqa: E402
from src.eval.samples import SINGLE_MUTATORS, VARIANTS, load_variant  # noqa: E402
from src.eval.scoring import (  # noqa: E402
    PredictionRecord,
    load_cvss_scores,
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
    "sink_attr_obfuscate": "SAO",
    "sink_via_globals": "SVG",
    "taint_through_dict": "TTD",
    "composed": "Comp",
}


def run_tool(
    detector,
    variants: list[str],
    variants_dir: str,
    raw_dir: str,
    max_samples: int | None = None,
) -> list[PredictionRecord]:
    """Run one detector over every requested variant; return all records."""
    records: list[PredictionRecord] = []
    version = detector.version
    for variant in variants:
        samples = load_variant(variant, variants_dir, raw_dir)
        if max_samples is not None:
            samples = samples[:max_samples]
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


def build_summary(
    tool: str,
    records: list[PredictionRecord],
    cvss_scores: dict[str, float] | None = None,
) -> dict:
    """Compute macro-F1 per variant, per-CWE F1, robustness drop, and
    the §3.6 profile additions (Detection MCC + Severity-Weighted Recall)."""
    by_variant: dict[str, list[PredictionRecord]] = {}
    for r in records:
        by_variant.setdefault(r.variant, []).append(r)

    variant_scores = {
        v: score_variant(rs, cvss_scores) for v, rs in by_variant.items()
    }

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
        "detection_mcc": {v: s.detection_mcc for v, s in variant_scores.items()},
        "severity_weighted_recall": {
            v: s.severity_weighted_recall for v, s in variant_scores.items()
        },
        "swr_pool_size": {v: s.swr.pool_size for v, s in variant_scores.items()},
        "hcma": {v: s.hcma for v, s in variant_scores.items()},
        "weighted_kappa": {v: s.weighted_kappa for v, s in variant_scores.items()},
        "observed_agreement": {
            v: s.observed_agreement for v, s in variant_scores.items()
        },
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

    print("\nDetection profile (§3.6 — bounded, chance-corrected):")
    mccs = "  ".join(
        f"{m:>+6.3f}" if m is not None else f"{'—':>6}"
        for m in (summary['detection_mcc'][v] for v in ordered)
    )
    print(f"  {'MCC':<10}{mccs}")
    swrs = "  ".join(f"{summary['severity_weighted_recall'][v]:>6.3f}" for v in ordered)
    print(f"  {'SWR':<10}{swrs}")
    pool = "  ".join(f"{summary['swr_pool_size'][v]:>6}" for v in ordered)
    print(f"  {'SWR n':<10}{pool}")
    hcmas = "  ".join(f"{summary['hcma'][v]:>6.3f}" for v in ordered)
    print(f"  {'HCMA':<10}{hcmas}")
    kappas = "  ".join(
        f"{k:>+6.3f}" if k is not None else f"{'—':>6}"
        for k in (summary['weighted_kappa'][v] for v in ordered)
    )
    print(f"  {'kappa_w':<10}{kappas}")
    agrees = "  ".join(
        f"{a:>6.3f}" if a is not None else f"{'—':>6}"
        for a in (summary['observed_agreement'][v] for v in ordered)
    )
    print(f"  {'p_obs':<10}{agrees}")

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


def dry_run_llm(detector: LLMDetector, variants: list[str],
                variants_dir: str, raw_dir: str,
                max_samples: int | None) -> None:
    """Offline cost projection for an LLM detector — no API call."""
    print(f"\n{'=' * 64}")
    print(f"  {detector.name}  ({detector.version}) — DRY RUN, no API calls")
    print(f"{'=' * 64}")
    total_cost = 0.0
    total_calls = 0
    for variant in variants:
        samples = load_variant(variant, variants_dir, raw_dir)
        if max_samples is not None:
            samples = samples[:max_samples]
        est = detector.estimate_cost(samples)
        total_cost += est["est_cost_usd"]
        total_calls += est["calls"]
        print(f"  {variant:<22} {est['calls']:>4} calls  "
              f"~{est['est_input_tokens']:>8,} in + "
              f"{est['est_output_tokens']:>6,} out  "
              f"≈ ${est['est_cost_usd']:.2f}")
    print(f"  {'TOTAL':<22} {total_calls:>4} calls"
          f"{'':>27}≈ ${total_cost:.2f}")
    print("\nThis is an offline chars/4 estimate. A real run needs "
          "ANTHROPIC_API_KEY and `pip install anthropic`,\nand bills the "
          "account — run `--tool claude` (optionally `--max-samples N`) "
          "to execute it.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", choices=[*DETECTORS, "all"], default="all")
    parser.add_argument("--variants", nargs="+", choices=VARIANTS,
                        default=list(VARIANTS))
    parser.add_argument("--variants-dir", default="data/test_variants")
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--out-dir", default="reports/eval")
    parser.add_argument("--max-samples", type=int, default=None,
                        help="Cap samples per variant (cost control / smoke test).")
    parser.add_argument("--dry-run", action="store_true",
                        help="LLM tools: print an offline cost projection, "
                             "make no API calls.")
    args = parser.parse_args()

    # `all` runs the free local SAST tools only — never an LLM (real LLM
    # runs bill the Anthropic account and must be requested explicitly).
    tools = list(SAST_TOOLS) if args.tool == "all" else [args.tool]
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build the sample_id → cvss_score lookup once for SWR scoring.
    cvss_scores = load_cvss_scores(args.raw_dir)
    logger.info(f"Loaded {len(cvss_scores)} CVSS scores for SWR weighting")

    exit_code = 0
    for tool_name in tools:
        detector = DETECTORS[tool_name]()

        if args.dry_run and isinstance(detector, LLMDetector):
            dry_run_llm(detector, args.variants,
                        args.variants_dir, args.raw_dir, args.max_samples)
            continue

        if not detector.is_available():
            if isinstance(detector, LLMDetector):
                hint = "set ANTHROPIC_API_KEY and `pip install anthropic`"
            elif isinstance(detector, GraphCodeBERTDetector):
                hint = (f"a trained checkpoint at {detector.checkpoint} "
                        "and `pip install torch transformers`")
            else:
                hint = f"`pip install {tool_name}`"
            logger.warning(f"{tool_name}: unavailable — skipping. Needs {hint}.")
            exit_code = 1
            continue

        logger.info(f"Running {tool_name} (v{detector.version})")
        records = run_tool(detector, args.variants, args.variants_dir,
                           args.raw_dir, args.max_samples)

        pred_path = out_dir / f"{detector.name}_predictions.jsonl"
        with pred_path.open("w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r.to_json()) + "\n")

        summary = build_summary(detector.name, records, cvss_scores)
        print_report(summary)

        summary.pop("_variant_scores")
        (out_dir / f"{detector.name}_summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8")
        logger.info(f"  wrote {pred_path} and {detector.name}_summary.json")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
