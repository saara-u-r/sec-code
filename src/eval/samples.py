"""Test-sample loading for the evaluation harness.

The adversarial test set lives in ``data/test_variants/``. Each variant
directory holds one ``{sample_id}.py`` per test-split positive (67 of
them); only ``clean/`` also carries the ``{sample_id}.meta.json`` label
files. The 62 ``safe`` hard negatives are not mutated — they live in
``data/raw/`` and are loaded into the ``clean`` variant only, so the
``clean`` run measures false positives while the mutator runs measure
robustness on the 67 positives.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

#: Hard-negative samples excluded from the benchmark. Each entry is a
#: legitimate hardneg in ``data/raw/`` whose source file exceeds the
#: practical context window of current LLM detectors (chars/4 estimate
#: > 25K tokens; ``markup_to_escape_296506d7974aea62`` is a 1.79 MB
#: bundled artifact from docassemble). Files are kept on disk for audit
#: and provenance; the load path filters them out of every variant so
#: SAST, GraphCodeBERT, and LLM detectors all score the same 129-sample
#: test set. Documented in paper §3 (dataset construction).
EXCLUDED_SAMPLE_IDS: frozenset[str] = frozenset({
    "hardneg_markup_to_escape_296506d7974aea62",
    "hardneg_insert_url_allowlist_guard_5183615b0d6ce175",
    "hardneg_wrap_with_secure_filename_a77f0dd698a4d64c",
})

VARIANTS: tuple[str, ...] = (
    "clean",
    "dead_code_injection",
    "string_split",
    "variable_rename",
    "wrapper_extraction",
    "sink_attr_obfuscate",
    "sink_via_globals",
    "taint_through_dict",
    "composed",
)

#: Mutator variants only — excludes ``clean`` and ``composed``. These are
#: the single-mutator variants the robustness drop averages over.
SINGLE_MUTATORS: tuple[str, ...] = (
    "dead_code_injection",
    "string_split",
    "variable_rename",
    "wrapper_extraction",
    "sink_attr_obfuscate",
    "sink_via_globals",
    "taint_through_dict",
)


@dataclass(frozen=True)
class EvalSample:
    """One file to hand to a detector."""

    id: str
    cwe: str        # ground truth: a CWE-* class, or "safe"
    variant: str
    code: str
    path: str       # absolute path to the .py file on disk


def _read_code(py_path: Path, meta: dict | None = None) -> str | None:
    """Read source from disk, falling back to the meta blob."""
    if py_path.exists():
        return py_path.read_text(encoding="utf-8")
    if meta:
        return meta.get("code_before") or meta.get("code_after")
    return None


def load_labels(variants_dir: str | Path = "data/test_variants") -> dict[str, str]:
    """Map ``sample_id -> ground-truth CWE`` for the 67 test positives,
    read from ``clean/*.meta.json``."""
    clean = Path(variants_dir) / "clean"
    labels: dict[str, str] = {}
    for meta_path in sorted(clean.glob("*.meta.json")):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        labels[meta["id"]] = meta["cwe"]
    return labels


def _load_safe_samples(raw_dir: str | Path) -> list[EvalSample]:
    """Load the test-split ``safe`` hard negatives from ``data/raw/``."""
    raw = Path(raw_dir)
    out: list[EvalSample] = []
    for meta_path in sorted(raw.glob("*.meta.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if meta.get("split") != "test":
            continue
        if meta.get("cwe") != "safe" and not meta.get("is_hard_negative"):
            continue
        if meta["id"] in EXCLUDED_SAMPLE_IDS:
            continue
        py_path = meta_path.with_name(meta_path.name.replace(".meta.json", ".py"))
        code = _read_code(py_path, meta)
        if code is None:
            continue
        out.append(EvalSample(
            id=meta["id"], cwe="safe", variant="clean",
            code=code, path=str(py_path.resolve()),
        ))
    return out


def load_variant(
    variant: str,
    variants_dir: str | Path = "data/test_variants",
    raw_dir: str | Path = "data/raw",
    include_safe: bool = True,
) -> list[EvalSample]:
    """Load every sample for one variant.

    ``clean`` returns the 67 positives plus the 65 ``safe`` hard
    negatives (unless ``include_safe=False``). Mutator variants return
    the 67 positives only — the hard negatives are not mutated.
    """
    if variant not in VARIANTS:
        raise ValueError(f"unknown variant {variant!r}; expected one of {VARIANTS}")

    labels = load_labels(variants_dir)
    vdir = Path(variants_dir) / variant
    samples: list[EvalSample] = []
    for sample_id, cwe in sorted(labels.items()):
        py_path = vdir / f"{sample_id}.py"
        code = _read_code(py_path)
        if code is None:
            raise FileNotFoundError(f"missing variant file: {py_path}")
        samples.append(EvalSample(
            id=sample_id, cwe=cwe, variant=variant,
            code=code, path=str(py_path.resolve()),
        ))

    if variant == "clean" and include_safe:
        for s in _load_safe_samples(raw_dir):
            samples.append(EvalSample(
                id=s.id, cwe=s.cwe, variant="clean",
                code=s.code, path=s.path,
            ))

    return samples
