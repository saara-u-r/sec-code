"""
labeler/cvss_targets.py — Phase 2b CVSS target preparation.

For each sample, builds the regression / multi-task targets that Phase 3
trains its CVSS heads against, per design doc §5.

The CVSS prediction architecture decomposes the score into 8 sub-vector
classification heads (Le et al. 2022, MSR), then composes the final
score deterministically using the CVSS 3.1 formula. This module
prepares the per-sample targets for that architecture.

Per-sample target schema
------------------------

::

    {
      "cvss_score":   7.5 | null,        # the scalar regression target
      "cvss_vector":  "CVSS:3.1/..." | null,
      "sub_vectors": {                    # 8 classification targets
          "AV": "N",                      # Network / Adjacent / Local / Physical
          "AC": "L",                      # Low / High
          "PR": "N",                      # None / Low / High
          "UI": "N",                      # None / Required
          "S":  "U",                      # Unchanged / Changed
          "C":  "H",                      # None / Low / High
          "I":  "H",
          "A":  "N"
      } | null,
      "score_source": "advisory" | "band_midpoint" | "missing",
      "label_confidence": "high" | "medium" | "low",
      "loss_weight": 1.0                  # heavier for high-confidence labels
    }

Confidence-weighted loss
------------------------

Per design doc §5.4, hard-confidence samples (CVE-linked, CVSS in
advisory) get full loss weight; medium-confidence samples (VUDENC,
no CVE) get reduced weight; samples with no CVSS at all get 0 (their
sub-vector heads are masked out). This prevents noisy labels from
dominating the loss while still letting unlabeled samples contribute
to the CWE classification head's gradients.
"""

from __future__ import annotations

import re
from typing import Iterable

# ---------------------------------------------------------------------------
# CVSS sub-vector code spaces — must match the 8 classification heads
# ---------------------------------------------------------------------------

SUBVECTOR_CODES: dict[str, list[str]] = {
    "AV": ["N", "A", "L", "P"],     # Network / Adjacent / Local / Physical
    "AC": ["L", "H"],                # Low / High
    "PR": ["N", "L", "H"],
    "UI": ["N", "R"],
    "S":  ["U", "C"],
    "C":  ["N", "L", "H"],
    "I":  ["N", "L", "H"],
    "A":  ["N", "L", "H"],
}

# Severity-band fallback midpoints when no full vector is available
SEVERITY_BAND_MIDPOINT: dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      2.5,
    "NONE":     0.0,
}

# Confidence → loss weight (per design doc §5.4)
CONFIDENCE_LOSS_WEIGHT: dict[str, float] = {
    "high":   1.0,
    "medium": 0.3,
    "low":    0.1,
}

# Regex to capture the CVSS prefix and the 8 components
_VECTOR_RE = re.compile(r"^CVSS:3\.[01]/")


# ---------------------------------------------------------------------------
# Sub-vector parsing
# ---------------------------------------------------------------------------

def parse_subvectors(vector: str | None) -> dict[str, str] | None:
    """
    Parse a CVSS v3 vector string into the 8 single-letter sub-vector
    codes. Returns None if the vector is missing or malformed.
    """
    if not vector:
        return None
    if not _VECTOR_RE.match(vector):
        return None

    parts = vector.split("/")[1:]
    lookup = {}
    for p in parts:
        if ":" not in p:
            continue
        k, v = p.split(":", 1)
        lookup[k] = v

    out: dict[str, str] = {}
    for key, valid in SUBVECTOR_CODES.items():
        v = lookup.get(key)
        if v not in valid:
            return None  # malformed or unsupported value
        out[key] = v
    return out


# ---------------------------------------------------------------------------
# Deterministic CVSS 3.1 base score composer
# ---------------------------------------------------------------------------

def compose_base_score(sub: dict[str, str]) -> float | None:
    """
    Compute the CVSS v3.1 base score from sub-vector codes.

    Implements the official FIRST.org CVSS 3.1 formula. Returns None if
    any sub-vector is missing/invalid.
    """
    if not sub:
        return None
    needed = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not needed.issubset(sub.keys()):
        return None

    av  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(sub["AV"])
    ac  = {"L": 0.77, "H": 0.44}.get(sub["AC"])
    ui  = {"N": 0.85, "R": 0.62}.get(sub["UI"])
    if None in (av, ac, ui):
        return None

    scope_unchanged = sub["S"] == "U"
    if scope_unchanged:
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(sub["PR"])
    else:
        pr = {"N": 0.85, "L": 0.68, "H": 0.50}.get(sub["PR"])
    if pr is None:
        return None

    cia = {"N": 0.0, "L": 0.22, "H": 0.56}
    c, i, a = cia.get(sub["C"]), cia.get(sub["I"]), cia.get(sub["A"])
    if None in (c, i, a):
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_unchanged:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui

    if scope_unchanged:
        raw = min(impact + exploitability, 10.0)
    else:
        raw = min(1.08 * (impact + exploitability), 10.0)

    # Round up to one decimal place per CVSS spec
    import math
    return math.ceil(raw * 10) / 10


# ---------------------------------------------------------------------------
# Per-sample target builder
# ---------------------------------------------------------------------------

def build_target_for_sample(sample: dict) -> dict:
    """
    Construct the CVSS target dict for a single sample.

    `sample` is expected to have at least:
      • ``cvss_vector``       — full vector string, or None
      • ``cvss_score``        — float, or None
      • ``cvss_severity``     — "CRITICAL"/"HIGH"/... , or None
      • ``label_confidence``  — "high" | "medium" | "low", or None
    """
    vector  = sample.get("cvss_vector")
    score_in = sample.get("cvss_score")
    severity = (sample.get("cvss_severity") or "").upper()
    confidence = (sample.get("label_confidence") or "medium").lower()

    sub_vectors = parse_subvectors(vector) if vector else None

    if sub_vectors is not None:
        cvss_score = score_in if score_in is not None else compose_base_score(sub_vectors)
        score_source = "advisory" if score_in is not None else "computed_from_vector"
    elif score_in is not None:
        cvss_score = float(score_in)
        score_source = "advisory_score_only"
    elif severity in SEVERITY_BAND_MIDPOINT:
        cvss_score = SEVERITY_BAND_MIDPOINT[severity]
        score_source = "band_midpoint"
        # Severity-only confidence is downgraded — we don't have the
        # vector, so reduce the loss weight even further
        if confidence == "high":
            confidence = "medium"
    else:
        cvss_score = None
        score_source = "missing"
        # Missing CVSS → confidence-weighted loss for CVSS heads = 0
        # but the sample still contributes to CWE head training
        confidence = "low"

    loss_weight = CONFIDENCE_LOSS_WEIGHT.get(confidence, 0.0)
    if cvss_score is None:
        # No CVSS target → CVSS-head loss is masked out for this sample
        loss_weight = 0.0

    return {
        "cvss_score":       cvss_score,
        "cvss_vector":      vector,
        "sub_vectors":      sub_vectors,
        "score_source":     score_source,
        "label_confidence": confidence,
        "loss_weight":      loss_weight,
    }


# ---------------------------------------------------------------------------
# Bulk builder + summary statistics
# ---------------------------------------------------------------------------

def build_targets(samples: Iterable[dict]) -> dict:
    """
    Build CVSS targets for every sample in `samples`. Returns a dict
    keyed by ``content_hash`` (or ``id`` if no content_hash) with the
    schema described in this module's docstring.

    Also returns a ``_summary`` block with diagnostic counts.
    """
    targets: dict[str, dict] = {}
    score_sources: dict[str, int] = {}
    confidences: dict[str, int] = {}
    head_coverage = 0  # samples with sub_vectors available
    score_coverage = 0

    for s in samples:
        key = s.get("content_hash") or s.get("id")
        if not key:
            continue
        t = build_target_for_sample(s)
        targets[key] = t

        score_sources[t["score_source"]] = score_sources.get(t["score_source"], 0) + 1
        confidences[t["label_confidence"]] = confidences.get(t["label_confidence"], 0) + 1
        if t["sub_vectors"] is not None:
            head_coverage += 1
        if t["cvss_score"] is not None:
            score_coverage += 1

    return {
        "_schema_version":    1,
        "_summary": {
            "total":              len(targets),
            "score_coverage":     score_coverage,
            "subvector_coverage": head_coverage,
            "score_sources":      score_sources,
            "label_confidence":   confidences,
        },
        "_subvector_codes":   SUBVECTOR_CODES,
        "_confidence_weights": CONFIDENCE_LOSS_WEIGHT,
        "targets": targets,
    }
