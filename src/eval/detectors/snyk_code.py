"""Snyk Code detector.

Snyk Code is cloud-backed SAST: the CLI uploads source to Snyk's
analysis service and returns SARIF. We materialize the sample batch
into a temp directory (one ``{id}.py`` per sample), run
``snyk code test <dir> --json``, and parse the SARIF results.

Each rule carries its CWE tags directly in
``rules[].properties.cwe`` (e.g. ``["CWE-78"]``), so the mapping to
our seven target classes goes through ``normalize_cwe`` — no
Snyk-specific rule-to-CWE table to maintain.

Authentication: the CLI reads ``SNYK_TOKEN`` from the environment.
Our ``scripts/run_eval.py`` loads ``.env`` at startup, so the token
is available without an explicit shell export.

Snyk Code on the free tier needs to be enabled per-organization at
https://app.snyk.io/manage/snyk-code before the first call works.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

from src.eval.cwe_map import normalize_cwe
from src.eval.detectors.base import Detector, Prediction, find_executable
from src.eval.samples import EvalSample


def _cwes_from_rule(rule: dict) -> set[str]:
    """Extract target-class CWEs from a Snyk SARIF rule entry.

    Snyk puts CWE tags in ``rule.properties.cwe`` as a list of strings
    like ``["CWE-78", "CWE-77"]``. We fold each onto our seven target
    classes via ``normalize_cwe``.
    """
    props = rule.get("properties", {}) or {}
    out: set[str] = set()
    for tag in props.get("cwe") or []:
        s = str(tag).strip().upper().removeprefix("CWE-")
        if not s.isdigit():
            continue
        norm = normalize_cwe(int(s))
        if norm:
            out.add(norm)
    return out


class SnykCodeDetector(Detector):
    """Snyk Code SAST detector — batch-oriented, cloud-backed."""

    name = "snyk_code"

    def __init__(self) -> None:
        self._exe = find_executable("snyk")
        self._version: str | None = None

    def is_available(self) -> bool:
        if self._exe is None:
            return False
        # The CLI is installed but useless without a token.
        return bool(os.environ.get("SNYK_TOKEN"))

    @property
    def version(self) -> str:
        if self._version is None:
            if not self._exe:
                self._version = "not-installed"
            else:
                out = subprocess.run(
                    [self._exe, "--version"],
                    capture_output=True, text=True, check=False,
                )
                first = (out.stdout or out.stderr).strip().splitlines()[0]
                m = re.search(r"(\d+\.\d+\.\d+)", first)
                self._version = m.group(1) if m else "unknown"
        return self._version

    def run(self, samples: list[EvalSample]) -> dict[str, Prediction]:
        if not self._exe:
            raise RuntimeError(
                "snyk executable not found — install with "
                "`brew install snyk-cli`"
            )
        if not os.environ.get("SNYK_TOKEN"):
            raise RuntimeError(
                "SNYK_TOKEN not set — add it to .env or run `snyk auth`"
            )
        if not samples:
            return {}

        with tempfile.TemporaryDirectory(prefix="snyk_eval_") as tmp:
            tmpdir = Path(tmp)
            for s in samples:
                (tmpdir / f"{s.id}.py").write_text(s.code, encoding="utf-8")

            t0 = time.monotonic()
            # `--json` emits SARIF on stdout. Exit code 1 means findings
            # exist (success), 2 means a real error.
            proc = subprocess.run(
                [self._exe, "code", "test", str(tmpdir), "--json"],
                capture_output=True, text=True, check=False,
            )
            elapsed_ms = int((time.monotonic() - t0) * 1000)

            if not proc.stdout.strip():
                raise RuntimeError(
                    f"snyk produced no output (exit {proc.returncode}): "
                    f"{proc.stderr.strip()[:1000]}"
                )
            try:
                report = json.loads(proc.stdout)
            except json.JSONDecodeError as e:
                raise RuntimeError(
                    f"snyk output is not JSON (exit {proc.returncode}): "
                    f"{e}; first 500 chars: {proc.stdout[:500]}"
                ) from e

        # Build {rule_id -> set(target CWEs)} from the SARIF run's rules.
        run_obj = (report.get("runs") or [{}])[0]
        rules_block = (run_obj.get("tool") or {}).get("driver") or {}
        rule_cwes: dict[str, set[str]] = {}
        for rule in rules_block.get("rules") or []:
            rid = rule.get("id", "")
            cwes = _cwes_from_rule(rule)
            if cwes:
                rule_cwes[rid] = cwes

        # Group results by sample id (filename stem).
        findings: dict[str, list[dict]] = {s.id: [] for s in samples}
        for r in run_obj.get("results") or []:
            rid = r.get("ruleId", "")
            for loc in r.get("locations") or []:
                uri = ((loc.get("physicalLocation") or {})
                       .get("artifactLocation") or {}).get("uri", "")
                stem = Path(uri).stem
                if stem in findings:
                    findings[stem].append({
                        "rule_id": rid,
                        "cwes": sorted(rule_cwes.get(rid, set())),
                        "message": (r.get("message") or {}).get("text", ""),
                    })
                    break

        per_sample_ms = elapsed_ms // max(len(samples), 1)
        predictions: dict[str, Prediction] = {}
        for s in samples:
            hits = findings[s.id]
            predicted: set[str] = set()
            for h in hits:
                predicted.update(h["cwes"])
            predictions[s.id] = Prediction(
                predicted=predicted,
                raw={"findings": hits, "n_rules": len(rule_cwes)},
                latency_ms=per_sample_ms,
            )
        return predictions
