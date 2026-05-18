"""Bandit detector.

Bandit is batch-oriented: one process recursively scans a directory.
We materialize the sample batch into a temp directory (one ``{id}.py``
per sample), run ``bandit -f json -r``, and map each finding's rule id
to a target CWE via `bandit_rule_to_cwe`. Bandit's own ``issue_cwe`` is
kept in the raw record for audit but not used for scoring — see
`src.eval.cwe_map` for why.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path

from src.eval.cwe_map import bandit_rule_to_cwe
from src.eval.detectors.base import Detector, Prediction, find_executable
from src.eval.samples import EvalSample


class BanditDetector(Detector):
    name = "bandit"

    def __init__(self) -> None:
        self._exe = find_executable("bandit")
        self._version: str | None = None

    def is_available(self) -> bool:
        return self._exe is not None

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
                # "bandit 1.9.4\n  python version = ..."
                first = (out.stdout or out.stderr).strip().splitlines()[0]
                self._version = first.replace("bandit", "").strip() or "unknown"
        return self._version

    def run(self, samples: list[EvalSample]) -> dict[str, Prediction]:
        if not self._exe:
            raise RuntimeError(
                "bandit executable not found — install it with "
                "`pip install bandit`"
            )
        if not samples:
            return {}

        with tempfile.TemporaryDirectory(prefix="bandit_eval_") as tmp:
            tmpdir = Path(tmp)
            for s in samples:
                (tmpdir / f"{s.id}.py").write_text(s.code, encoding="utf-8")

            t0 = time.monotonic()
            proc = subprocess.run(
                [self._exe, "-f", "json", "-q", "-r", str(tmpdir)],
                capture_output=True, text=True, check=False,
            )
            elapsed_ms = int((time.monotonic() - t0) * 1000)

            # Bandit exits 1 when it finds issues; only a missing/empty
            # stdout is a real failure.
            if not proc.stdout.strip():
                raise RuntimeError(
                    f"bandit produced no output (exit {proc.returncode}): "
                    f"{proc.stderr.strip()[:500]}"
                )
            report = json.loads(proc.stdout)

        # Group findings by sample id (filename stem).
        findings: dict[str, list[dict]] = {s.id: [] for s in samples}
        for r in report.get("results", []):
            stem = Path(r.get("filename", "")).stem
            if stem in findings:
                findings[stem].append({
                    "test_id": r.get("test_id"),
                    "test_name": r.get("test_name"),
                    "bandit_cwe": (r.get("issue_cwe") or {}).get("id"),
                    "severity": r.get("issue_severity"),
                    "line": r.get("line_number"),
                })

        per_sample_ms = elapsed_ms // max(len(samples), 1)
        predictions: dict[str, Prediction] = {}
        for s in samples:
            hits = findings[s.id]
            predicted = {
                cwe for f in hits
                if (cwe := bandit_rule_to_cwe(f["test_id"] or "")) is not None
            }
            predictions[s.id] = Prediction(
                predicted=predicted,
                raw={"findings": hits},
                latency_ms=per_sample_ms,
            )
        return predictions
