"""Semgrep detector.

Like Bandit, Semgrep batch-scans a directory. Each finding carries a
``extra.metadata.cwe`` field (a CWE string or list of strings); we fold
those onto our 7 target classes with `normalize_cwe`.

Semgrep is not in the project venv by default. `is_available()` returns
False until ``pip install semgrep`` has been run; `run()` raises a clear
error rather than failing cryptically.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path

from src.eval.cwe_map import normalize_cwe
from src.eval.detectors.base import Detector, Prediction, find_executable
from src.eval.samples import EvalSample

#: Default Semgrep rulesets, per docs/reference/EVALUATION_METHODOLOGY.md section 5.1.
#: ``p/python`` alone is mostly correctness lints; the security-audit
#: and owasp-top-ten packs carry the injection/XSS/SSRF rules with CWE
#: metadata. All three are fetched from the registry once and cached.
DEFAULT_CONFIGS: tuple[str, ...] = (
    "p/python",
    "p/security-audit",
    "p/owasp-top-ten",
)


class SemgrepDetector(Detector):
    name = "semgrep"

    def __init__(self, configs: tuple[str, ...] = DEFAULT_CONFIGS) -> None:
        self._exe = find_executable("semgrep")
        self._configs = tuple(configs)
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
                self._version = (out.stdout or out.stderr).strip().splitlines()[0]
        return self._version

    def run(self, samples: list[EvalSample]) -> dict[str, Prediction]:
        if not self._exe:
            raise RuntimeError(
                "semgrep executable not found — install it with "
                "`pip install semgrep`"
            )
        if not samples:
            return {}

        with tempfile.TemporaryDirectory(prefix="semgrep_eval_") as tmp:
            tmpdir = Path(tmp)
            for s in samples:
                (tmpdir / f"{s.id}.py").write_text(s.code, encoding="utf-8")

            cmd = [self._exe, "scan", "--json", "--quiet"]
            for cfg in self._configs:
                cmd += ["--config", cfg]
            cmd.append(str(tmpdir))

            t0 = time.monotonic()
            proc = subprocess.run(
                cmd, capture_output=True, text=True, check=False,
            )
            elapsed_ms = int((time.monotonic() - t0) * 1000)

            if not proc.stdout.strip():
                raise RuntimeError(
                    f"semgrep produced no output (exit {proc.returncode}): "
                    f"{proc.stderr.strip()[:500]}"
                )
            report = json.loads(proc.stdout)

        findings: dict[str, list[dict]] = {s.id: [] for s in samples}
        for r in report.get("results", []):
            stem = Path(r.get("path", "")).stem
            if stem not in findings:
                continue
            meta = (r.get("extra") or {}).get("metadata") or {}
            cwe_field = meta.get("cwe")
            cwe_list = cwe_field if isinstance(cwe_field, list) else [cwe_field]
            findings[stem].append({
                "check_id": r.get("check_id"),
                "cwe": cwe_list,
                "line": (r.get("start") or {}).get("line"),
            })

        per_sample_ms = elapsed_ms // max(len(samples), 1)
        predictions: dict[str, Prediction] = {}
        for s in samples:
            hits = findings[s.id]
            predicted = {
                norm for f in hits for raw in f["cwe"]
                if (norm := normalize_cwe(raw)) is not None
            }
            predictions[s.id] = Prediction(
                predicted=predicted,
                raw={"findings": hits},
                latency_ms=per_sample_ms,
            )
        return predictions
