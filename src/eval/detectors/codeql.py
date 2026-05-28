"""CodeQL detector.

CodeQL is database-oriented: ``codeql database create`` builds a
relational fact database from a source tree, then ``codeql database
analyze`` runs a query suite against the database and emits SARIF.
Database creation is the slow step (5-30 s on a small directory), so
we materialize all samples of a batch into one temp directory and
build a single database per call to ``run()`` — the harness will pass
one variant's samples at a time.

The query suite is ``python-security-extended.qls`` from
``codeql/python-queries``: 54 security queries, no code-quality
lints that would inflate the safe-class false-positive rate.

Rule-to-CWE mapping is read from each result's
``rule.properties.tags``, which CodeQL prefixes with
``external/cwe/cwe-<id>``. We fold those onto the seven target
classes via the existing ``normalize_cwe`` helper, so there is no
separate CodeQL-specific mapping table to drift from the rule set.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
import time
from pathlib import Path

from src.eval.cwe_map import normalize_cwe
from src.eval.detectors.base import Detector, Prediction, find_executable
from src.eval.samples import EvalSample

logger = logging.getLogger(__name__)

#: Default query suite. Security-only, extended ruleset (54 queries as
#: of codeql/python-queries 1.8.3). Adding the quality suite would
#: pull in lint-style rules that inflate FP rate on the safe class.
_DEFAULT_SUITE = "python-security-extended.qls"

#: SARIF property tag pattern emitted by CodeQL: ``external/cwe/cwe-022``.
_CWE_TAG = re.compile(r"^external/cwe/cwe-(\d+)$", re.IGNORECASE)


def _cwes_from_rule(rule: dict) -> set[str]:
    """Extract target-class CWEs from a SARIF rule's tag list."""
    props = rule.get("properties", {}) or {}
    tags = props.get("tags") or []
    out: set[str] = set()
    for tag in tags:
        m = _CWE_TAG.match(str(tag))
        if not m:
            continue
        norm = normalize_cwe(int(m.group(1)))
        if norm:
            out.add(norm)
    return out


class CodeQLDetector(Detector):
    """CodeQL-backed detector — one database per batch of samples."""

    name = "codeql"

    def __init__(self, suite: str = _DEFAULT_SUITE) -> None:
        self._exe = find_executable("codeql")
        self._version: str | None = None
        self._suite = suite

    def is_available(self) -> bool:
        if self._exe is None:
            return False
        # The query pack must be downloaded (`codeql pack download
        # codeql/python-queries`); without it, analyze will fail.
        try:
            out = subprocess.run(
                [self._exe, "resolve", "qlpacks", "--format=json"],
                capture_output=True, text=True, check=False, timeout=15,
            )
        except (subprocess.TimeoutExpired, OSError):
            return False
        return "codeql/python-queries" in out.stdout

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
                # "CodeQL command-line toolchain release 2.25.5."
                first = (out.stdout or out.stderr).strip().splitlines()[0]
                m = re.search(r"(\d+\.\d+\.\d+)", first)
                self._version = m.group(1) if m else "unknown"
        return self._version

    def run(self, samples: list[EvalSample]) -> dict[str, Prediction]:
        if not self._exe:
            raise RuntimeError(
                "codeql executable not found — install with "
                "`brew install --cask codeql`"
            )
        if not samples:
            return {}

        with tempfile.TemporaryDirectory(prefix="codeql_eval_") as tmp:
            tmp_path = Path(tmp)
            src = tmp_path / "src"
            src.mkdir()
            db = tmp_path / "db"
            sarif = tmp_path / "results.sarif"

            for s in samples:
                (src / f"{s.id}.py").write_text(s.code, encoding="utf-8")

            t0 = time.monotonic()
            # 1. Build the CodeQL database from the materialized source dir.
            #    --overwrite is safe because db doesn't exist yet; it keeps
            #    re-runs idempotent during development.
            create = subprocess.run(
                [self._exe, "database", "create", str(db),
                 "--language=python",
                 f"--source-root={src}",
                 "--overwrite", "--quiet"],
                capture_output=True, text=True, check=False,
            )
            if create.returncode != 0:
                raise RuntimeError(
                    f"codeql database create failed (exit "
                    f"{create.returncode}): "
                    f"{create.stderr.strip()[:1000]}"
                )

            # 2. Run the security-extended suite against the database.
            analyze = subprocess.run(
                [self._exe, "database", "analyze", str(db),
                 f"codeql/python-queries:codeql-suites/{self._suite}",
                 "--format=sarif-latest",
                 f"--output={sarif}",
                 "--quiet"],
                capture_output=True, text=True, check=False,
            )
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            if analyze.returncode != 0:
                raise RuntimeError(
                    f"codeql database analyze failed (exit "
                    f"{analyze.returncode}): "
                    f"{analyze.stderr.strip()[:1000]}"
                )

            report = json.loads(sarif.read_text(encoding="utf-8"))

        # Build {rule_id -> set(target CWEs)} from the SARIF run's rules.
        # SARIF wraps results under runs[0]; we only have one run.
        run_obj = (report.get("runs") or [{}])[0]
        rules_block = (run_obj.get("tool") or {}).get("driver") or {}
        rule_cwes: dict[str, set[str]] = {}
        for rule in rules_block.get("rules") or []:
            rule_id = rule.get("id", "")
            cwes = _cwes_from_rule(rule)
            if cwes:
                rule_cwes[rule_id] = cwes

        # Group results by sample id (filename stem).
        findings: dict[str, list[dict]] = {s.id: [] for s in samples}
        for r in run_obj.get("results") or []:
            rid = r.get("ruleId", "")
            locs = r.get("locations") or []
            for loc in locs:
                uri = ((loc.get("physicalLocation") or {})
                       .get("artifactLocation") or {}).get("uri", "")
                stem = Path(uri).stem
                if stem in findings:
                    findings[stem].append({
                        "rule_id": rid,
                        "cwes": sorted(rule_cwes.get(rid, set())),
                        "message": (r.get("message") or {}).get("text", ""),
                    })
                    break  # one location per result is enough for attribution

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
