"""Detector base class for the evaluation harness.

A detector takes a batch of `EvalSample`s and returns one `Prediction`
per sample. SAST tools are batch-oriented (one process scans a whole
directory); LLM detectors added later are per-sample but fit the same
`run()` signature.
"""

from __future__ import annotations

import shutil
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from src.eval.samples import EvalSample


@dataclass
class Prediction:
    """A detector's verdict on one sample."""

    #: CWE classes the tool flagged, a subset of TARGET_CWES. Empty means
    #: the tool flagged nothing in our 7 classes (i.e. predicted "safe").
    predicted: set[str] = field(default_factory=set)
    #: Raw tool output for audit — must be JSON-serializable.
    raw: object = None
    #: Wall-clock latency attributed to this sample, milliseconds.
    latency_ms: int = 0


def find_executable(name: str) -> str | None:
    """Locate a CLI tool, preferring the one next to the active
    interpreter (the project venv) before falling back to PATH."""
    local = Path(sys.executable).parent / name
    if local.exists():
        return str(local)
    return shutil.which(name)


class Detector(ABC):
    """Base class for all detectors."""

    #: Short CLI/registry name, e.g. "bandit".
    name: str = "detector"

    @property
    @abstractmethod
    def version(self) -> str:
        """Tool version string, recorded in every prediction record."""

    @abstractmethod
    def is_available(self) -> bool:
        """True if the tool can actually run on this machine."""

    @abstractmethod
    def run(self, samples: list[EvalSample]) -> dict[str, Prediction]:
        """Scan a batch of samples. Return ``{sample_id: Prediction}``
        covering every input sample."""
