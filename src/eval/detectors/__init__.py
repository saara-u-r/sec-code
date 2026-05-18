"""Detector implementations for the evaluation harness."""

from src.eval.detectors.bandit import BanditDetector
from src.eval.detectors.base import Detector, Prediction, find_executable
from src.eval.detectors.semgrep import SemgrepDetector

#: Registry of available SAST detectors, keyed by CLI name.
DETECTORS: dict[str, type[Detector]] = {
    "bandit": BanditDetector,
    "semgrep": SemgrepDetector,
}

__all__ = [
    "Detector",
    "Prediction",
    "find_executable",
    "BanditDetector",
    "SemgrepDetector",
    "DETECTORS",
]
