"""Detector implementations for the evaluation harness."""

from collections.abc import Callable

from src.eval.detectors.bandit import BanditDetector
from src.eval.detectors.base import Detector, Prediction, find_executable
from src.eval.detectors.graphcodebert import GraphCodeBERTDetector
from src.eval.detectors.llm import LLMDetector
from src.eval.detectors.semgrep import SemgrepDetector

#: Tools run by `--tool all`. Free, local, no API cost. `graphcodebert`
#: needs a local checkpoint and CPU inference cycles but no external
#: services, so it joins the SAST sweep.
SAST_TOOLS: tuple[str, ...] = ("bandit", "semgrep", "graphcodebert")

#: Registry of all detectors, keyed by CLI name. Values are factories
#: (a no-arg callable returning a Detector). `claude` is excluded from
#: `all` because a real run bills the Anthropic account.
DETECTORS: dict[str, Callable[[], Detector]] = {
    "bandit": BanditDetector,
    "semgrep": SemgrepDetector,
    "graphcodebert": GraphCodeBERTDetector,
    "claude": LLMDetector,
}

__all__ = [
    "Detector",
    "Prediction",
    "find_executable",
    "BanditDetector",
    "SemgrepDetector",
    "GraphCodeBERTDetector",
    "LLMDetector",
    "DETECTORS",
    "SAST_TOOLS",
]
