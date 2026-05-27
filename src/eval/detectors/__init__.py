"""Detector implementations for the evaluation harness."""

from collections.abc import Callable

from src.eval.detectors.bandit import BanditDetector
from src.eval.detectors.base import Detector, Prediction, find_executable
from src.eval.detectors.graphcodebert import GraphCodeBERTDetector
from src.eval.detectors.llm import LLMDetector
from src.eval.detectors.openai_llm import OpenAILLMDetector
from src.eval.detectors.ollama_llm import (
    DeepSeekR1LocalDetector,
    OllamaLLMDetector,
    QwenCoderLocalDetector,
)
from src.eval.detectors.openrouter_llm import (
    DeepSeekR1Detector,
    OpenRouterLLMDetector,
    QwenCoderDetector,
)
from src.eval.detectors.semgrep import SemgrepDetector

#: Tools run by `--tool all`. Free, local, no API cost. `graphcodebert`
#: needs a local checkpoint and CPU inference cycles but no external
#: services, so it joins the SAST sweep.
SAST_TOOLS: tuple[str, ...] = ("bandit", "semgrep", "graphcodebert")

#: Registry of all detectors, keyed by CLI name. Values are factories
#: (a no-arg callable returning a Detector). LLM-backed detectors are
#: excluded from `all` because each hits an external surface:
#:   * `claude`, `gpt`           — billed cloud APIs
#:   * `deepseek`, `qwen`        — OpenRouter free tier (rate-limited)
#:   * `deepseek_local`, `qwen_local` — Ollama, local, $0
DETECTORS: dict[str, Callable[[], Detector]] = {
    "bandit": BanditDetector,
    "semgrep": SemgrepDetector,
    "graphcodebert": GraphCodeBERTDetector,
    "claude": LLMDetector,
    "gpt": OpenAILLMDetector,
    "deepseek": DeepSeekR1Detector,
    "qwen": QwenCoderDetector,
    "deepseek_local": DeepSeekR1LocalDetector,
    "qwen_local": QwenCoderLocalDetector,
}

__all__ = [
    "Detector",
    "Prediction",
    "find_executable",
    "BanditDetector",
    "SemgrepDetector",
    "GraphCodeBERTDetector",
    "LLMDetector",
    "OpenAILLMDetector",
    "OpenRouterLLMDetector",
    "DeepSeekR1Detector",
    "QwenCoderDetector",
    "OllamaLLMDetector",
    "DeepSeekR1LocalDetector",
    "QwenCoderLocalDetector",
    "DETECTORS",
    "SAST_TOOLS",
]
