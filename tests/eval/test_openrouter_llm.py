"""Tests for src.eval.detectors.openrouter_llm — offline surface only.

Mirrors test_llm.py / test_openai_llm.py: no API calls, no key required.
The detector shares parse_llm_response with the Anthropic harness (covered
there); these tests pin the OpenRouter-specific behavior — naming, the
free-tier $0 cost projection, and the <think>-stripping safety net for
reasoning models.
"""

import pytest

from src.eval.detectors.openrouter_llm import (
    DeepSeekR1Detector,
    OpenRouterLLMDetector,
    QwenCoderDetector,
    _strip_thinking,
)
from src.eval.samples import EvalSample


def _sample(code: str) -> EvalSample:
    return EvalSample(id="s", cwe="CWE-89", variant="clean",
                      code=code, path="/tmp/s.py")


def test_deepseek_metadata():
    det = DeepSeekR1Detector()
    assert det.name == "deepseek_r1"
    assert det.version == "deepseek/deepseek-r1:free"


def test_qwen_metadata():
    det = QwenCoderDetector()
    assert det.name == "qwen_coder"
    assert det.version == "qwen/qwen3-coder:free"


def test_detectors_unavailable_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert DeepSeekR1Detector().is_available() is False
    assert QwenCoderDetector().is_available() is False


def test_estimate_cost_is_free():
    est = DeepSeekR1Detector().estimate_cost(
        [_sample("x = 1\n") for _ in range(10)]
    )
    assert est["calls"] == 10
    assert est["est_input_tokens"] > 0
    assert est["est_output_tokens"] > 0
    assert est["est_cost_usd"] == 0.0


def test_estimate_cost_empty():
    est = QwenCoderDetector().estimate_cost([])
    assert est["calls"] == 0
    assert est["est_cost_usd"] == 0.0


@pytest.mark.parametrize("text,expected", [
    ("<think>let me reason</think>\nCWE-89", "CWE-89"),
    ("<think>multi\nline\nreasoning</think>CWE-22", "CWE-22"),
    ("plain text no think tag", "plain text no think tag"),
    ("<THINK>upper case</THINK>safe", "safe"),
])
def test_strip_thinking(text, expected):
    assert _strip_thinking(text) == expected


def test_base_class_is_abstract_via_empty_model():
    # Sanity: the base class has no model — only subclasses are runnable.
    assert OpenRouterLLMDetector.model == ""
    assert OpenRouterLLMDetector.name == ""
