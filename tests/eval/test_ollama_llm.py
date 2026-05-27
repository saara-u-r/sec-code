"""Tests for src.eval.detectors.ollama_llm — offline surface only.

Mirrors test_openrouter_llm.py: no API calls, no daemon required. The
shared <think>-stripping helper lives in openrouter_llm and is tested
there; these tests pin the Ollama-specific behavior — naming, the $0
cost projection, and the daemon-not-running fallback.
"""

from src.eval.detectors.ollama_llm import (
    DeepSeekR1LocalDetector,
    OllamaLLMDetector,
    QwenCoderLocalDetector,
)
from src.eval.samples import EvalSample


def _sample(code: str) -> EvalSample:
    return EvalSample(id="s", cwe="CWE-89", variant="clean",
                      code=code, path="/tmp/s.py")


def test_deepseek_local_metadata():
    det = DeepSeekR1LocalDetector()
    assert det.name == "deepseek_local"
    assert det.version == "deepseek-r1:7b"


def test_qwen_local_metadata():
    det = QwenCoderLocalDetector()
    assert det.name == "qwen_local"
    assert det.version == "qwen2.5-coder:7b"


def test_unavailable_when_daemon_unreachable(monkeypatch):
    # Point at a port nothing is listening on — is_available should
    # return False without raising.
    monkeypatch.setenv("OLLAMA_HOST", "localhost:1")
    assert DeepSeekR1LocalDetector().is_available() is False


def test_estimate_cost_is_free():
    est = DeepSeekR1LocalDetector().estimate_cost(
        [_sample("x = 1\n") for _ in range(10)]
    )
    assert est["calls"] == 10
    assert est["est_input_tokens"] > 0
    assert est["est_output_tokens"] > 0
    assert est["est_cost_usd"] == 0.0


def test_estimate_cost_empty():
    est = QwenCoderLocalDetector().estimate_cost([])
    assert est["calls"] == 0
    assert est["est_cost_usd"] == 0.0


def test_base_class_is_abstract_via_empty_model():
    assert OllamaLLMDetector.model == ""
    assert OllamaLLMDetector.name == ""
