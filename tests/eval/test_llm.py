"""Tests for src.eval.detectors.llm — response parsing and cost projection.

These cover the pure/offline surface only; they do not call the API and
do not require the `anthropic` package or an API key.
"""

import pytest

from src.eval.detectors.llm import (
    DEFAULT_MODEL,
    LLMDetector,
    parse_llm_response,
)
from src.eval.samples import EvalSample


# --------------------------------------------------------------------------
# parse_llm_response
# --------------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("CWE-89", {"CWE-89"}),
    ("CWE-89: SQL injection via string concatenation", {"CWE-89"}),
    ("cwe-79", {"CWE-79"}),
    ("CWE 502", {"CWE-502"}),                 # space instead of hyphen
    ("CWE-80", {"CWE-79"}),                   # child folded to parent
    ("CWE-95", {"CWE-94"}),
])
def test_parse_extracts_cwe(text, expected):
    assert parse_llm_response(text) == expected


@pytest.mark.parametrize("text", [
    "safe",
    "safe — no user input reaches a sink",
    "This file is safe.",
    "",
    "   \n  \n",
    "I could not determine a vulnerability.",
])
def test_parse_non_cwe_is_empty(text):
    assert parse_llm_response(text) == set()


def test_parse_out_of_scope_cwe_is_empty():
    # CWE-611 (XXE) is a real CWE but outside the 7 scored classes.
    assert parse_llm_response("CWE-611: XML external entity") == set()


def test_parse_skips_leading_blank_lines():
    assert parse_llm_response("\n\n  \nCWE-22\nextra noise") == {"CWE-22"}


def test_parse_uses_first_nonblank_line_only():
    # Justification on a later line must not override the verdict.
    assert parse_llm_response("CWE-78\nAlso uses pickle elsewhere") == {"CWE-78"}


def test_parse_requires_cwe_at_line_start():
    # Methodology: the prediction line must *start* with the identifier.
    assert parse_llm_response("It looks like CWE-89 to me") == set()


# --------------------------------------------------------------------------
# LLMDetector — naming, availability, offline cost estimate
# --------------------------------------------------------------------------

def test_detector_name_derived_from_model():
    assert LLMDetector("claude-opus-4-7").name == "claude_opus"
    assert LLMDetector("claude-sonnet-4-6").name == "claude_sonnet"


def test_detector_version_is_model_id():
    assert LLMDetector().version == DEFAULT_MODEL


def test_detector_unavailable_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert LLMDetector().is_available() is False


def _sample(code: str) -> EvalSample:
    return EvalSample(id="s", cwe="CWE-89", variant="clean",
                      code=code, path="/tmp/s.py")


def test_estimate_cost_structure():
    det = LLMDetector("claude-opus-4-7")
    est = det.estimate_cost([_sample("x = 1\n") for _ in range(10)])
    assert est["model"] == "claude-opus-4-7"
    assert est["calls"] == 10
    assert est["est_input_tokens"] > 0
    assert est["est_output_tokens"] > 0
    assert est["est_cost_usd"] > 0


def test_estimate_cost_scales_with_sample_count():
    det = LLMDetector()
    small = det.estimate_cost([_sample("code") for _ in range(5)])
    large = det.estimate_cost([_sample("code") for _ in range(50)])
    assert large["est_cost_usd"] > small["est_cost_usd"]
    assert large["calls"] == 50


def test_estimate_cost_empty_is_zero():
    est = LLMDetector().estimate_cost([])
    assert est["calls"] == 0
    assert est["est_cost_usd"] == 0
