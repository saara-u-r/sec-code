"""OpenRouter LLM detectors — DeepSeek R1 and Qwen Coder, free tier.

OpenRouter exposes an OpenAI-compatible Chat Completions API at
https://openrouter.ai/api/v1, so the existing `openai` SDK works
unchanged with a different base_url and the OPENROUTER_API_KEY. Both
detectors share the system prompt and parsing rule from llm.py — one
Chat Completions call per sample, with parse_llm_response stripping
`<think>...</think>` first in case the reasoning model leaks its
scratchpad into the content field (OpenRouter usually surfaces R1's
reasoning in a separate `message.reasoning` field, but not always).

Free-tier note: OpenRouter free models share a 20 req/min ceiling and
~200 req/day window (1000/day with $10+ credit added). A full sweep is
1584 calls (132 samples × 6 variants × 2 models), so plan on splitting
the run across days or use --max-samples for a smoke test first.
"""

from __future__ import annotations

import logging
import os
import re
import time

from src.eval.detectors.base import Detector, Prediction
from src.eval.detectors.llm import SYSTEM_PROMPT, parse_llm_response
from src.eval.samples import EvalSample

logger = logging.getLogger(__name__)

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Reasoning models sometimes echo their scratchpad inside <think>...</think>
# instead of using the separate `reasoning` field. Strip it before parsing
# so the first non-empty line is the actual verdict.
_THINK_BLOCK = re.compile(r"<think\b[^>]*>.*?</think>", re.DOTALL | re.IGNORECASE)

_EST_OUTPUT_TOKENS = 60


def _strip_thinking(text: str) -> str:
    return _THINK_BLOCK.sub("", text).strip()


class OpenRouterLLMDetector(Detector):
    """Base — concrete subclasses set `model` (OpenRouter slug) and `name`."""

    #: OpenRouter model slug, e.g. "deepseek/deepseek-r1:free".
    model: str = ""
    #: Short detector name used in output filenames, e.g. "deepseek_r1".
    name: str = ""

    def __init__(self) -> None:
        self._client = None

    @property
    def version(self) -> str:
        return self.model

    def is_available(self) -> bool:
        if not os.environ.get("OPENROUTER_API_KEY"):
            return False
        try:
            import openai  # noqa: F401 — OpenRouter uses the OpenAI SDK.
        except ImportError:
            return False
        return True

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(
                base_url=OPENROUTER_BASE_URL,
                api_key=os.environ["OPENROUTER_API_KEY"],
                max_retries=8,
            )
        return self._client

    def estimate_cost(self, samples: list[EvalSample]) -> dict:
        """Offline projection — free models always cost $0."""
        sys_tokens = len(SYSTEM_PROMPT) // 4
        in_tokens = sum(sys_tokens + len(s.code) // 4 for s in samples)
        out_tokens = _EST_OUTPUT_TOKENS * len(samples)
        return {
            "model": self.model,
            "calls": len(samples),
            "est_input_tokens": in_tokens,
            "est_output_tokens": out_tokens,
            "est_cost_usd": 0.0,
        }

    def _call(self, code: str):
        return self._get_client().chat.completions.create(
            model=self.model,
            # Reasoning models can need extra headroom even when only the
            # final line is parsed — OpenRouter caps reply tokens here.
            max_tokens=512,
            temperature=0,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": code},
            ],
        )

    def run(self, samples: list[EvalSample]) -> dict[str, Prediction]:
        import openai as _openai
        if not self.is_available():
            raise RuntimeError(
                f"{self.name} unavailable — set OPENROUTER_API_KEY and "
                "`pip install openai`."
            )
        predictions: dict[str, Prediction] = {}
        for s in samples:
            t0 = time.monotonic()
            try:
                try:
                    msg = self._call(s.code)
                except _openai.RateLimitError:
                    # Free tier's per-minute window resets in 60s; the
                    # daily cap is harder to recover from, but one extra
                    # try is cheap and the SDK retries are exhausted.
                    time.sleep(60)
                    msg = self._call(s.code)
            except Exception as e:
                # One bad call (provider 5xx, timeout, content-policy
                # refusal, etc.) must not abort the 665-call sweep.
                logger.warning(f"{self.name}: skipping {s.id} — {type(e).__name__}: {e}")
                predictions[s.id] = Prediction(
                    predicted=set(),
                    raw={"error": f"{type(e).__name__}: {e}"},
                    latency_ms=int((time.monotonic() - t0) * 1000),
                )
                continue
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            answer = msg.choices[0].message.content or ""
            predictions[s.id] = Prediction(
                predicted=parse_llm_response(_strip_thinking(answer)),
                raw={
                    "response": answer,
                    "request_id": msg.id,
                    "usage": {
                        "input_tokens":
                            msg.usage.prompt_tokens if msg.usage else None,
                        "output_tokens":
                            msg.usage.completion_tokens if msg.usage else None,
                    },
                },
                latency_ms=elapsed_ms,
            )
        return predictions


class DeepSeekR1Detector(OpenRouterLLMDetector):
    # The `:free` variant was deprecated by OpenRouter; the canonical
    # DeepSeek R1 endpoint is paid (~$0.70/$2.50 per 1M tokens as of
    # May 2026). A full 665-call sweep is ~$4.50 at current rates.
    model = "deepseek/deepseek-r1"
    name = "deepseek_r1"


class QwenCoderDetector(OpenRouterLLMDetector):
    model = "qwen/qwen3-coder:free"
    name = "qwen_coder"
