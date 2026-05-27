"""OpenAI LLM detector — classify a Python file's CWE via the OpenAI
Chat Completions API.

Mirrors src/eval/detectors/llm.py for the Anthropic harness: the same
system prompt, the same one-line-CWE parsing rule, and the same offline
cost projection. One Chat Completions call per sample.
"""

from __future__ import annotations

import logging
import os
import time

from src.eval.detectors.base import Detector, Prediction
from src.eval.detectors.llm import SYSTEM_PROMPT, parse_llm_response
from src.eval.samples import EvalSample

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gpt-4o"

#: OpenAI list pricing, USD per 1M tokens. Used by the offline cost
#: projection only. Source: https://openai.com/api/pricing/ (May 2026).
_PRICING: dict[str, dict[str, float]] = {
    "gpt-4o": {"in": 2.50, "out": 10.00},
    "gpt-4o-mini": {"in": 0.15, "out": 0.60},
    "gpt-4-turbo": {"in": 10.00, "out": 30.00},
}
_EST_OUTPUT_TOKENS = 60


class OpenAILLMDetector(Detector):
    """OpenAI Chat Completions detector. One API call per sample."""

    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        self.model = model
        # gpt-4o -> "gpt_4o"; gpt-4o-mini -> "gpt_4o-mini" (keep readable).
        parts = model.split("-", 2)
        self.name = f"{parts[0]}_{parts[1]}" if len(parts) > 1 else model
        self._client = None

    @property
    def version(self) -> str:
        return self.model

    def is_available(self) -> bool:
        if not os.environ.get("OPENAI_API_KEY"):
            return False
        try:
            import openai  # noqa: F401
        except ImportError:
            return False
        return True

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI
            # max_retries=8 mirrors the Anthropic detector — absorbs 429s
            # with the server's retry-after header before bubbling up.
            self._client = OpenAI(max_retries=8)
        return self._client

    def estimate_cost(self, samples: list[EvalSample]) -> dict:
        """Offline cost projection — no API call, no key required."""
        price = _PRICING.get(self.model, _PRICING[DEFAULT_MODEL])
        sys_tokens = len(SYSTEM_PROMPT) // 4
        in_tokens = sum(sys_tokens + len(s.code) // 4 for s in samples)
        out_tokens = _EST_OUTPUT_TOKENS * len(samples)
        cost = in_tokens / 1e6 * price["in"] + out_tokens / 1e6 * price["out"]
        return {
            "model": self.model,
            "calls": len(samples),
            "est_input_tokens": in_tokens,
            "est_output_tokens": out_tokens,
            "est_cost_usd": round(cost, 2),
        }

    def run(self, samples: list[EvalSample]) -> dict[str, Prediction]:
        """Classify each sample with one Chat Completions call. Bills
        the OpenAI account."""
        import openai as _openai
        if not self.is_available():
            raise RuntimeError(
                "OpenAI detector unavailable — needs the `openai` package "
                "and OPENAI_API_KEY."
            )
        client = self._get_client()
        predictions: dict[str, Prediction] = {}

        def _call(code: str):
            return client.chat.completions.create(
                model=self.model,
                max_tokens=256,
                temperature=0,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": code},
                ],
            )

        for s in samples:
            t0 = time.monotonic()
            try:
                try:
                    msg = _call(s.code)
                except _openai.RateLimitError:
                    time.sleep(60)
                    msg = _call(s.code)
            except Exception as e:
                # One bad sample (oversized, content-policy refusal, transient
                # 500, etc.) must not abort the 665-call sweep. Record an
                # empty prediction and continue.
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
                predicted=parse_llm_response(answer),
                raw={
                    "response": answer,
                    "request_id": msg.id,
                    "usage": {
                        "input_tokens": msg.usage.prompt_tokens,
                        "output_tokens": msg.usage.completion_tokens,
                    },
                },
                latency_ms=elapsed_ms,
            )
        return predictions
