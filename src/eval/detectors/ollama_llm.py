"""Ollama LLM detectors — DeepSeek R1 and Qwen Coder, local, $0.

Ollama exposes an OpenAI-compatible Chat Completions API at
http://localhost:11434/v1, so the existing `openai` SDK works
unchanged with that base_url and a placeholder api_key. Concrete
detectors wrap two open-weights models the user must `ollama pull`
first:

  * `deepseek-r1:7b`        (DeepSeek R1 distilled into Qwen 7B)
  * `qwen2.5-coder:7b`      (Qwen 2.5 Coder, code-specialized)

These are the practical $0 path: no API key, no daily cap, no token
budget. Apple Silicon Macs run them with Metal GPU acceleration —
expect ~1–3 s per call. A full 792-call sweep takes roughly 30–60 min
per model on a 24 GB M-series.

Reasoning-model note: Ollama returns R1's chain-of-thought inside
`<think>...</think>` blocks in `message.content` (no separate
`reasoning` field). `_strip_thinking` removes them before parsing so
the first non-empty line is the actual verdict.
"""

from __future__ import annotations

import os
import time

from src.eval.detectors.base import Detector, Prediction
from src.eval.detectors.llm import SYSTEM_PROMPT, parse_llm_response
from src.eval.detectors.openrouter_llm import _strip_thinking
from src.eval.samples import EvalSample

DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434/v1"

_EST_OUTPUT_TOKENS = 60


class OllamaLLMDetector(Detector):
    """Base — concrete subclasses set `model` (Ollama tag) and `name`."""

    #: Ollama model tag as it appears in `ollama list`, e.g. "deepseek-r1:7b".
    model: str = ""
    #: Short detector name used in output filenames, e.g. "deepseek_local".
    name: str = ""

    def __init__(self) -> None:
        self._client = None

    @property
    def version(self) -> str:
        return self.model

    def is_available(self) -> bool:
        """Available iff the openai SDK is importable and the Ollama
        daemon answers on its OpenAI-compatible port."""
        try:
            import openai  # noqa: F401
        except ImportError:
            return False
        # Probe the daemon with a 1-second connect — `ollama serve` may be
        # down even when the binary is on PATH.
        import socket
        host = os.environ.get("OLLAMA_HOST", "localhost:11434")
        host, _, port = host.partition(":")
        try:
            with socket.create_connection((host, int(port or 11434)), timeout=1):
                return True
        except OSError:
            return False

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI
            base_url = os.environ.get(
                "OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL
            )
            # api_key is ignored by Ollama but required by the OpenAI SDK.
            self._client = OpenAI(
                base_url=base_url, api_key="ollama", max_retries=2
            )
        return self._client

    def estimate_cost(self, samples: list[EvalSample]) -> dict:
        """Local inference — always $0. Token counts informational."""
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
            # R1 emits long <think> traces before the verdict — 4096 is the
            # smallest cap that reliably lets the answer fit after the
            # reasoning. Qwen Coder uses far less but the cap is harmless.
            max_tokens=4096,
            temperature=0,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": code},
            ],
        )

    def run(self, samples: list[EvalSample]) -> dict[str, Prediction]:
        if not self.is_available():
            raise RuntimeError(
                f"{self.name} unavailable — install Ollama, run "
                "`ollama serve`, and `ollama pull "
                f"{self.model}` (needs `pip install openai`)."
            )
        predictions: dict[str, Prediction] = {}
        for s in samples:
            t0 = time.monotonic()
            msg = self._call(s.code)
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


class DeepSeekR1LocalDetector(OllamaLLMDetector):
    model = "deepseek-r1:7b"
    name = "deepseek_local"


class QwenCoderLocalDetector(OllamaLLMDetector):
    model = "qwen2.5-coder:7b"
    name = "qwen_local"
