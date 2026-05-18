"""LLM detector — classify a Python file's CWE via the Anthropic Messages API.

Implements the protocol in EVALUATION_METHODOLOGY.md section 6.2: a fixed
system prompt lists the 7 target CWEs, the file contents go in the user
turn, and the model answers with a single line (a CWE identifier or
"safe"). The first non-empty line of the response is parsed.

Notes on Opus 4.7 (the default model):
  * `temperature` is removed on Opus 4.7 — sending it 400s. The
    methodology's "temperature=0" cannot be honoured; we omit sampling
    parameters entirely. Opus 4.7 is not bit-for-bit deterministic, but
    a terse classification prompt is highly stable in practice.
  * The system prompt is short (~250 tokens). Prompt caching has a
    4096-token minimum prefix on Opus 4.7, so the `cache_control` marker
    below is a no-op until the system prompt grows past that. It is left
    in as the correct, future-proof placement; the per-call file body
    lives in the user turn and is never cacheable regardless.
"""

from __future__ import annotations

import os
import re
import time

from src.eval.cwe_map import normalize_cwe
from src.eval.detectors.base import Detector, Prediction
from src.eval.samples import EvalSample

DEFAULT_MODEL = "claude-opus-4-7"

SYSTEM_PROMPT = """\
You are a security code reviewer. Given a Python source file, identify
whether it contains a vulnerability in one of these CWE classes:

  CWE-89  : SQL Injection
  CWE-79  : Cross-site Scripting
  CWE-22  : Path Traversal
  CWE-78  : OS Command Injection
  CWE-94  : Code Injection
  CWE-918 : Server-Side Request Forgery
  CWE-502 : Insecure Deserialization

If the file is safe, respond with "safe". If it contains one of these
vulnerabilities, respond with the CWE identifier. Respond with a single
line containing only the CWE identifier or "safe", followed by an
optional one-sentence justification."""

#: Anthropic list pricing, USD per 1M tokens. Used for the offline cost
#: projection (`estimate_cost`) — not billed, just arithmetic.
_PRICING: dict[str, dict[str, float]] = {
    "claude-opus-4-7": {"in": 5.0, "out": 25.0},
    "claude-opus-4-6": {"in": 5.0, "out": 25.0},
    "claude-sonnet-4-6": {"in": 3.0, "out": 15.0},
    "claude-haiku-4-5": {"in": 1.0, "out": 5.0},
}
#: Output is one short line plus an optional sentence — well under this.
_EST_OUTPUT_TOKENS = 60

_CWE_AT_LINE_START = re.compile(r"^CWE[-\s]?(\d+)", re.IGNORECASE)


def parse_llm_response(text: str) -> set[str]:
    """Parse a model response into a predicted-CWE set.

    Per the methodology: take the first non-empty line. If it starts
    with a CWE identifier, that is the prediction (folded onto the 7
    target classes; an out-of-scope CWE yields no prediction). Otherwise
    the line is treated as "safe" or "no answer" — both score as an
    empty prediction set.
    """
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = _CWE_AT_LINE_START.match(line)
        if m:
            norm = normalize_cwe(int(m.group(1)))
            return {norm} if norm else set()
        # First non-empty line was not a CWE — "safe" or unparseable.
        return set()
    return set()


class LLMDetector(Detector):
    """Anthropic-API-backed detector. One Messages API call per sample."""

    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        self.model = model
        # e.g. claude-opus-4-7 -> "claude_opus"
        parts = model.split("-")
        self.name = f"{parts[0]}_{parts[1]}" if len(parts) > 1 else model
        self._client = None

    @property
    def version(self) -> str:
        return self.model

    def is_available(self) -> bool:
        """Available only with the SDK installed and an API key set —
        a real run bills the account."""
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False
        return True

    def _get_client(self):
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic()
        return self._client

    def estimate_cost(self, samples: list[EvalSample]) -> dict:
        """Offline cost projection — no API call, no key required.

        Token counts are a chars/4 heuristic, good enough to decide
        whether to authorize a real run.
        """
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
        """Classify each sample with one Messages API call. Bills the
        account — gate real runs behind explicit authorization."""
        if not self.is_available():
            raise RuntimeError(
                "LLM detector unavailable — needs the `anthropic` package "
                "and ANTHROPIC_API_KEY."
            )
        client = self._get_client()
        predictions: dict[str, Prediction] = {}
        for s in samples:
            t0 = time.monotonic()
            msg = client.messages.create(
                model=self.model,
                max_tokens=256,
                # Opus 4.7: no `temperature` (removed), thinking off by default.
                system=[{
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=[{"role": "user", "content": s.code}],
            )
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            answer = next(
                (b.text for b in msg.content if b.type == "text"), ""
            )
            predictions[s.id] = Prediction(
                predicted=parse_llm_response(answer),
                raw={
                    "response": answer,
                    "request_id": msg._request_id,
                    "usage": {
                        "input_tokens": msg.usage.input_tokens,
                        "output_tokens": msg.usage.output_tokens,
                        "cache_read_input_tokens":
                            msg.usage.cache_read_input_tokens,
                    },
                },
                latency_ms=elapsed_ms,
            )
        return predictions
