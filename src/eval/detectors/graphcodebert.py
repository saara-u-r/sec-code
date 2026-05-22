"""GraphCodeBERT learned-detector for the evaluation harness.

Loads the Phase 3 dual-task checkpoint (``runs/phase3_v1/best.pt``) and
classifies each sample's CWE via the 8-way ``cwe_logits`` head. The
sub-vector CVSS heads are not used here — this row scores on CWE
classification only, matching the SAST tools.

Per `src.eval.cwe_map.TARGET_CWES`, a predicted index that maps to one
of the 7 target CWEs becomes the singleton prediction; an "safe"
prediction (index 7) yields the empty set, matching the SAST contract.
"""

from __future__ import annotations

import time
from pathlib import Path

from src.eval.detectors.base import Detector, Prediction
from src.eval.samples import EvalSample

DEFAULT_CHECKPOINT = "runs/phase3_v1/best.pt"
DEFAULT_BACKBONE = "microsoft/graphcodebert-base"
DEFAULT_MAX_LENGTH = 512
DEFAULT_BATCH_SIZE = 8


class GraphCodeBERTDetector(Detector):
    """Phase 3 GraphCodeBERT dual-task model as an eval-harness Detector."""

    name = "graphcodebert"

    def __init__(
        self,
        checkpoint: str | Path = DEFAULT_CHECKPOINT,
        backbone: str = DEFAULT_BACKBONE,
        max_length: int = DEFAULT_MAX_LENGTH,
        batch_size: int = DEFAULT_BATCH_SIZE,
        device: str = "cpu",
    ) -> None:
        self.checkpoint = Path(checkpoint)
        self.backbone = backbone
        self.max_length = max_length
        self.batch_size = batch_size
        self.device = device
        self._model = None
        self._tokenizer = None
        self._index_to_cwe: list[str] = []
        self._version: str | None = None

    @property
    def version(self) -> str:
        if self._version is None:
            # Use the checkpoint mtime as a stable per-run version tag —
            # the eval doesn't need the training git SHA, just something
            # that distinguishes one trained model from another.
            if self.checkpoint.exists():
                mtime = int(self.checkpoint.stat().st_mtime)
                self._version = f"phase3-{mtime}"
            else:
                self._version = "not-installed"
        return self._version

    def is_available(self) -> bool:
        if not self.checkpoint.exists():
            return False
        try:
            import torch  # noqa: F401
            import transformers  # noqa: F401
        except ImportError:
            return False
        return True

    def _load(self) -> None:
        if self._model is not None:
            return
        import torch
        from transformers import AutoTokenizer

        from src.model.dataset import INDEX_TO_CWE
        from src.model.graphcodebert_dualtask import (
            GraphCodeBERTDualTask,
            ModelConfig,
        )

        self._index_to_cwe = list(INDEX_TO_CWE)
        self._tokenizer = AutoTokenizer.from_pretrained(self.backbone)

        model = GraphCodeBERTDualTask(ModelConfig(backbone_name=self.backbone))
        ckpt = torch.load(self.checkpoint, map_location=self.device, weights_only=False)
        model.load_state_dict(ckpt["model"])
        model.to(self.device)
        model.eval()
        self._model = model

    def run(self, samples: list[EvalSample]) -> dict[str, Prediction]:
        if not samples:
            return {}
        if not self.is_available():
            raise RuntimeError(
                f"graphcodebert checkpoint not found at {self.checkpoint} — "
                "train Phase 3 and copy best.pt into place"
            )

        import torch

        self._load()
        assert self._model is not None and self._tokenizer is not None

        # Local aliases — avoids attribute lookup inside the inner loop.
        from src.eval.cwe_map import TARGET_CWES
        target = set(TARGET_CWES)

        predictions: dict[str, Prediction] = {}
        t0 = time.monotonic()

        for start in range(0, len(samples), self.batch_size):
            batch = samples[start : start + self.batch_size]
            enc = self._tokenizer(
                [s.code for s in batch],
                truncation=True,
                padding=True,
                max_length=self.max_length,
                return_tensors="pt",
            )
            input_ids = enc["input_ids"].to(self.device)
            attention_mask = enc["attention_mask"].to(self.device)

            with torch.no_grad():
                out = self._model(input_ids, attention_mask)
                logits = out["cwe_logits"]
                probs = torch.softmax(logits, dim=-1)
                pred_idx = logits.argmax(dim=-1)

            for i, s in enumerate(batch):
                idx = int(pred_idx[i].item())
                cwe = self._index_to_cwe[idx]
                predicted = {cwe} if cwe in target else set()
                top_prob = float(probs[i, idx].item())
                predictions[s.id] = Prediction(
                    predicted=predicted,
                    raw={
                        "argmax_index": idx,
                        "argmax_label": cwe,
                        "argmax_prob": round(top_prob, 4),
                    },
                    latency_ms=0,  # filled in after the loop with a per-sample avg
                )

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        per_sample_ms = elapsed_ms // max(len(samples), 1)
        for pred in predictions.values():
            pred.latency_ms = per_sample_ms

        return predictions
