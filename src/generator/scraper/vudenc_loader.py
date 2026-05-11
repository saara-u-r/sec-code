"""
vudenc_loader.py — Phase 1, VUDENC source

Loads the VUDENC dataset from HuggingFace (DetectVul/Vudenc).
VUDENC contains 15,841 Python functions from real GitHub security commits,
labeled at statement level for 7 vulnerability types.

Label-to-CWE mapping (empirically confirmed via pattern analysis):
  1 → CWE-22  Path Traversal     (os.path.join dominant)
  2 → CWE-78  Command Injection   (subprocess / os.system dominant)
  3 → CWE-79  Cross-Site Scripting(mark_safe present; by elimination)
  4 → CWE-89  SQL Injection       (cursor.execute dominant — most confident)
  5 → XSRF    (CWE-352) — SKIP   (not in our target list)
  6 → Open Redirect (CWE-601) — SKIP
  7 → CWE-94  Code Injection/RCE  (by elimination; remaining of 7 types)

Note: VUDENC does not provide code_after (no fix pairs). Samples are saved
with code_after="" and label_confidence="medium" (GitHub commit context only,
no formal CVE linkage in the dataset).

Install: pip install datasets
"""


from src.utils.cwe_taxonomy import CWE_VULN_MAP
from src.utils.file_utils import build_meta, detect_framework, has_cwe_sink, hash_code, save_code_sample
from src.utils.logger import get_logger
from src.utils.mongo_writer import get_collection

logger = get_logger(__name__)

# Empirically confirmed label → CWE mapping (see module docstring).
#
# 2026-05-11 (Phase 2B): label 7 → CWE-94 mapping disabled. The runs/phase3_v1
# audit (AUDIT.md) found 14 of 15 vudenc CWE-94 samples were commit-level
# noise — files co-changed in a CWE-94 fix commit but containing no
# eval/exec/compile sinks. Remaining CWE-94 signal comes from cvefixes/ghsa.
LABEL_CWE_MAP: dict[int, str | None] = {
    1: "CWE-22",
    2: "CWE-78",
    3: "CWE-79",
    4: "CWE-89",
    5: None,       # XSRF — not our target
    6: None,       # Open Redirect — not our target
    7: None,       # CWE-94 — disabled per audit (see comment above)
}


def _load_existing_hashes() -> set[str]:
    try:
        col = get_collection()
        return {doc["content_hash"] for doc in col.find(
            {"source": "vudenc", "content_hash": {"$exists": True}},
            {"content_hash": 1, "_id": 0},
        )}
    except Exception:
        return set()


def run(output_dir: str = "data/raw") -> int:
    try:
        from datasets import load_dataset
    except ImportError:
        logger.error("HuggingFace `datasets` not installed. Run: pip install datasets")
        return 0

    logger.info("Loading DetectVul/Vudenc from HuggingFace…")
    try:
        ds = load_dataset("DetectVul/Vudenc")
    except Exception as e:
        logger.error(f"Failed to load DetectVul/Vudenc: {e}")
        return 0

    existing_hashes = _load_existing_hashes()
    logger.info(f"Skipping {len(existing_hashes)} already-ingested VUDENC hashes")

    seen: set[str] = set(existing_hashes)
    total = 0

    for split_name in ds.keys():
        rows = ds[split_name]
        logger.info(f"Processing VUDENC {split_name} split ({len(rows)} rows)…")

        for row in rows:
            labels = row["label"]
            max_label = max(labels)

            if max_label == 0:
                continue

            cwe = LABEL_CWE_MAP.get(max_label)
            if not cwe:
                continue

            vuln_type = CWE_VULN_MAP.get(cwe)
            if not vuln_type:
                continue

            code_before = "".join(row["raw_lines"]).strip()
            if not code_before or len(code_before) < 30:
                continue

            # Phase 2B sink-presence filter — vudenc uses commit-level labels
            # so without this gate we ingest co-changed-file noise.
            sink_ok, _ = has_cwe_sink(code_before, cwe)
            if not sink_ok:
                continue

            h = hash_code(code_before)
            if h in seen:
                continue
            seen.add(h)

            framework = detect_framework(code_before)

            meta = build_meta(
                {
                    "id":               f"vudenc_{vuln_type}_{h}",
                    "source":           "vudenc",
                    "cwe":              cwe,
                    "vuln_type":        vuln_type,
                    "label_source":     "vudenc_commit",
                    "label_confidence": "medium",
                    "framework":        framework,
                },
                code_before,
                "",   # no fix version available in VUDENC
            )
            save_code_sample(code_before, meta, output_dir)
            total += 1

    logger.info(f"vudenc_loader finished — {total} new samples saved")
    return total
