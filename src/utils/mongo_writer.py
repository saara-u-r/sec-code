"""
mongo_writer.py — MongoDB Atlas writer for vulnerability samples.

Provides a lazy singleton connection to Atlas. Called by save_code_sample()
in file_utils.py so every scraper writes to MongoDB automatically alongside
the local file system (Option A — dual write).

Connection is configured via MONGODB_URI in .env and mongodb section of
configs/config.yaml. If MONGODB_URI is not set, all writes silently no-op
so scrapers work without a DB connection.

Indexes created on first connection:
  - content_hash  (unique) — cross-run deduplication
  - cve_id        (sparse) — CVE lookups
  - cwe                    — filter by vulnerability type
  - source                 — per-scraper yield inspection
  - framework              — filter by web framework
  - cvss_score    (sparse) — range queries for severity gradient
  - nvd_enriched           — Phase 3: find unenriched samples quickly
  - split         (sparse) — Phase 4: fetch train/val/test splits
"""

import os
from typing import Optional

from dotenv import load_dotenv

from src.utils.logger import get_logger

load_dotenv()
logger = get_logger(__name__)

_client = None
_collection = None
_init_attempted = False


def _init() -> bool:
    """Lazy-initialize the MongoDB connection. Returns True if connected."""
    global _client, _collection, _init_attempted

    if _init_attempted:
        return _collection is not None

    _init_attempted = True
    uri = os.getenv("MONGODB_URI", "").strip()

    if not uri:
        logger.warning(
            "MONGODB_URI not set in .env — MongoDB writes disabled. "
            "Samples will be saved to the file system only."
        )
        return False

    try:
        import certifi
        from pymongo import MongoClient, ASCENDING
        from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
        from src.utils.config_loader import load_config

        config = load_config().get("mongodb", {})
        db_name  = config.get("database",   "sec_code")
        col_name = config.get("collection", "vulnerability_samples")

        _client = MongoClient(
            uri,
            serverSelectionTimeoutMS=5000,
            tlsCAFile=certifi.where(),
        )
        # Ping to confirm connection before declaring success
        _client.admin.command("ping")

        db = _client[db_name]
        _collection = db[col_name]

        _ensure_indexes(_collection)
        logger.info(
            f"MongoDB connected — {db_name}.{col_name} "
            f"({_client.topology_description.topology_type_name})"
        )
        return True

    except Exception as e:
        logger.error(f"MongoDB connection failed: {e}")
        _client = None
        _collection = None
        return False


def _ensure_indexes(col) -> None:
    """Create indexes if they don't exist yet. Safe to call on every startup."""
    from pymongo import ASCENDING

    existing = {idx["name"] for idx in col.list_indexes()}

    specs = [
        # Unique index on content_hash — prevents duplicate documents
        ({"content_hash": ASCENDING}, {"unique": True,  "name": "idx_content_hash"}),
        ({"cve_id":       ASCENDING}, {"sparse": True,  "name": "idx_cve_id"}),
        ({"cwe":          ASCENDING}, {"name": "idx_cwe"}),
        ({"source":       ASCENDING}, {"name": "idx_source"}),
        ({"framework":    ASCENDING}, {"name": "idx_framework"}),
        ({"cvss_score":   ASCENDING}, {"sparse": True,  "name": "idx_cvss_score"}),
        ({"nvd_enriched": ASCENDING}, {"name": "idx_nvd_enriched"}),
        ({"split":        ASCENDING}, {"sparse": True,  "name": "idx_split"}),
        # Compound: Phase 3 enricher — find unenriched CVE-linked samples
        ({"nvd_enriched": ASCENDING, "cve_id": ASCENDING},
         {"sparse": True, "name": "idx_enrich_queue"}),
        # Compound: ML training — fetch a split filtered by CWE
        ({"split": ASCENDING, "cwe": ASCENDING},
         {"sparse": True, "name": "idx_split_cwe"}),
    ]

    for keys, opts in specs:
        if opts["name"] not in existing:
            col.create_index(list(keys.items()), **opts)
            logger.debug(f"Created index: {opts['name']}")


def upsert_sample(meta: dict) -> bool:
    """
    Upsert a sample document into MongoDB using content_hash as the key.
    Returns True on success, False if MongoDB is unavailable.
    Silently skips if MONGODB_URI is not configured.
    """
    if not _init():
        return False

    try:
        from pymongo import UpdateOne

        content_hash = meta.get("content_hash")
        if not content_hash:
            logger.warning(f"Sample {meta.get('id')} has no content_hash — skipping MongoDB write")
            return False

        _collection.update_one(
            {"content_hash": content_hash},
            {"$set": meta},
            upsert=True,
        )
        return True

    except Exception as e:
        logger.error(f"MongoDB upsert failed for {meta.get('id')}: {e}")
        return False


def get_collection():
    """Return the raw pymongo Collection for direct queries (Phase 3, Phase 4, etc.)."""
    _init()
    return _collection


def close() -> None:
    """Close the MongoDB connection cleanly."""
    global _client, _collection, _init_attempted
    if _client:
        _client.close()
        logger.debug("MongoDB connection closed")
    _client = None
    _collection = None
    _init_attempted = False
