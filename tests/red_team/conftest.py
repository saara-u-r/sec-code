"""
conftest.py — pytest fixtures for the red_team test suite.

Provides:
  • `synthetic_functions`   — small hand-crafted functions for fast unit tests
  • `real_world_samples`    — diversity sampler: 10 functions from each of the
    5 major sources (cvefixes, ghsa_db, osv, vudenc, plus one fallback) for
    a total of 50 real samples drawn from MongoDB
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Synthetic functions — small, predictable, used for fast unit tests
# ---------------------------------------------------------------------------

_SYNTHETIC = [
    # Simple SQLi
    """
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)
""",
    # XSS via Markup
    """
def render_comment(text):
    from flask import Markup
    return Markup(text)
""",
    # Command injection
    """
def ping_host(host):
    import os
    return os.system(f"ping -c 1 {host}")
""",
    # Path traversal
    """
def read_file(filename):
    import os
    path = os.path.join("/data", filename)
    return open(path).read()
""",
    # Deserialization
    """
def load_session(blob):
    import pickle
    return pickle.loads(blob)
""",
    # SSRF
    """
def fetch_url(url):
    import requests
    return requests.get(url).text
""",
    # Code injection (eval)
    """
def calc(expr):
    return eval(expr)
""",
    # Function with docstring (tests docstring preservation)
    '''
def documented(x):
    """This function does a thing."""
    return x + 1
''',
    # Async function
    """
async def async_get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return await db.execute(query)
""",
    # Function with decorator
    """
@app.route("/users/<int:uid>")
def show_user(uid):
    return f"<h1>User {uid}</h1>"
""",
    # Function with try/except
    """
def safe_divide(a, b):
    try:
        return a / b
    except ZeroDivisionError:
        return None
""",
    # Function with nested for + if
    """
def count_evens(items):
    n = 0
    for x in items:
        if x % 2 == 0:
            n += 1
    return n
""",
]


@pytest.fixture
def synthetic_functions() -> list[str]:
    """Return the list of synthetic function source strings."""
    return [s.strip() for s in _SYNTHETIC]


# ---------------------------------------------------------------------------
# Real-world diversity sampler
# ---------------------------------------------------------------------------

_REAL_WORLD_CACHE: list[str] | None = None


def _load_real_world_samples() -> list[str]:
    """
    Pull 10 samples from each major source for a total of 50 real samples.

    Returns code_before strings. Uses MongoDB; if unreachable, falls back to
    reading from data/raw/*.py.
    """
    samples: list[str] = []

    try:
        from src.utils.mongo_writer import get_collection
        col = get_collection()
        target_sources = ["cvefixes", "ghsa_db", "osv", "vudenc", "ghsa"]
        per_source = 10

        for src in target_sources:
            cursor = col.find(
                {"source": src, "code_before": {"$exists": True, "$ne": ""}},
                {"code_before": 1, "_id": 0},
            ).limit(per_source)
            for doc in cursor:
                code = doc.get("code_before", "")
                if code and len(code) > 50:
                    samples.append(code)

        if samples:
            return samples
    except Exception as e:
        logger.warning(f"MongoDB diversity sampler failed, falling back to disk: {e}")

    # Fallback: pull from data/raw/*.py if MongoDB is unavailable
    raw = Path("data/raw")
    if raw.exists():
        py_files = sorted(raw.glob("*.py"))[:50]
        for p in py_files:
            try:
                code = p.read_text(encoding="utf-8", errors="ignore")
                if code and len(code) > 50:
                    samples.append(code)
            except Exception:
                continue

    return samples


@pytest.fixture(scope="session")
def real_world_samples() -> list[str]:
    """50 real samples from MongoDB, drawn diversely across sources."""
    global _REAL_WORLD_CACHE
    if _REAL_WORLD_CACHE is None:
        _REAL_WORLD_CACHE = _load_real_world_samples()
    if not _REAL_WORLD_CACHE:
        pytest.skip("No real-world samples available (MongoDB and data/raw both empty)")
    return _REAL_WORLD_CACHE
