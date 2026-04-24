# Project Structure — File & Folder Explanation

## Directory Overview

```
sec_code/
├── data/
│   ├── raw/
│   ├── labeled/
│   ├── datasets/
│   └── adversarial/
├── src/
│   ├── generator/
│   ├── analyzer/
│   ├── labeler/
│   ├── ml/
│   ├── redteam/
│   ├── feedback/
│   └── utils/
├── models/
├── reports/
├── tests/
├── scripts/
├── configs/
├── notebooks/
└── docker/
```

---

## `README.md`

**Why:** Every serious project needs a README. This is the entry point for anyone to understand what the project does, how to run it, and what each phase maps to.

**What it contains:**
- Phase table mapping each phase to its folder
- Full directory tree
- Quick start commands
- Target vulnerability list with CWE IDs

---

## `requirements.txt`

**Why:** Tracks all Python dependencies so the project installs consistently on any machine.

**What each group does:**

| Group | Libraries | Purpose |
|-------|-----------|---------|
| Core | `flask`, `requests`, `python-dotenv` | Run Flask apps, make HTTP calls, load `.env` secrets |
| Scrapers | `gitpython`, `requests` | Fetch real-world vulnerable code from GitHub, ExploitDB, etc. |
| Static Analysis | `bandit`, `ast-grep-py` | Scan Python code for known insecure patterns |
| ML | `scikit-learn`, `numpy`, `pandas` | Train and evaluate vulnerability detection models |
| Data | `pyyaml`, `jsonlines` | Read config files, store labeled data |
| Red Team | `httpx` | Send crafted HTTP attack payloads to Flask endpoints |
| Testing | `pytest`, `pytest-cov` | Run unit/integration tests with coverage |
| Notebooks | `jupyter` | Interactive EDA and demo walkthroughs |

---

## `configs/config.yaml`

**Why:** Centralizes all tunable settings in one place. Instead of hardcoding values across multiple files, every module reads from this config. You change one value here and it affects the whole pipeline.

**What each section controls:**

| Section | Controls |
|---------|---------|
| `generator` | Which LLM to use, how many apps to generate, what ratio are vulnerable vs secure, where to save output |
| `analyzer` | Which vulnerability types to scan for, where to find detection rules |
| `labeler` | Severity levels, the CWE ID mapping for each vuln type |
| `dataset` | Train/validation/test split ratios (70/15/15) |
| `ml` | Which ML model to use, which feature extraction method, where to save models |
| `redteam` | Target Flask server URL, payload folder, whether to run in sandbox mode |
| `feedback` | When to trigger retraining (e.g., if exploit success rate exceeds 30%) |

---

## `src/__init__.py`

**Why:** Makes `src` a Python package so you can do `from src.generator import ...` anywhere in the project without path hacks.

---

## `src/generator/__init__.py`

**Why:** Makes `generator` importable as a subpackage.

**What this module will contain (Phase 1):**
- `run.py` — orchestrator that triggers all scrapers in order
- `scraper/` — handles fetching real vulnerable samples from multiple sources
- Output: raw `.py` Flask app files or snippets saved to `data/raw/`

---

## `src/analyzer/__init__.py`

**Why:** Makes `analyzer` importable as a subpackage.

**What this module will contain (Phase 2):**
- `analyzer.py` — scans each Flask file using AST parsing and pattern matching
- `rules/` — detection rules for each vuln type (e.g., flag `os.system(request.args.get(...))`)
- It reads from `data/raw/`, outputs findings to `data/labeled/`

---

## `src/labeler/__init__.py`

**Why:** Makes `labeler` importable as a subpackage.

**What this module will contain (Phase 3):**
- `labeler.py` — takes analyzer output and assigns CWE ID and severity metadata
- `cvss_mapper.py` — calculates the **CVSS v3.1 score** for each vulnerability
- Output: `vulnerability_gradient.json` which maps every code snippet to its CVSS score

---

## `src/ml/__init__.py`

**Why:** Makes `ml` importable as a subpackage.

**What this module will contain (Phase 5):**
- `feature_extractor.py` — converts Flask source code into ML features (TF-IDF on tokens, or AST-based features)
- `trainer.py` — trains a classifier (Random Forest, etc.) on the labeled dataset
- `evaluator.py` — measures Precision, Recall, F1-score, false positive/negative rates
- Saves trained models to `models/`

---

## `src/redteam/__init__.py`

**Why:** Makes `redteam` importable as a subpackage.

**What this module will contain (Phase 6 — the core of the project):**
- `attack_simulator.py` — sends crafted HTTP requests to a running Flask app and checks if the exploit succeeded
- `adversarial_tester.py` — generates deceptive Flask code designed to evade the ML model
- `payloads/` folder — stores payload wordlists per vulnerability type
- `payloads/` folder — stores payload wordlists per vulnerability type

---

## `src/feedback/__init__.py`

**Why:** Makes `feedback` importable as a subpackage.

**What this module will contain (Phase 7):**
- `feedback_loop.py` — reads red team exploit results, identifies which vulnerabilities the ML model missed, augments the dataset with those failure cases, and triggers retraining
- This is what makes the system **self-improving**

---

## `src/utils/__init__.py`

**Why:** Makes `utils` importable as a subpackage.

**What this module will contain:**
- `file_utils.py` — reading/writing JSON, YAML, Python files
- `config_loader.py` — loads `configs/config.yaml` and provides it to all modules
- `logger.py` — centralized logging so all modules write to the same log format

---

## Folders Without Files Yet

| Folder | Purpose |
|--------|---------|
| `data/raw/` | Stores the raw Flask `.py` files generated by the LLM |
| `data/labeled/` | Stores JSON metadata files after analysis + labeling |
| `data/datasets/` | Final train/val/test split files ready for ML |
| `data/adversarial/` | Deceptive/poisoned code samples from red team adversarial testing |
| `models/` | Saved trained ML model files (`.joblib` or `.pkl`) |
| `reports/` | Auto-generated reports — exploit success rates, model metrics |
| `tests/` | `pytest` unit tests for each module |
| `scripts/` | CLI scripts you run from terminal (`run_generator.py`, `run_redteam.py`, etc.) |
| `notebooks/` | Jupyter notebooks for exploring the dataset, visualizing results, demo walkthroughs |
| `docker/` | Dockerfile for running Flask target apps in an isolated sandbox during red team attacks |

---

## Implementation Roadmap

Build the phases in this order:

| Phase | Module | Description |
|-------|--------|-------------|
| 1 | `src/generator` | Ingest raw Flask snippets from GitHub/ExploitDB/CVEfixes |
| 2 | `src/labeler` | **CVE Attribution**: Link snippets to real-world security commits |
| 3 | `src/labeler` | **CVSS Gradient Mapping**: Assign official NVD severity scores |
| 4 | `data/datasets` | Structured dataset construction |
| 5 | `src/ml` | Train and evaluate models |
| 6 | `src/redteam` | Build the red team engine |
| 7 | `src/feedback` | Wire the feedback loop |

---

## Target Vulnerabilities

| Vulnerability | CWE ID | Example Flask Pattern |
|--------------|--------|-----------------------|
| SQL Injection | CWE-89 | `f"SELECT * FROM users WHERE id={request.args.get('id')}"` |
| Command Injection | CWE-78 | `os.system(request.args.get('cmd'))` |
| Path Traversal | CWE-22 | `open("files/" + request.args.get('file'))` |
| Insecure Deserialization | CWE-502 | `pickle.loads(request.data)` |
