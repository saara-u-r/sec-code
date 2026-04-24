# AI-Driven Security Analysis and Autonomous Red Teaming for LLM-Generated Flask Applications

## Project Overview

An integrated AI security pipeline that generates, analyzes, labels, and red-teams LLM-generated Flask applications in a continuous feedback loop.

## Phases

| Phase | Module | Description |
|-------|--------|-------------|
| 1 | `src/generator` | Ingest raw Flask snippets from GitHub/ExploitDB/CVEfixes |
| 2 | `src/labeler` | **CVE Attribution**: Link snippets to real-world security commits |
| 3 | `src/labeler` | **CVSS Gradient Mapping**: Assign official NVD severity scores |
| 4 | `data/datasets` | Structured dataset construction |
| 5 | `src/ml` | Train vulnerability detection models |
| 6 | `src/redteam` | Autonomous Red Team Simulation Engine |
| 7 | `src/feedback` | Feedback loop: exploit results → model retraining |

## Directory Structure

```
sec_code/
├── data/
│   ├── raw/            # Raw LLM-generated Flask apps
│   ├── labeled/        # Labeled with vulnerability metadata
│   ├── datasets/       # Final ML-ready datasets (train/val/test)
│   └── adversarial/    # Adversarial/deceptive code samples
├── src/
│   ├── generator/      # Phase 1: LLM code generation
│   ├── analyzer/       # Phase 2: Vulnerability static analysis
│   ├── labeler/        # Phase 3: CWE/OWASP labeling engine
│   ├── ml/             # Phase 5: ML model training + evaluation
│   ├── redteam/        # Phase 6: Red team engine
│   ├── feedback/       # Phase 7: Feedback loop system
│   └── utils/          # Shared utilities
├── models/             # Saved trained models
├── reports/            # Exploit validation + performance reports
├── tests/              # Unit + integration tests
├── scripts/            # CLI entry points
├── configs/            # Config files (YAML)
├── notebooks/          # Jupyter notebooks for EDA / demos
└── docker/             # Sandboxed execution environments
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Phase 1: Generate Flask apps
python scripts/run_generator.py

# Phase 2: Analyze vulnerabilities
python scripts/run_analyzer.py

# Phase 3: Label dataset
python scripts/run_labeler.py

# Phase 5: Train ML models
python scripts/run_training.py

# Phase 6: Run red team simulation
python scripts/run_redteam.py
```

## Target Vulnerabilities

- **CWE-89** — SQL Injection
- **CWE-78** — Command Injection
- **CWE-22** — Path Traversal
- **CWE-502** — Insecure Deserialization
