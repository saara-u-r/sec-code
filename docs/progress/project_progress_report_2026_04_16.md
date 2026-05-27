# Project Progress Report — April 16, 2026

## Objective
Build a high-authority, AI-driven security analysis pipeline for LLM-generated Flask applications, focused on real-world vulnerabilities and CVSS-based severity gradients.

---

## 1. Key Accomplishments Today

### A. Architectural Pivot: "Vulnerability-Only" Dataset
We refined the project goals to focus purely on **real-world vulnerable code samples**. 
- **Removed:** Synthetic/LLM code generation (avoiding low-quality "hallucinated" vulnerabilities).
- **Added:** A rigorous **CVE Attribution** flow where every code snippet is linked to an official security commit.
- **Goal:** Every sample in the dataset must be a proven, real-world security failure.

### B. Environment & Security Configuration
- **GitHub Authentication:** Configured `GITHUB_TOKEN` in the root `.env` file, increasing API rate limits from 10 to 30 requests per minute.
- **Python Environment:** Rebuilt the `.venv` virtual environment and installed all core dependencies (`flask`, `requests`, `python-dotenv`, etc.).
- **VS Code Integration:** Resolved integrated terminal environment injection issues to ensure `.env` variables are correctly loaded.

### C. Phase 1 Completion: Multi-Source Scraping
We successfully executed the Phase 1 ingestion pipeline, scraping data from four distinct sources:
- **GitHub Scraper:** Pattern-matching real repositories for f-string SQLi, os.system command injection, etc.
- **Exploit-DB:** Extracted real exploit proofs-of-concept and target code.
- **Repo Cloner:** Scraped core patterns from the official `pallets/flask` repository.
- **CVEfixes:** Ingested authoritative "code before fix" snippets from known security commits.

### D. Advanced Data Sanitization
We implemented a smarter `cleaner.py` to handle "dirty" data from Exploit-DB (write-ups containing the description mixed with code).
- **CVE Autodiscovery:** The system now automatically finds `CVE-YYYY-NNNNN` IDs within the source text.
- **Narrative Wrapping:** Instructions and reproduction steps are now automatically wrapped in `""" docstrings """`, making previously unparseable files **Valid Python**.
- **Results:** 
  - **Identified 16 CVEs** automatically.
  - **Recovered 47+ files** from "invalid syntax" to "valid code".

---

## 2. Current Dataset Status (`data/raw/`)

| Metric | Value |
| :--- | :--- |
| **Total Raw Samples** | 1,350 |
| **Deduplicated Samples** | 675 |
| **Valid Python Modules** | 469 (Up from 422) |
| **Confirmed Vulnerabilities** | 100% (is_vulnerable: true) |
| **Target CWEs** | CWE-89, CWE-78, CWE-22, CWE-502 |

---

## 3. Revised Implementation Roadmap

| Phase | Title | Objective | Status |
| :--- | :--- | :--- | :--- |
| **1** | **Ingestion** | Scrape real-world vulnerable snippets | **Complete** |
| **2** | **CVE Attribution** | Search GitHub for matching CVE commits | *Pending* |
| **3** | **CVSS Mapping** | Assign official NVD severity scores | *Pending* |
| **4** | **Dataset Construction** | Build final Train/Val/Test splits | *Planned* |
| **5** | **ML Defense** | Train vulnerability detection models | *Planned* |
| **6** | **Red Team** | Simulate real HTTP exploits | *Planned* |

---

## 4. Next Steps
- **Start Phase 2:** Build `src/labeler/cve_enricher.py` to search for official security advisories matching your 675 snippets.
- **CVSS Gradient:** Map these CVEs to official NVD scores to build your final "vulnerability gradient" JSON file.
