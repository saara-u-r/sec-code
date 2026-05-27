# Literature Survey — AI-Driven Security Analysis for LLM-Generated Flask Applications

**Scope:** 15 peer-reviewed and high-quality arXiv papers, 2022–2025  
**Focus areas:** LLM-generated code security · Vulnerability datasets · ML/GNN-based detection · Red teaming · Prompt injection

---

## Full Survey Table

| # | Title | Authors | Year | Venue | Dataset Used / Introduced | Key Contribution | Relevance to This Project |
|---|-------|---------|------|-------|--------------------------|-----------------|--------------------------|
| 1 | **Security Weaknesses of Copilot-Generated Code in GitHub Projects: An Empirical Study** | Fu, Liang, Tahir, et al. | 2023 | ACM TOSEM (arXiv: 2310.02059) | 733 Python/JS snippets from GitHub Copilot | Found 29.5% of Python Copilot snippets were vulnerable across 43 CWE categories | Direct evidence that LLM-generated code contains real vulnerabilities — justifies this project's core premise |
| 2 | **Assessing the Security of GitHub Copilot Generated Code — A Targeted Replication Study** | Majdinasab, Bishop, Rasheed, et al. | 2023 | IEEE Xplore (arXiv: 2311.11177) | GitHub Copilot Python snippets + CodeQL analysis | Replicated Pearce et al.; newer Copilot reduced vuln rate from 36.54% → 27.25% but still significant | Shows LLM models are improving but not solved — validates the need for continuous evaluation like our feedback loop |
| 3 | **DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection** | Chen, Ding, Alowain, Chen, Wagner | 2023 | RAID 2023 | **DiverseVul** — 18,945 vulnerable + 330,492 non-vulnerable functions across 150 CWEs from 7,514 commits | Unified and deduplicated BigVul, Devign, ReVeal, CrossVul, CVEfixes into one clean benchmark | Direct dataset reference for our ML training pipeline (Phase 5); methodology mirrors our dataset construction (Phase 4) |
| 4 | **Vulnerability Detection with Code Language Models: How Far Are We?** | Ding, Fu, Ibrahim, Sitawarin, Chen, et al. | 2024 | arXiv: 2403.18624 | **PrimeVul** — 7k vulnerable + 229k benign C/C++ functions across 140+ CWEs | Showed a model scoring 68.26% F1 on BigVul drops to 3.09% on PrimeVul — existing benchmarks overestimate model performance | Critical warning for Phase 5: we must build a rigorous clean test set, not just use scraped data at face value |
| 5 | **CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software** | Bhandari, Naseer, Moonen | 2021 (updated July 2024) | PROMISE '21 | **CVEfixes** — 12,107 vuln-fixing commits across 4,249 projects, 11,873 CVEs, 272 CWE types | Automated pipeline linking CVE IDs to exact GitHub commits (before/after fix) | Directly integrated into our Phase 1 scraper (cvefixes_loader.py) — provides paired vulnerable/secure samples |
| 6 | **CyberSecEval 2: A Wide-Ranging Cybersecurity Evaluation Suite for Large Language Models** | Bhatt, Saxe, et al. (Meta AI) | 2024 | arXiv: 2404.13161 | Custom benchmark — exploit generation, prompt injection, code interpreter abuse | Average LLM compliance with cyber attack requests dropped from 52% (Dec 2023) → 28% (Apr 2024) across tested models | Blueprint for our Phase 6 red team engine — their attack categories map directly to our payload types |
| 7 | **Interpreters for GNN-Based Vulnerability Detection: Are We There Yet?** | Hu, Wang, Li, Peng, Wu, Zou, Jin | 2023 | ISSTA 2023 | Devign, IVDetect, ReVeal, DeepWukong evaluation sets | Evaluated 6 GNN explainability methods; found all interpreters failed to reliably identify true vulnerable statements | Informs Phase 5 model choice: GNNs have interpretability gaps — justifies using simpler, explainable models (Random Forest + TF-IDF) first |
| 8 | **Prompt Injection Attack Against LLM-Integrated Applications** | Liu, Deng, Li, Wang, et al. | 2023 | arXiv: 2306.05499 | HouYi framework; 36 commercial LLM-integrated apps tested | 86.1% black-box prompt injection success rate; 31/36 apps exploitable | Direct technical reference for Phase 6 `prompt_injector.py` — their HouYi framework is the methodology we replicate |
| 9 | **LineVul: A Transformer-based Line-Level Vulnerability Prediction** | Fu, Tantithamthavorn | 2022 | MSR 2022 | 188k+ C/C++ functions from multiple datasets | Achieved 160–379% higher F1 than prior methods for function-level; 12–25% better line-level Top-10 Accuracy | Foundational transformer architecture for our Phase 5 ML model — we adapt this to Python/Flask code |
| 10 | **GRACE: Empowering LLM-based Vulnerability Detection with Graph Structure and In-Context Learning** | Lu, Ju, Chen, Pei, Cai | 2024 | Journal of Systems and Software, Vol. 212 | Multiple graph-based vulnerability datasets | Outperformed 6 SOTA baselines by at least 28.65% F1 by combining graph structural features with LLM in-context learning | Advanced technique for Phase 5 — shows graph-based code representation improves over token-level features alone |
| 11 | **Toward Improved Deep Learning-based Vulnerability Detection** | Sejfia, Das, Shafiq, Medvidović | 2024 | ICSE 2024 | ReVeal, DeepWukong, LineVul datasets | Revealed that all current deep learning detectors fail on multi-base-unit (MBU) vulnerabilities — a major blind spot | Shows our analyzer (Phase 2) must handle cross-function vulnerabilities, not just single-function patterns |
| 12 | **RedCoder: Automated Multi-Turn Red Teaming for Code LLMs** | Mo, et al. (Amazon Science) | 2025 | arXiv: 2507.22063 | Multi-turn adversarial conversations with Code LLMs | 61.18% vuln induction on CodeGemma-7B and 65.29% on Qwen2.5-Coder-7B via multi-agent red teaming | Direct architecture reference for Phase 6 — their multi-turn approach extends our single-turn prompt injection module |
| 13 | **BlueCodeAgent: A Blue Teaming Agent Enabled by Automated Red Teaming for CodeGen AI** | U. Chicago, UCSB, UIUC, Microsoft Research | 2024 | arXiv: 2510.18131 | Three risk categories; textual + code-level vuln datasets | Unified red+blue teaming; red team findings distilled into "constitutions" guiding detection; +12.7% avg F1 | Directly mirrors our Phase 7 feedback loop — their constitution-building is the conceptual equivalent of our retraining trigger |
| 14 | **Data and Context Matter: Towards Generalizing AI-based Software Vulnerability Detection** | Safdar, Mateen, Ali, Ashfaq, Hussain | 2025 | arXiv: 2508.16625 | **VulGate** — 236,663 samples unified from 10 datasets; expert-verified VulGate+ test set | Unified 10 major datasets; expanded CWE coverage from 91 → 180 types; demonstrated cross-project generalization gap | Shows dataset diversity is critical — validates our multi-source scraping strategy (Phase 1) over using a single dataset |
| 15 | **Security and Quality in LLM-Generated Code: A Multi-Language, Multi-Model Analysis** | Kharma, Choi, AlKhanafseh, Mohaisen | 2025 | arXiv: 2502.01853 | 200 programming tasks across Python, Java, C++, C; 5 LLM families | Python/Java safer than C/C++; widespread deprecated security methods; hardcoded secrets and crypto misuse common | Directly validates our Flask/Python scope — Python-specific vuln patterns confirmed, hardcoded secrets relevant to our labeler |

---

## Thematic Grouping

### Group A — LLM Code Security (Core Justification for This Project)
> Papers 1, 2, 6, 12, 15

These papers establish that LLMs generate insecure code at a measurable rate and that automated evaluation and red teaming are necessary. Together they justify every phase of this project.

### Group B — Vulnerability Datasets (Phase 1 & 4 Reference)
> Papers 3, 5, 14

DiverseVul, CVEfixes, and VulGate are the three most relevant real-world datasets. CVEfixes is directly integrated into our scraper. DiverseVul and VulGate inform how we should structure and clean our own dataset.

### Group C — ML / DL Vulnerability Detection Models (Phase 5 Reference)
> Papers 4, 7, 9, 10, 11

These papers benchmark ML approaches for vulnerability detection. Paper 4 (PrimeVul) is a critical warning: easy benchmarks overestimate real performance. Papers 9 and 10 give us the best model architectures to implement.

### Group D — Red Teaming & Adversarial Testing (Phase 6 Reference)
> Papers 6, 8, 12, 13

CyberSecEval 2, HouYi (prompt injection), RedCoder (multi-turn), and BlueCodeAgent are the four most directly applicable papers to our autonomous red team engine and feedback loop.

---

## Research Gap — Where This Project Contributes

| Limitation in Existing Work | How This Project Addresses It |
|-----------------------------|-----------------------------|
| Most datasets are C/C++ (Devign, BigVul, LineVul) | We build a **Python/Flask-specific** dataset |
| Benchmarks overestimate performance (Paper 4) | We validate with **live exploit testing** (red team), not just held-out test sets |
| LLM security benchmarks test prompts, not full apps | We evaluate **complete Flask applications**, not isolated code snippets |
| Red teaming and detection are separate tools | We close the loop — red team failures **trigger model retraining** (Phase 7) |
| No dataset maps vuln → exploit → patch for Flask | Our dataset captures **exploitability metadata** from the red team engine |

---

## Citation Format (BibTeX-style references)

```
[1]  Fu et al. (2023). Security Weaknesses of Copilot-Generated Code. ACM TOSEM. arXiv:2310.02059
[2]  Majdinasab et al. (2023). Assessing GitHub Copilot Security. arXiv:2311.11177
[3]  Chen et al. (2023). DiverseVul. RAID 2023.
[4]  Ding et al. (2024). Vulnerability Detection with Code LMs: How Far Are We? arXiv:2403.18624
[5]  Bhandari et al. (2021/2024). CVEfixes. PROMISE '21.
[6]  Bhatt et al. (2024). CyberSecEval 2. arXiv:2404.13161
[7]  Hu et al. (2023). Interpreters for GNN-Based Vulnerability Detection. ISSTA 2023.
[8]  Liu et al. (2023). Prompt Injection Attack Against LLM-Integrated Applications. arXiv:2306.05499
[9]  Fu & Tantithamthavorn (2022). LineVul. MSR 2022.
[10] Lu et al. (2024). GRACE. Journal of Systems and Software, Vol. 212.
[11] Sejfia et al. (2024). Toward Improved DL-based Vulnerability Detection. ICSE 2024.
[12] Mo et al. (2025). RedCoder. arXiv:2507.22063
[13] BlueCodeAgent (2024). arXiv:2510.18131
[14] Safdar et al. (2025). Data and Context Matter. arXiv:2508.16625
[15] Kharma et al. (2025). Security and Quality in LLM-Generated Code. arXiv:2502.01853
```
