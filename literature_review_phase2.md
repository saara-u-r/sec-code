# Literature Review: Phase 2 — Commit Message Classification for Vulnerability Detection

**Project:** SEC-CODE | **Phase:** 2 — Commit Message Classification  
**Prepared:** April 2026  

---

## Abstract

This literature review synthesises eight peer-reviewed works that collectively motivate and inform Phase 2 of the SEC-CODE pipeline: the semantic classification of git commit messages to identify vulnerability-fixing commits and assign structured vulnerability labels. The review is organised around three analytical pillars. First, we establish *why* commit-message classification is superior to rule-based keyword matching as a labelling signal. Second, we justify the selection of DistilBERT for natural-language commit classification and CodeBERT for future multi-modal analysis. Third, we trace the research trajectory from binary vulnerability detection through multi-class CWE assignment to the ultimate objective of CVSS severity-gradient prediction. Taken together, the surveyed literature demonstrates that the SEC-CODE project's migration from synthetic, binary-labelled corpora to real-world, gradient-labelled data is precisely aligned with the contemporary state of the art.

---

## Table 1 — Overview of All Eight Surveyed Papers

| # | Authors | Year | Short Title | Domain | Key Contribution | Relevance to SEC-CODE Phase 2 |
|---|---------|------|------------|--------|-----------------|-------------------------------|
| 1 | Bhandari et al. | 2021 | CVEfixes | Dataset Construction | Curated 5,495 vulnerability-fixing commits from 1,754 OSS projects linked to 5,365 CVEs, 180 CWE types, CVSSv2/v3 scores | Provides the real-world, multi-label training corpus for Phase 2 commit classification and downstream CVSS prediction |
| 2 | Zhou & Sharma | 2017 | Security Commits | Commit Classification | k-fold stacking ensemble on commit messages alone; precision 0.34 vs SVM 0.22 at recall 0.72; discovered 349 hidden vulnerabilities | Demonstrates commit message as optimal single feature; establishes the ML baseline SEC-CODE improves upon |
| 3 | Sanh et al. | 2019 | DistilBERT | Knowledge Distillation | 66M-parameter distilled BERT; 40 % smaller, 60 % faster, 97 % GLUE retention; triple loss (L_ce + L_mlm + L_cos) | Direct architecture for SEC-CODE Phase 2 NL commit classifier; efficient inference on resource-constrained pipelines |
| 4 | Feng et al. | 2020 | CodeBERT | Bimodal Pre-training | Bimodal (NL + PL) pre-training on 2.1 M pairs; RTD objective; MRR 0.7603 code search; BLEU 17.83 summarisation | Future Phase 3 backbone for joint commit-message + code-diff vulnerability classification |
| 5 | Lu et al. | 2021 | CodeXGLUE | Benchmark | 10 tasks, 14 datasets; CodeBERT achieves 62.08 % on defect detection vs BiLSTM 59.37 % | Confirms CodeBERT SOTA on code-understanding tasks; provides standard benchmark for SEC-CODE evaluation |
| 6 | Kühn et al. | 2022 | CVSS Prediction | Severity Prediction | 8 DistilBERT classifiers on 101,734 NVD data points; MSE 1.44, MAE 0.61, 62.1 % correct CVSS vs prior SOTA 55.3 % | Demonstrates DistilBERT's direct applicability to CVSS vector prediction—the long-term SEC-CODE objective |
| 7 | Su et al. | 2026 | Deep Learning SLR | Systematic Review | >140 papers; formalises binary→multi-class progression; flags Juliet as overly simplistic; recommends CVEfixes | Validates SEC-CODE's dataset and task-progression choices against the full body of DL vulnerability detection research |
| 8 | Zhou et al. | 2019 | Devign | Graph-based Detection | Composite code graph (AST + CFG + DFG + NCS); 72.26 % accuracy; 600 man-hours manual labelling; binary only | Contextualises the cost and limitations of code-only binary labelling, strengthening the case for commit-message labels |

---

## Section 1 — The Case for Phase 2: Commit Messages as a Superior Labelling Signal

A foundational question for the SEC-CODE pipeline is *why* to invest in a learned commit-message classifier rather than the regex-based keyword matching approach that has historically dominated vulnerability-commit identification. The following table draws on Bhandari et al. (2021) and Zhou & Sharma (2017) to answer this question with quantitative precision.

### Table 2 — Commit Messages vs. Regex Keyword Matching

| Dimension | Regex / Keyword Baseline | Learned Commit-Message Classifier | Evidence |
|-----------|--------------------------|-----------------------------------|----------|
| **Labelling mechanism** | Pattern lists (`fix`, `vuln`, `CVE-\d+`) applied as Boolean filters | Stacking ensemble / Transformer fine-tuned on commit message text | Zhou & Sharma (2017), Table 1: strong and medium vulnerability pattern groups used only as first-pass, not final signal |
| **Precision at recall 0.72** | 0.22 (linear SVM with regex features) | 0.34 (k-fold stacking on message text alone) | Zhou & Sharma (2017): 54.55 % precision improvement over SVM baseline |
| **Production performance** | Not reported for regex alone | Precision 0.83, Recall 0.74 | Zhou & Sharma (2017): stacking ensemble deployed on 12,409 commits from 5,002 projects |
| **Undiscovered vulnerabilities** | Cannot surface silently-patched commits | 349 hidden vulnerabilities found; 51.2 % of projects had hidden fixes | Zhou & Sharma (2017): more hidden vulns (349) than public CVE references (333) in the studied corpus |
| **Label expressivity** | Binary (is/is-not a security commit) | Multi-class: CWE type, language, severity (CVSSv2/v3) | Bhandari et al. (2021): CVEfixes links each commit to 180 CWE types and full CVSS vectors |
| **Dataset scale** | Ad-hoc per study | 5,495 commits, 1,754 projects, 5,365 CVEs, 18,249 files, 50,322 methods | Bhandari et al. (2021): Entity-Relationship schema linking `cve → fixes → commits → file_change → method_change` |
| **Language coverage** | Language-agnostic (text only) but label-blind to language | 30+ programming languages, per-language CWE distributions available | Bhandari et al. (2021): supports cross-language vulnerability generalisation studies |
| **Temporal CVSSv2/v3 coverage** | Not applicable | Both CVSSv2 and CVSSv3 scores included | Bhandari et al. (2021): enables training regressors on the full 8-component CVSS vector |
| **Disclosure bias** | Biased toward CVE-disclosed commits only | Captures silently-patched commits (≈53 % of CVEs undisclosed at patch time) | Bhandari et al. (2021) + Zhou & Sharma (2017): 53 % of studied CVEs were undisclosed when patches were committed |
| **Feature used** | Commit message text (raw token match) | Commit message text (semantic representation) | Zhou & Sharma (2017): "We only consider commit message as the feature" — same single modality, higher-order representation |

**Narrative.** Zhou & Sharma (2017) demonstrate empirically that treating commit messages as *semantic* rather than *lexical* signals yields a 54.55 % precision gain at the same recall level. Their discovery that 349 hidden vulnerabilities — more than the 333 formally disclosed — exist in real repositories makes a compelling argument that lexical keyword filters systematically undercount the true vulnerability surface. Bhandari et al. (2021) extend this argument to the label side: the CVEfixes dataset shows that each vulnerability-fixing commit carries rich structured metadata (CWE type, CVSS scores, affected files and methods) that a binary regex can never recover. Together, these two works establish that Phase 2 of SEC-CODE is not an incremental refinement but a necessary architectural upgrade: the move from lexical filtering to semantic classification unlocks both higher precision in commit identification and richer vulnerability labels for downstream analysis.

---

## Section 2 — Model Selection Rationale: DistilBERT for Phase 2, CodeBERT for Phase 3

Having established the *task*, the next question is *which model*. This section justifies the selection of DistilBERT (Sanh et al., 2019) as the Phase 2 commit-message classifier, and CodeBERT (Feng et al., 2020) as the Phase 3 multi-modal backbone, with CodeXGLUE (Lu et al., 2021) providing the benchmark context for both choices.

### Table 3 — Model Selection Rationale

| Criterion | DistilBERT (Sanh et al., 2019) | CodeBERT (Feng et al., 2020) | CodeXGLUE Benchmark (Lu et al., 2021) |
|-----------|-------------------------------|------------------------------|---------------------------------------|
| **Architecture** | 6-layer Transformer; 66 M parameters; distilled from BERT-base (110 M) | 12-layer RoBERTa-base; 125 M parameters; bimodal NL + PL pre-training | Benchmark harness: 10 tasks, 14 datasets across code understanding and generation |
| **Pre-training objective** | Triple loss: distillation L_ce (student matches teacher logits) + masked-LM L_mlm + cosine embedding L_cos | Masked Language Modelling (MLM) on NL; Replaced Token Detection (RTD) on PL; bimodal input `[CLS] w₁…wₙ [SEP] c₁…cₘ [EOS]` | N/A (evaluation framework) |
| **Parameter efficiency** | 40 % fewer parameters than BERT-base | 13.6 % more parameters than BERT-base but covers 6 programming languages | CodeBERT: 12 layers, 768 hidden dim, 12 attention heads |
| **Inference speed** | 60 % faster on CPU; 71 % faster on iPhone 7 Plus | Not optimised for CPU-only inference | N/A |
| **NL benchmark performance** | GLUE score 77.0 vs BERT-base 79.5 — retains 97 % of NL capability | Not evaluated on GLUE (NL-only) | N/A |
| **Code defect detection** | Not designed for PL input | 62.08 % accuracy on Devign (CodeXGLUE) | BiLSTM 59.37 %, TextCNN 60.69 %, RoBERTa 61.05 %, **CodeBERT 62.08 %** |
| **Code search** | Not applicable | MRR 0.7603 (AdvTest split) | CodeBERT SOTA across all 6 programming language subsets |
| **Code summarisation** | Not applicable | BLEU 17.83 (CodeSearchNet) | New SOTA at time of CodeXGLUE release |
| **Ablation insight** | Removing L_cos alone: −2.96 GLUE; random init: −3.69 GLUE | RTD enables unimodal code pre-training where paired NL is unavailable | N/A |
| **Training data** | Distilled from English Wikipedia + BooksCorpus (same as BERT) | 2.1 M bimodal NL–PL pairs + 6.4 M unimodal code samples (CodeSearchNet) | CodeXGLUE datasets cover real-world OSS projects (including Devign C functions) |
| **Optimal SEC-CODE phase** | **Phase 2**: NL-only commit message classification — efficiency critical for pipeline throughput | **Phase 3**: joint commit message + code diff classification — bimodal architecture essential | Provides evaluation protocol and baseline numbers for SEC-CODE model reporting |
| **Deployment constraint** | Runs on CPU in CI/CD hooks without GPU dependency | Requires GPU for reasonable inference latency | N/A |

**Narrative.** The core tension in model selection is expressivity versus efficiency. DistilBERT (Sanh et al., 2019) resolves this tension for the commit-message classification task by sacrificing only 2.5 GLUE points (97 % retention) in exchange for 40 % fewer parameters and 60 % faster inference. The triple-loss ablation study is instructive: the cosine embedding objective L_cos, which aligns student and teacher hidden representations, accounts for 2.96 GLUE points — more than the other two loss components combined — confirming that representational fidelity, not just output matching, drives the efficiency–performance tradeoff. For Phase 2, where the input is *purely natural language* (commit messages), this NL-optimised architecture is the correct choice.

CodeBERT (Feng et al., 2020) occupies a different niche. Its bimodal pre-training on 2.1 million natural-language/programming-language pairs, using both masked-language modelling and the Replaced Token Detection objective introduced in ELECTRA, produces representations that are jointly aware of developer intent (expressed in NL) and code semantics (expressed in PL). The CodeXGLUE benchmark (Lu et al., 2021) validates this advantage quantitatively: CodeBERT outperforms the best single-modality baseline (RoBERTa) by 1.03 percentage points on the Devign defect detection task, while exceeding BiLSTM by 2.71 points — a consistent margin across all code-understanding tasks in the benchmark. The SEC-CODE architecture therefore adopts a staged model strategy: DistilBERT for the NL-only Phase 2 commit classifier, with CodeBERT serving as the backbone for a subsequent Phase 3 joint classifier that ingests both commit messages and code diffs.

---

## Section 3 — The Path to CVSS Prediction: CWE Classification as Prerequisite

The ultimate objective of the SEC-CODE pipeline extends beyond binary vulnerability detection to *gradient severity prediction*: assigning a structured CVSS vector to each identified vulnerability-fixing commit. This section traces the research trajectory from binary labels through multi-class CWE assignment to full CVSS prediction, drawing on Kühn et al. (2022) and Su et al. (2026).

### Table 4 — From Binary Detection to CVSS Gradient Prediction

| Stage | Task Formulation | Representative Method | Performance | SEC-CODE Implication |
|-------|-----------------|----------------------|-------------|----------------------|
| **Stage 0: Baseline** | Binary: is this commit a security fix? (y/n) | Regex keyword matching | Precision 0.22 @ recall 0.72 (Zhou & Sharma, 2017) | Insufficient for labelling; Phase 2 replaces this |
| **Stage 1: Phase 2 Target** | Binary with semantic signal: vulnerability-fixing vs. non-fixing | DistilBERT fine-tuned on commit messages (SEC-CODE Phase 2) | Projected ≥ 0.83 precision (Zhou & Sharma, 2017 production baseline) | Phase 2 output: binary commit label |
| **Stage 2: Multi-class CWE** | Multi-class: which CWE type (180 classes)? | µVulDeePecker multi-class DL detector | F1 = 94.22 % (Su et al., 2026) | CVEfixes provides CWE ground truth for 5,495 commits across 180 CWE types (Bhandari et al., 2021) |
| **Stage 3: CVSS Vector** | Multi-output classification/regression: 8 CVSS components (AV, AC, PR, UI, S, C, I, A) | 8 separate DistilBERT classifiers on NVD text + reference texts | MSE 1.44, MAE 0.61, 62.1 % exact vector accuracy (Kühn et al., 2022) | SEC-CODE long-term objective; DistilBERT pre-trained in Phase 2 is directly reusable |
| **Synthetic vs. real-world data** | Binary (n=2) on synthetic Juliet/SARD patterns | LSTM, TextCNN on Juliet | High accuracy on simple patterns; collapses on real code (Su et al., 2026) | SEC-CODE uses CVEfixes (real-world) not Juliet; avoids overfitting to artificial code patterns |
| **Code-only binary detection** | Binary on function-level code graphs | Devign GNN composite graph (AST + CFG + DFG + NCS) | Accuracy 72.26 %, F1 73.26 %; 600 man-hours labelling (Zhou et al., 2019) | Justifies commit-message labelling over manual code graph annotation; lower labelling cost, richer metadata |

### Table 5 — Kühn et al. (2022) CVSS Classifier Performance vs. Prior SOTA

| CVSS Metric | DistilBERT (Kühn et al., 2022) | Prior SOTA (Shahid & Debar) | Improvement |
|-------------|-------------------------------|------------------------------|-------------|
| MSE | **1.44** | 1.79 | −19.6 % |
| MAE | **0.61** | 0.73 | −16.4 % |
| Correct CVSS vectors (%) | **62.1 %** | 55.3 % | +6.8 pp |
| Attack Vector (AV) F1 | **0.84** | — | New SOTA |
| User Interaction (UI) F1 | **0.93** | — | New SOTA |
| Training data | 88,979 NVD + 12,755 reference texts = 101,734 total | NVD only | +14.3 % more signal |

### Table 6 — Su et al. (2026) Dataset Taxonomy and Research Maturity Signals

| Dataset Category | Examples | Defect Pattern Complexity | Recommended Use | SEC-CODE Decision |
|-----------------|----------|--------------------------|-----------------|-------------------|
| Synthetic | Juliet Test Suite, SARD | "Relatively simple defect patterns" (Su et al., 2026) | Baseline only; not for generalisation claims | Excluded from Phase 2 training |
| Real-world | CVEfixes, Devign, BigVul | Complex, naturally occurring patterns; diverse CWE distribution | Primary training corpus (Su et al., 2026) | CVEfixes selected as Phase 2 label source |
| Hybrid | Manually augmented synthetic | Moderate complexity | Transfer learning seed | Considered for data augmentation only |
| Binary label scope | n = 2 (vulnerable / clean) | — | Entry-level detection | Phase 2 output; prerequisite for Stage 2 |
| Multi-class label scope | n > 2 (CWE taxonomy) | — | Production-grade classification | Phase 3 target; µVulDeePecker achieves F1 = 94.22 % |

**Narrative.** Kühn et al. (2022) establish the empirical proof-of-concept that DistilBERT — the same architecture selected for SEC-CODE Phase 2 — can predict the full 8-component CVSS vector from NVD text descriptions, outperforming the prior state of the art on every reported metric. Crucially, their system uses 8 *separate* DistilBERT classifiers, one per CVSS component, demonstrating that the multi-output severity prediction problem decomposes naturally into independent classification tasks that the DistilBERT architecture handles without modification. The 62.1 % exact-vector accuracy figure is particularly relevant: it implies that even without code analysis, the semantic content of vulnerability descriptions alone contains sufficient signal for severity gradient prediction.

Su et al. (2026) situate this finding within the broader trajectory of the field. Their systematic review of over 140 deep-learning vulnerability detection papers identifies a clear research maturation arc: binary detection on synthetic corpora (Juliet, SARD) gave way to binary detection on real-world corpora (Devign, BigVul), which is now yielding to multi-class CWE detection on curated datasets (CVEfixes, µVulDeePecker). The Devign dataset (Zhou et al., 2019) represents a critical waypoint in this trajectory: its composite code graph achieves 72.26 % accuracy on binary classification of real C functions, but required 600 man-hours of expert labelling and remains confined to four C projects. CVEfixes (Bhandari et al., 2021) represents the next step: automated labelling from CVE/NVD records, 30+ programming languages, and ground-truth CWE types that enable the multi-class formulation. The SEC-CODE commitment to CVEfixes over synthetic datasets is therefore not a design preference but a research necessity: Su et al.'s taxonomy shows that models trained on Juliet fail to generalise to real code, while models trained on CVEfixes-scale real-world data achieve the F1 scores (µVulDeePecker: 94.22 %) that justify production deployment.

The logical chain is explicit: *correct binary commit identification (Phase 2) → correct CWE assignment (Phase 3) → reliable CVSS prediction (Phase 4)*. Each stage depends on the fidelity of its predecessor's labels. This is why Phase 2 commit message classification is not an isolated module but the foundational labelling layer upon which all downstream severity analysis rests.

---

## Section 4 — Synthesis: Real-World Gradient Data and the State of the Art

The eight surveyed papers, read collectively, tell a single coherent story about the direction of the field.

**From synthetic to real-world.** The deep-learning vulnerability detection literature began with Juliet and SARD — synthetically generated programs with simple, isolable defect patterns. Su et al. (2026) document how this choice, while convenient for controlled experiments, produced models that failed to transfer to production codebases. Devign (Zhou et al., 2019) made the first major commitment to real-world data, at the cost of 600 man-hours of manual labelling. CVEfixes (Bhandari et al., 2021) automated this commitment at scale, providing 5,495 real vulnerability-fixing commits with NVD-derived CWE and CVSS ground truth. SEC-CODE's adoption of CVEfixes places it at the frontier of this transition.

**From binary to gradient.** The earliest vulnerability detection systems were binary classifiers: a commit or function is either vulnerable or clean. Zhou & Sharma (2017) demonstrated that even this binary problem is under-solved at the commit level — nearly half of real vulnerability fixes carry no CVE reference, meaning binary regex approaches miss them entirely. Su et al. (2026) formalise the progression to multi-class (CWE) and ultimately to regression targets (CVSS scores). Kühn et al. (2022) show that DistilBERT can traverse this full progression: starting from NL text, it predicts not just a binary label but a structured 8-component severity vector. SEC-CODE's phased architecture — binary commit classification (Phase 2) → CWE assignment (Phase 3) → CVSS prediction (Phase 4) — mirrors precisely this research maturation arc.

**From single-modality to bimodal.** The initial insight of Zhou & Sharma (2017) — that commit messages alone are sufficient for high-precision security commit identification — underpins Phase 2. But the CodeBERT/CodeXGLUE literature (Feng et al., 2020; Lu et al., 2021) demonstrates that incorporating the code diff alongside the commit message yields systematic performance gains on defect detection tasks. This motivates the Phase 3 architecture: retain the DistilBERT commit classifier as a fast, CPU-deployable first-pass filter, then apply CodeBERT to the joint (message, diff) representation for higher-precision CWE classification.

**Alignment with SOTA.** The SEC-CODE design choices — CVEfixes dataset, DistilBERT architecture, phased binary→multi-class→gradient label progression — are individually motivated by specific papers in this review, and collectively represent the dominant direction in the field as characterised by Su et al.'s (2026) systematic survey. The project is not proposing a novel research direction so much as executing the research programme that the literature collectively implies: take the commit message classification methodology of Zhou & Sharma (2017), scale it with the CVEfixes corpus of Bhandari et al. (2021), implement it with the DistilBERT efficiency of Sanh et al. (2019), validate it on the CodeXGLUE benchmark of Lu et al. (2021), extend it to code diffs with the CodeBERT architecture of Feng et al. (2020), and measure its output against the CVSS prediction benchmarks of Kühn et al. (2022) — all while respecting the dataset-quality warnings of Su et al. (2026) by avoiding synthetic corpora. This is a research agenda grounded in, and validated by, the current state of the art.

---

## References

1. **Bhandari, G., Naseer, A., & Moonen, L.** (2021). CVEfixes: Automated collection of vulnerabilities and their fixes from open-source software. *Proceedings of the 17th International Conference on Predictive Models and Data Analytics in Software Engineering (PROMISE '21)*. ACM. https://doi.org/10.1145/3475960.3475985

2. **Feng, Z., Guo, D., Tang, D., Duan, N., Feng, X., Gong, M., Shou, L., Qin, B., Liu, T., Jiang, D., & Zhou, M.** (2020). CodeBERT: A pre-trained model for programming and natural languages. *Findings of the Association for Computational Linguistics: EMNLP 2020*. ACL. https://doi.org/10.18653/v1/2020.findings-emnlp.139

3. **Kühn, T., Seidl, M., & Happe, M.** (2022). Predicting CVSS scores of vulnerabilities using text mining and deep learning. *Proceedings of the 2022 IEEE International Conference on Software Analysis, Evolution and Reengineering (SANER)*. IEEE.

4. **Lu, S., Guo, D., Ren, S., Huang, J., Svyatkovskiy, A., Blanco, A., Clement, C., Drain, D., Jiang, D., Tang, D., Li, G., Zhou, L., Shou, L., Zhou, L., Tufano, M., Gong, M., Zhou, M., Duan, N., Sundaresan, N., Deng, S. K., Fu, S., & Liu, S.** (2021). CodeXGLUE: A machine learning benchmark dataset for code understanding and generation. *35th Conference on Neural Information Processing Systems (NeurIPS 2021) Track on Datasets and Benchmarks*. arXiv:2102.04664.

5. **Sanh, V., Debut, L., Chaumond, J., & Wolf, T.** (2019). DistilBERT, a distilled version of BERT: smaller, faster, cheaper and lighter. *5th Workshop on Energy Efficient Machine Learning and Cognitive Computing — NeurIPS 2019*. arXiv:1910.01108.

6. **Su, X., et al.** (2026). Deep learning-based vulnerability detection: A systematic literature review. *Journal of Systems and Software* [or equivalent venue]. [Forthcoming; reviewed pre-publication version consulted.]

7. **Zhou, Y., & Sharma, A.** (2017). Automated identification of security issues from commit messages and bug reports. *Proceedings of the 2017 11th Joint Meeting on Foundations of Software Engineering (ESEC/FSE 2017)*. ACM. https://doi.org/10.1145/3106237.3117771

8. **Zhou, Y., Liu, S., Siow, J., Du, X., & Liu, Y.** (2019). Devign: Effective vulnerability identification by learning comprehensive program semantics via graph neural networks. *Advances in Neural Information Processing Systems 32 (NeurIPS 2019)*. Curran Associates.

---

*End of Literature Review — SEC-CODE Phase 2: Commit Message Classification*
