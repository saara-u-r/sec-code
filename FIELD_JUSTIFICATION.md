# Schema Field Justification — Literature Survey

This document provides a detailed, field-by-field justification for every metadata field
in the vulnerability dataset schema (`build_meta()` in `src/utils/file_utils.py`).
Each field is grounded in peer-reviewed vulnerability dataset and vulnerability detection
research. The aim is to demonstrate that every field either (a) directly mirrors a field
used in a published dataset, (b) follows a standard established in the literature, or
(c) is an original contribution motivated by the security-focus of this pipeline.

The schema has **26 fields** organized into 9 groups, schema version **3.0**. The
7 sink-shaped Top-25 Python CWE classes targeted (CWE-89, CWE-79, CWE-22, CWE-78,
CWE-94, CWE-918, CWE-502) are justified separately at the end.

**Schema 3.0 (this version)** trimmed 27 fields from the 53-field 2.x schema. The
trim removed redundant fields (the 8 per-CVSS-metric breakdowns are decomposable
from `cvss_vector`; `cwe_name` and `vuln_type` are derivable from `cwe`),
filter-time-only signals that have no downstream readers (`syntax_valid`,
`has_taint_source`, `is_web_code`, `has_cwe_sink`, `loc_before`, `loc_after`),
and fields tied to removed pipeline phases (`classifier_cwe`,
`classifier_confidence` from the dropped Phase-2 commit classifier). The 26
retained fields are partitioned into three usage tiers below; the removed fields
are documented in the "Removed in schema 3.0" appendix with their literature
justifications preserved for traceability.

---

## Field Tiers — What Each Consumer Actually Uses

Not every consumer of this dataset needs every field. The 26 fields cluster into
three tiers by *role*. A reviewer asking "do you really need 26 fields?" should
see this table first: only 3 are required to run an evaluation; the rest exist
to support training and to make the benchmark reproducible.

### Tier 1 — Core evaluation (3 fields)

What a detector is scored against. A third-party SAST or LLM run only needs
these.

| Field | Used by |
|---|---|
| `code_before` | Detector input. |
| `cwe` | Ground-truth label. |
| `split` | Identifies the held-out test set used in `reports/eval/`. |

### Tier 2 — Training and augmentation (11 fields)

Additional fields read by the Phase-3 dual-task model and the Phase-2.5
augmentation pipeline.

| Field | Used by |
|---|---|
| `code_after` | Phase-2.5 sanitization rules (transform `code_before` → safe variant). |
| `cvss_score` | Phase-3 dual-task model — regression head target. |
| `cvss_severity` | Per-severity slicing in the eval harness. |
| `label_confidence` | Training-time sample weighting (low-confidence labels down-weighted). |
| `label_source` | Per-source quality filtering during training. |
| `pair_id` | Joins `code_before`/`code_after` records for contrastive examples. |
| `framework` | Per-framework slicing in result tables. |
| `is_hard_negative` | Distinguishes augmented hard negatives from natural samples. |
| `parent_sample_id` | Links a hard negative to the vulnerable sample it was derived from. |
| `sanitization_transform` | Records which Phase-2.5 rule generated the hard negative. |
| `repo` | Anti-leakage grouping in the stratified splitter (`src/labeler/stratified_splitter.py`). |

### Tier 3 — Benchmark artifact (12 fields)

Provenance, dedup, and pipeline-state fields that let a third party re-derive
or extend the dataset. Not read at evaluation or training time, but essential
if the benchmark is to outlive any single training run — the same role these
fields play in CVEfixes, BigVul, and DiverseVul.

| Field | Used by |
|---|---|
| `_schema_version` | Forward-compatibility for future schema changes. |
| `id` | Primary key. |
| `source` | Which scraper produced the record. |
| `cve_id` | Canonical external identifier. |
| `ghsa_id` | Scraper-level dedup (`ghsa_db_scraper`) + alternate join key. |
| `cvss_version` | CVSS 3.0 vs 3.1 disambiguation. |
| `cvss_vector` | Full vector string encoding all 8 base metrics. |
| `file_path` | Where in the source repo the sample lives. |
| `fix_commit` | Reproducibility: re-pull the original fix from upstream. |
| `sink_pattern` | Which sub-pattern within a CWE matched (audit + per-pattern slicing). |
| `content_hash` | MongoDB dedup key. |
| `nvd_enriched` | Phase-3 idempotency flag (skip already-enriched records). |

---

## Reference Papers

All papers below were independently verified with DOIs/URLs.

| Short ID | Full citation |
|---|---|
| **CVEfixes** | Bhandari G., Naseer A., Moonen L. "CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software." *PROMISE '21*, ACM, 2021. DOI: 10.1145/3475960.3475985. arXiv: 2107.08760. Dataset DOI: 10.5281/zenodo.4476563. |
| **BigVul** | Fan J., Li Y., Wang S., Nguyen T.N. "A C/C++ Code Vulnerability Dataset with Code Changes and CVE Summaries." *MSR '20*, ACM, 2020. DOI: 10.1145/3379597.3387501. |
| **CrossVul** | Nikitopoulos G., Dritsa K., Louridas P., Mitropoulos D. "CrossVul: A Cross-Language Vulnerability Dataset with Commit Data." *ESEC/FSE '21*, ACM, 2021. DOI: 10.1145/3468264.3473122. Dataset DOI: 10.5281/zenodo.4734050. |
| **LineVul** | Fu M., Tantithamthavorn C. "LineVul: A Transformer-based Line-Level Vulnerability Prediction." *MSR '22*, IEEE, 2022. IEEE Xplore: 9796256. |
| **D2A** | Zheng Y., Pujar S., Burdet B., Buratti L., Epstein E., Yang B., Lewis B., Zhang C., Farchi E. "D2A: A Dataset Built for AI-Based Vulnerability Detection Methods Using Differential Analysis." *ICSE-SEIP '21*, 2021. DOI: 10.1109/ICSE-SEIP52600.2021.00020. arXiv: 2102.07995. |
| **ReVeal** | Chakraborty S., Krishna R., Ding Y., Ray B. "Deep Learning based Vulnerability Detection: Are We There Yet?" *IEEE Transactions on Software Engineering*, vol. 48, no. 9, pp. 3280–3296, 2022. arXiv: 2009.07235. |
| **Devign** | Zhou Y., Liu S., Siow J., Du X., Liu Y. "Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks." *NeurIPS 2019*. arXiv: 1909.03496. |
| **Spanos18** | Spanos G., Angelis L. "A Multi-Target Approach to Estimate Software Vulnerability Characteristics and Severity Scores." *Journal of Systems and Software*, vol. 146, pp. 152–166, 2018. DOI: 10.1016/j.jss.2018.09.044. |
| **CVSS-BERT** | Shahid M.R., Debar H. "CVSS-BERT: Explainable Natural Language Processing to Determine the Severity of a Computer Security Vulnerability from its Description." *ISSREW 2021*. arXiv: 2111.08510. |
| **VCCFinder** | Perl H., Dechand S., Smith M., Heid D., Acar Y., Fahl S., Smith P. "VCCFinder: Finding Potential Vulnerabilities in Open-Source Projects to Assist Code Audits." *CCS '15*, ACM, 2015. DOI: 10.1145/2810103.2813604. |
| **SZZ** | Śliwerski J., Zimmermann T., Zeller A. "When Do Changes Induce Fixes?" *MSR 2005*, ACM SIGSOFT Software Engineering Notes, vol. 30, no. 4, pp. 1–5, 2005. PDF: https://thomas-zimmermann.com/publications/files/sliwerski-wsr-2005.pdf |
| **OSV-schema** | Chang O. et al. (Google). "OSV Schema Specification v1.x." https://ossf.github.io/osv-schema/. 2021–present. |
| **Bozorgi10** | Bozorgi M., Saul L.K., Savage S., Voelker G.M. "Beyond Heuristics: Learning to Classify Vulnerabilities and Predict Exploits." *KDD '10*, ACM, 2010. DOI: 10.1145/1835804.1835821. |
| **NVD-CVSS** | NIST. "Common Vulnerability Scoring System v3.1: Specification Document." 2019. https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator. |
| **OWASP21** | OWASP Foundation. "OWASP Top 10: 2021." https://owasp.org/Top10/, 2021. |
| **DiverseVul** | Chen Y., Ding Y., Alowain L., Chen X., Wagner D. "DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection." *RAID 2023*. |

---

## Group 1 — Identity (3 fields)

**Fields:** `_schema_version`, `id`, `source`

### Purpose

These four fields form the administrative backbone of every record. They identify what a
document is, where it came from, and when it was collected. Without them, a dataset
cannot support reproducibility, incremental updates, or multi-source merging.

### `_schema_version`

Schema versioning is standard practice in any dataset that evolves across multiple
releases. The NVD itself versions its JSON data feeds (NVD Data Feed v1.0 → v1.1 →
v2.0), and every consumer of NVD data must check the version tag before parsing fields.
CVEfixes (Bhandari et al., 2021) explicitly describes its schema as versioned and
provides a changelog between dataset releases. Without a version tag, a consumer cannot
determine whether an old record was written under the current field layout or an earlier
one — silently incorrect parsing of old records becomes a risk as the pipeline evolves
across phases.

### `id`

Every major vulnerability dataset assigns a unique primary key per record. BigVul uses
`CVE_ID` as the primary key but appends a row index for multi-function records from the
same CVE. CVEfixes uses a composite key of `(repo_url, commit_hash, file_change_id)`.
Our `id` is constructed as `{source}_{vuln_type}_{content_hash}` — this ensures global
uniqueness, allows upsert-based deduplication in MongoDB (no duplicate inserts on
re-runs), and encodes meaningful provenance directly in the key so a human reading the
ID immediately knows what type of record it is.

### `source`

Recording which scraper produced each record is essential for data-quality auditing.
CVEfixes explicitly tracks the database of origin and notes that label quality varies
by source. Our four sources — CVEfixes, OSV, GHSA, and PyPA — differ in:
- Label quality: NVD-backed CWEs (CVEfixes, GHSA) are more reliable than inferred PyPA labels.
- CVSS availability: GHSA records include CVSS at scrape time; others need Phase 3.
- Code coverage: CVEfixes has more before/after pairs; PyPA often lacks `code_after`.

Without `source`, you cannot compute per-source quality metrics, filter for
high-quality-source records, or debug scraper-specific anomalies. CrossVul (Nikitopoulos
et al., 2021) organises its entire directory structure by source database and programming
language for the same reason.

---

## Group 2 — Advisory IDs (2 fields)

**Fields:** `cve_id`, `ghsa_id`

### Purpose

A single real-world vulnerability can simultaneously appear in CVE (MITRE/NVD), GitHub
Security Advisories (GHSA), OSV.dev, and the Python Packaging Authority (PyPA) advisory
database. Storing all four IDs enables cross-database enrichment, prevents different
scrapers from treating the same vulnerability as different records, and gives consumers
multiple ways to cross-reference a sample.

### `cve_id`

CVE IDs are the universal identifier for vulnerabilities across the entire security
research community. Their use is universal in the dataset literature:

- CVEfixes (2021) stores `cve_id` as the primary identifier and uses it to query NVD
  for CVSS data. Without `cve_id`, Phase 3 (NVD enrichment) cannot call the NVD REST
  API.
- BigVul (2020) uses `CVE_ID` as its primary key across 3,754 projects.
- CrossVul (2021) organises its 5,131 unique CVEs by CVE ID.
- Devign (2019) links its dataset to fix commits identified by CVE ID.
- VCCFinder (Perl et al., CCS 2015) was the first large-scale effort to map CVEs to
  GitHub commits — establishing CVE ID as the fundamental link between an advisory and
  source code.
- DiverseVul (2023) uses CVE IDs to merge and deduplicate records from five upstream
  datasets (BigVul, Devign, ReVeal, CrossVul, CVEfixes).

### `ghsa_id`

GitHub Security Advisories (GHSA) are the authoritative source for vulnerabilities in
open-source packages hosted on GitHub. GHSA advisories include CVSS v3 scores directly
and are typically published faster than NVD. The OSV schema (Chang et al., Google, 2021)
defines `aliases` as a first-class field specifically to store GHSA IDs alongside OSV IDs,
reflecting that the same advisory appears in multiple databases. CrossVul includes GHSA
links in its commit metadata. Storing `ghsa_id` allows Phase 3 to skip NVD enrichment
for records that already have CVSS data from GHSA, and it enables cross-referencing
between our scrapers (e.g., an OSV record and a GHSA record for the same vulnerability
can be merged).

Both ID fields coexist on every record, with `null` for whichever scrapers did
not produce the record — this is the same pattern used by the OSV schema's
`aliases` array and is consistent with CrossVul's multi-ID design. The original
schema also carried `osv_id` and `pysec_id`; those were trimmed in schema 3.0
because no downstream consumer reads them and the OSV/PySEC IDs can be
re-derived from `cve_id` + `source` via the OSV REST API. See the "Removed
in schema 3.0" appendix.

---

## Group 3 — Vulnerability Label (3 fields)

**Fields:** `cwe`, `label_source`, `label_confidence`

### Purpose

These are the ground-truth labels used for supervised learning in Phase 5. The group
records not only the label itself but its human-readable name, an internal slug for
programmatic use, where the label came from, and how much to trust it. The last two
fields — `label_source` and `label_confidence` — reflect hard lessons learned from
label quality issues that have been documented in the vulnerability dataset literature.

### `cwe`

CWE (Common Weakness Enumeration) is the standard taxonomy for vulnerability
classification, maintained by MITRE. Its use in vulnerability dataset papers is
universal:

- CVEfixes maps every record to a CWE type — 272 unique CWE types across its 11,873 CVEs.
- BigVul includes `CWE_ID` across 91 unique CWE categories covering 3,754 projects.
- CrossVul organises its entire directory structure by CWE ID, with 168 unique CWE
  types across 5,131 CVEs.
- DiverseVul (RAID 2023) covers 150 CWEs across 18,945 vulnerable functions.
- The NVD (NIST) assigns CWE IDs to CVEs as the official US government vulnerability
  classification system.
- MITRE's CWE Top 25 Most Dangerous Software Weaknesses (2022) uses CWE IDs as the
  primary metric for vulnerability prevalence.

CWE is the single most consistently used label in the vulnerability ML literature.
It is not a design choice; it is the standard.

### `label_source`

`label_source` records which authority assigned the CWE label: NVD, GHSA, OSV, PyPA,
or `advisory` (generic). This field has a verified direct precedent in the D2A dataset
(Zheng et al., ICSE-SEIP 2021), which includes an explicit `label_source` column with
values `"auto_labeler"` and `"after_fix_extractor"`. D2A's authors explicitly discuss
the need to record label provenance because automated labeling methods produce labels
of different reliability from manual labeling.

In our schema, NVD and GHSA labels are highest quality (assigned by domain experts
using standardised processes); OSV labels are medium quality (often mirror GHSA);
PyPA labels are lower quality because the PyPA advisory format does not always include
CWE fields, sometimes requiring inference. Without `label_source`, you cannot filter
for high-quality labels or stratify samples by label reliability in training.

### `label_confidence`

`label_confidence` is a three-tier categorical field (`high`, `medium`, `low`) encoding
how much to trust the CWE label for a given record. The motivation comes from documented
label quality problems in the vulnerability dataset literature:

- D2A (Zheng et al., 2021) discusses that different labeling methods produce labels of
  different reliability and notes that "auto_labeler" labels should be treated with
  lower confidence than "after_fix_extractor" labels.
- Devign (Zhou et al., NeurIPS 2019) uses a two-round manual labeling process with
  senior researcher adjudication specifically to produce high-confidence labels, and
  explicitly discusses inter-annotator agreement as a quality metric.
- A replication study of BigVul (Croft et al., 2023) found that only ~70.97% of
  BigVul's CWE labels match NVD annotations — meaning roughly 30% of widely-used
  training labels in BigVul are incorrect. LineVul's high benchmark scores are partially
  attributable to this label noise making the task artificially easy.

`label_confidence` is our mitigation for this documented problem: low-confidence labels
are down-weighted in Phase 5 training rather than discarded (which would reduce dataset
size) or treated equally (which would degrade model quality). This directly implements
the recommendation implied by D2A's label-source tracking.

---

## Group 4 — CVSS Severity (4 fields)

**Fields:** `cvss_score`, `cvss_severity`, `cvss_version`, `cvss_vector`

### Purpose

CVSS v3 encodes vulnerability severity across 8 independent dimensions, which combine
mathematically into a 0–10 score. Schema 2.x stored each dimension as its own column
(13 fields total) following **Spanos & Angelis (2018)** and **CVSS-BERT (Shahid &
Debar, ISSREW 2021)**, which train per-dimension classifiers and argue that
sub-metrics are independently predictive.

Schema 3.0 collapses the 8 per-metric fields into the single `cvss_vector` string,
which encodes all of them in NVD's canonical form (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).
This is the same trade-off the NVD JSON 2.0 feed makes: it ships the vector string and
expects consumers to parse it for per-metric values rather than duplicating the data
across 8 columns. The Spanos/CVSS-BERT methods remain implementable from the vector
string with one parsing pass — the predictive content is preserved, only the
denormalisation is removed. See the "Removed in schema 3.0" appendix for the
literature justifications retained for the 8 dropped per-metric columns plus
`cvss_source`.

### `cvss_score`

The numerical score (0–10) is included in virtually every vulnerability ML paper that
incorporates severity. CVEfixes, BigVul, CrossVul, and D2A all store CVSS scores.
In this pipeline it is used to weight training samples in Phase 5 (high-CVSS
vulnerabilities receive higher weight) and to prioritise red team targets in Phase 6.

### `cvss_severity`

The severity band (LOW / MEDIUM / HIGH / CRITICAL) is the coarse four-category
discretisation of `cvss_score` defined in the NVD CVSS v3.1 specification. It is stored
as a separate field rather than computed on the fly because it is used directly as a
MongoDB filter key and as a reporting label. Computing it from `cvss_score` on every
query would add unnecessary complexity. BigVul and CVEfixes documentation both report
vulnerability distributions by severity band, confirming it is a standard reporting
field.

### `cvss_version`

CVSS scoring changed between versions 3.0 and 3.1, with changes to the Attack
Complexity metric that can shift scores by up to 0.5 points for the same vulnerability.
Without knowing which version produced a score, cross-record comparisons are unreliable.
The NVD JSON 2.0 feed stores `cvssMetricV30` and `cvssMetricV31` as separate objects
for this reason. Our `cvss_version` field follows the same pattern. Spanos & Angelis
(2018) explicitly note the version differences when discussing their CVSS prediction
methodology.

### `cvss_vector`

The CVSS vector string (e.g., `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
encodes all 8 base metrics in a single parseable string. It is stored for auditability:
given the vector string, any downstream tool can re-derive any individual component
without querying the database again, and any discrepancy between `cvss_score` and the
vector can be detected. The NVD JSON feed includes the full vector string alongside
individual sub-metric fields, and this practice is mirrored here.

---

## Group 5 — Provenance (3 fields)

**Fields:** `repo`, `file_path`, `fix_commit`

### Purpose

Provenance fields allow every sample to be traced back to the exact git commit and file
it came from. Full provenance is what separates a research-grade dataset from a scraped
corpus: without it, labels cannot be independently verified, the dataset cannot be
reproduced, and temporal analysis is impossible.

### `repo`

The GitHub repository URL is the starting point for all provenance. CVEfixes stores
`repo_url` as a first-class field and uses it to clone repositories for file extraction.
VCCFinder (Perl et al., CCS 2015) stores repository URLs as the foundation for its
CVE-to-commit mapping — the paper argues that repository URLs are the essential link
between an advisory and the code. CrossVul includes repository URLs in its supporting
data tables. Without `repo`, none of the other provenance fields can be independently
verified.

### `file_path`

The file path within the repository is required to reconstruct the raw GitHub URL for
the vulnerable file: `raw.githubusercontent.com/{repo}/{commit}/{file_path}`.
CVEfixes stores `file_name` (the path within the repository) and uses it to fetch file
content for each commit. D2A stores file paths as part of each analysis trace step,
enabling reconstruction of the exact code state at analysis time. Without `file_path`,
the code payload (`code_before`, `code_after`) cannot be independently verified against
the original repository.

### `fix_commit`

The SHA of the commit that fixed the vulnerability is the central piece of provenance
in every vulnerability dataset that uses real-world code:

- CVEfixes stores `commit_hash` (the fix commit) as its primary data collection unit —
  the entire pipeline is built around identifying fix commits from CVE descriptions.
- BigVul maps each vulnerability to the commit hash of its fix and uses it to extract
  the patched function body.
- CrossVul identifies fix commits by GitHub URL and uses them to extract paired code
  files.
- D2A's entire methodology (Differential Analysis) is built around comparing snapshots
  before and after fix commits.
- Devign organises its dataset around `sha_id` (fix commit SHA) as the primary key.
- VCCFinder (2015) was the earliest large-scale work to map CVEs to GitHub fix commits,
  establishing this as the foundational concept for code-level vulnerability datasets.

`vulnerable_commit`, `commit_message`, `commit_date`, and `commit_author` were
present in schema 2.x but trimmed in schema 3.0. The vulnerable commit is recoverable
as the parent of `fix_commit` via one git API call (SZZ-style, Śliwerski et al., MSR
2005); `commit_message` and `commit_date` are recoverable from `fix_commit` against
the upstream repo; and `commit_author` was always set to `null` for PII reasons.
Literature justifications for the dropped fields are preserved in the "Removed in
schema 3.0" appendix.

---

## Group 6 — Code Payload (2 fields)

**Fields:** `code_before`, `code_after`

### Purpose

These two fields are the core of the dataset — the actual vulnerable and patched source
code. They enable supervised learning at the code level, with contrastive before/after
pairs providing a much stronger training signal than comparing unrelated vulnerable and
safe code samples.

### `code_before`

`code_before` is the vulnerable version of the source file at `vulnerable_commit`. It
is the positive (vulnerable) training example for Phase 5 and the red team target for
Phase 6. The use of pre-patch code as the vulnerable training sample is established
across multiple datasets:

- **CVEfixes** stores `code_before` at both file level and function level, using the
  **exact same field name**. This is the most direct schema-level precedent.
- **BigVul** stores `func_before` — the function body before the security patch.
- **CrossVul** uses the naming convention `bad_{commitID}_{fileID}` for the vulnerable
  version, conceptually identical to `code_before`.
- **Devign** (NeurIPS 2019) extracts function bodies from the parent of fix commits,
  equivalent to file-level `code_before`.
- **ReVeal** (Chakraborty et al., TSE 2022) labels C functions from before a security
  patch as vulnerable — implementing the `code_before` concept.
- **DiverseVul** (RAID 2023) unifies `code_before` entries from BigVul, Devign, ReVeal,
  CrossVul, and CVEfixes into a single deduplicated corpus.

Using real production code with confirmed CVEs as training examples — rather than
synthetic or contrived examples — is the key quality claim of all these datasets. Our
`code_before` carries the same claim.

**Why file-level instead of function-level?**
LineVul and BigVul work at function level for C/C++ code because function extraction
from compiled languages is well-defined. For Flask web applications, vulnerability
patterns often span multiple functions in the same file (e.g., a taint source in a
Flask route function and a dangerous sink in a helper function in the same module).
File-level extraction captures these cross-function patterns. CVEfixes stores both file-
and function-level code for this reason.

### `code_after`

`code_after` is the patched version of the file at `fix_commit`. It is the negative
(safe) training example for Phase 5.

The paired before/after approach is the central contribution of **LineVul** (Fu &
Tantithamthavorn, MSR 2022). LineVul's key empirical finding: using paired
`func_before`/`func_after` examples from the same repository — differing only by the
security patch — produces 160–379% higher F1 than prior methods that compare
unrelated vulnerable and safe functions. The before/after pair gives the model a clean
natural experiment: every other factor is held constant, and only the vulnerable lines
differ. This is the strongest possible training signal for a binary vulnerable/safe
classifier.

- **CVEfixes** stores `code_after` at file and function level (exact field name match).
- **BigVul** stores `func_after` for the patched function.
- **CrossVul** uses `good_{commitID}_{fileID}` naming for the patched version.
- **D2A** (ICSE-SEIP 2021) uses differential analysis of before/after snapshots as its
  core methodology.
- **ReVeal** labels the post-patch function as non-vulnerable (negative example).

`code_after` is empty for CVEfixes-sourced samples because CVEfixes does not always
store the patched version — a known limitation documented in the pipeline. Records with
both `code_before` and `code_after` are the highest-value samples and are weighted
accordingly in Phase 5, consistent with LineVul's finding that paired examples provide
superior training signal.

---

## Group 7 — Code Quality Signals (2 fields)

**Fields:** `framework`, `sink_pattern`

### Purpose

Schema 2.x stored 8 auto-computed signals (`language`, `loc_before`, `loc_after`,
`syntax_valid`, `has_taint_source`, `is_web_code`, `has_cwe_sink`, plus
`framework`/`sink_pattern`) used at scrape time to filter and stratify samples.
Schema 3.0 retains only the two signals that have downstream readers — `framework`
(per-framework slicing in result tables) and `sink_pattern` (audit + per-pattern
slicing). The other 6 are filter-time-only: they gate which samples enter
`data/raw/` but are never read again, so for the published artifact they are
recomputable from `code_before` if needed. Their literature justifications are
preserved in the "Removed in schema 3.0" appendix.

### `framework`

`framework` records the detected web framework (`flask`, `django`, `fastapi`, etc.),
detected by scanning import statements. This field is essential because different
frameworks have different vulnerability patterns. A SQL injection through Flask's
`request.args` differs structurally from one using Django's ORM; a path traversal using
Flask's `send_file` differs from one using Django's `FileResponse`.

CrossVul records programming language across 40+ languages and organises samples by
language — the most direct precedent for framework-level stratification. ReVeal is built
exclusively from Chromium and Debian security patches, implicitly applying a strong
framework/environment filter; our `framework` field makes this filter explicit and
queryable. In the eval harness, `framework` enables per-framework F1 breakdowns
(Django vs. Flask vs. FastAPI rows in the results table), and the Phase-6 red-team
engine uses it to select framework-specific exploit payloads.

### `sink_pattern`

`sink_pattern` records the specific regex within a CWE's pattern set that matched
`code_before` (e.g., for CWE-94 it captures whether the sample matched `eval(`,
`exec(`, `__import__(`, or `compile(...,'exec')`). The Phase-2B sink-presence
filter (`src/utils/cwe_taxonomy.py:has_cwe_sink`) computes this; the audit-pack
builder (`scripts/build_audit_pack.py:151`) reads it to stratify human-review
samples by sub-pattern, and the paper uses it for per-sub-pattern result tables
(e.g., "of CWE-94 samples, X% used `eval(` and Y% used dynamic import").

No prior Python vulnerability benchmark publishes this level of sink-pattern
detail. The closest precedent is Devign's per-function "vulnerability type" tag
on Chromium/QEMU patches, but Devign's tags are coarse-grained (e.g., "memory
corruption") rather than sink-specific. Storing the matched sink-pattern is an
original contribution of this benchmark and supports the sink-shaped scoping
decision documented in `PHASE_2B_DESIGN.md`.

---

## Group 8 — Dataset Management & Pipeline State (4 fields)

**Fields:** `content_hash`, `pair_id`, `nvd_enriched`, `split`

### Purpose

These fields serve two roles: `content_hash` and `pair_id` are dataset-management
keys (deduplication and before/after pair joining); `nvd_enriched` and `split` are
pipeline-state flags populated by later phases. Together they enable idempotent
re-execution: any phase can re-run and skip records it has already processed.

`classifier_cwe` and `classifier_confidence` were present in schema 2.x as outputs
of the Phase-2 commit-message classifier. The classifier was removed per
supervisor feedback (see `PROJECT_SUMMARY_2026-05-22.md`), and the fields were
trimmed in schema 3.0. Their literature justifications are preserved in the
"Removed in schema 3.0" appendix.

### `content_hash`

`content_hash` is the SHA-256 hash of `code_before`, used as the primary deduplication
key. Without deduplication, the same vulnerable file that has been forked into 50
repositories would appear 50 times in the training set, causing:
1. Massive data leakage between train and test splits (the same file appearing in both).
2. Inflated model performance metrics that do not reflect real-world generalisation.
3. Training set imbalance (heavily duplicated CWEs dominate the gradient updates).

Dataset deduplication is a critical quality concern across the literature:
- CVEfixes applies deduplication by `(commit_hash, file_name)` pair.
- BigVul applies CVE-level deduplication.
- DiverseVul (RAID 2023) explicitly deduplicates across five upstream datasets (BigVul,
  Devign, ReVeal, CrossVul, CVEfixes) by content hash, and reports that cross-dataset
  deduplication removes ~18% of records that would otherwise inflate model scores.
- Lee et al. (2022) showed that deduplicating training data improves language model
  generalisation — the same finding applies to code vulnerability datasets.

Content-hash deduplication is stricter than commit-based deduplication: two different
commits fixing the same file produce the same `content_hash` and are correctly merged.
In our pipeline `content_hash` is also the MongoDB unique-index key
(`src/utils/mongo_writer.py:96`), preventing duplicate inserts on re-runs.

### `pair_id`

`pair_id` links the before/after code pair: `{fix_commit_prefix}_{file_path}` for
OSV/GHSA/PyPA samples, or `{cve_id}_{file_path}` for CVEfixes samples. In Phase 5,
the before/after pair must be joined to construct the contrastive training example.
Without `pair_id`, joining records would require matching on `(fix_commit, file_path)`
tuples, which is more fragile than a single composite key.

LineVul joins before/after function pairs using function signatures and commit SHAs.
CrossVul encodes pair identity in its file naming convention
(`bad_{commitID}_{fileID}` / `good_{commitID}_{fileID}`). Our `pair_id` is a first-class
database field that makes pair joining a simple MongoDB equality query rather than a
multi-field join.

### `nvd_enriched`

`nvd_enriched` is a boolean flag recording whether Phase 3 (NVD enrichment) has been
applied to a record. Phase 3 calls the NVD REST API to retrieve CVSS data for records
that do not have CVSS at scrape time. Without this flag:

- Every Phase 3 run would re-query NVD for all records, wasting API calls and hitting
  rate limits (the NVD API has a limit of 5 requests per 30 seconds without an API key).
- GHSA records that already have CVSS would be re-queried unnecessarily.

This type of processing-state flag is standard in multi-stage data engineering pipelines.
CVEfixes describes a similar multi-stage enrichment process and notes that efficient
re-runs require tracking which records have already been enriched. D2A's dataset paper
discusses pipeline state tracking as part of its differential analysis methodology.

### `split`

`split` stores the train/val/test assignment (`"train"`, `"val"`, `"test"`) written by
Phase 2's data preparation stage. Storing the split in the record itself — rather than
in a separate index file — is a practice from CVEfixes and D2A, which both include
a split or fold assignment per record. The key advantage is reproducibility: anyone
who downloads the dataset gets the same splits without running the split code, and any
pipeline phase can filter for its required split with a single MongoDB query.

**LineVul** (Fu & Tantithamthavorn, MSR 2022) is the primary citation for formalising
the train/val/test split as a stored field. LineVul introduced the 80/10/10 chronological
split on BigVul as the standard evaluation protocol, and subsequent papers have adopted
the same split for fair comparability. Our pipeline uses a stratified 70/15/15 split
(to ensure class balance across CWE types, given that CWE-89 is ~5x more frequent than
CWE-22 in our scraped data) rather than a chronological split, but the practice of
storing the split assignment per record follows LineVul.

---

## Group 9 — Phase 2.5 Hard-Negative Provenance (3 fields)

**Fields:** `is_hard_negative`, `parent_sample_id`, `sanitization_transform`

### Purpose

Phase 2.5 generates **hard negatives** — samples that look superficially vulnerable
(same imports, similar variable names, same control flow) but have been sanitized so
the sink is no longer exploitable. A hard negative is produced by applying one of the
per-CWE *sanitization rules* (`src/red_team/sanitization/rules/`) to a vulnerable
sample. These three fields record the provenance of every hard-negative record so the
augmentation pipeline is auditable, reversible, and analyzable in the paper's
robustness section.

The group has no direct precedent in prior Python vulnerability benchmarks because
augmented-hard-negative provenance is itself a contribution of this work — but the
*pattern* of recording the source of synthetically generated samples is well-established
in adversarial-ML datasets (e.g., the original adversarial-examples literature
(Goodfellow et al., ICLR 2015) and contrastive-learning code datasets (CodeContrast,
SimCLR-Code) store the parent sample and the transformation that produced each
augmented example for exactly this reason).

### `is_hard_negative`

Boolean flag that distinguishes naturally-scraped samples (`false`) from samples
produced by Phase-2.5 sanitization (`true`). Used by the eval harness to score
detectors *only* on naturally-occurring samples in the standard test set, then
re-score on a hard-negative-augmented test set to report a robustness delta. Without
this flag, hard negatives would silently inflate the count of `safe`-labeled samples
in the standard test split and contaminate clean-test results.

### `parent_sample_id`

The `id` of the vulnerable sample that this hard negative was derived from. Enables:

1. **Audit**: a researcher can inspect both the original vulnerable code and the
   sanitized version side-by-side to verify the sanitization rule applied correctly.
2. **Anti-leakage in splits**: a hard negative must land in the same train/val/test
   split as its parent — otherwise a detector could see the parent in training and
   trivially recognise the hard-negative variant in test. The stratified splitter
   (`src/labeler/stratified_splitter.py`) uses `parent_sample_id` as part of its
   group key when present.
3. **Pair contrastive learning**: future Phase-3 work could use parent / hard-negative
   pairs as contrastive examples (closer to BigVul's `func_before`/`func_after`
   pairing pattern but applied to the augmented dimension).

### `sanitization_transform`

The name of the rule that produced this hard negative (e.g.,
`percent_execute_to_parameterized` for CWE-89,
`wrap_render_template_string_with_escape` for CWE-79). One value per record. Used
by the eval harness to compute per-transform robustness drops in the paper's
results table — answering "which sanitization patterns do detectors fail to
recognise as fixes?" rather than aggregating into a single hard-negative-vs-clean
number that would hide structure.

The Phase 2.5 mutator side (`dead_code_injection`, `string_split`,
`variable_rename`, `wrapper_extraction`, `composed`) materialises its variants
under `data/test_variants/` rather than into the dataset, so those mutator names
do not appear in this field — only the per-CWE sanitization-rule names do. This is
deliberate: sanitization changes the *label* (vulnerable → safe), so the result is
a new record; mutation preserves the label, so the result is a per-sample variant
attached to the same record.

---

## Justification for the 7 Target CWE Classes

The pipeline targets the **7 sink-shaped Top-25 Python CWEs**:
**CWE-89** (SQL Injection), **CWE-79** (Cross-Site Scripting),
**CWE-22** (Path Traversal), **CWE-78** (OS Command Injection),
**CWE-94** (Code Injection), **CWE-918** (Server-Side Request Forgery),
**CWE-502** (Insecure Deserialization).

The original four-CWE scope (CWE-89, CWE-78, CWE-22, CWE-502) was expanded during
Phase 2B (see `PHASE_2B_DESIGN.md`) to all sink-shaped CWEs in the MITRE Top 25 that
appear in Python web code with a closed alphabet of fix patterns. CWE-434 (file
upload), CWE-798 (hardcoded credentials), CWE-611 (XXE), CWE-330 (weak randomness),
and CWE-400 (resource exhaustion) were considered and dropped — either because they
fell outside the Top 25 (611/330/400), because their fix-pattern alphabet was too
small to support robustness analysis (798), or because audit found 100% false
positives from the sink filter on structural CWEs (434). The selection criteria
("sink-shaped" — vulnerability is the presence of a sink with attacker-controlled
input, not the absence of a structural property) is documented in
`PHASE_2B_DESIGN.md §1`.

### OWASP Top 10 (2021)

All seven CWE classes appear in the OWASP Top 10 (2021), the industry-standard list
of the most critical web application security risks:

- **A01 — Broken Access Control:** Includes CWE-22 Path Traversal.
- **A03 — Injection:** Covers CWE-89 SQL Injection, CWE-79 Cross-Site Scripting,
  CWE-78 OS Command Injection, and CWE-94 Code Injection as its primary examples.
- **A08 — Software and Data Integrity Failures:** Covers CWE-502 Insecure
  Deserialization as a primary example.
- **A10 — Server-Side Request Forgery:** A dedicated category in OWASP 2021,
  covering CWE-918.

The OWASP Top 10 is the most widely cited web security risk framework in both industry
and academic research (cited in over 1,200 academic papers per Google Scholar).

### MITRE CWE Top 25 (2022)

MITRE and CISA publish an annual list of the 25 most dangerous software weaknesses
based on NVD CVE data. In the 2022 edition:

- CWE-79 (Cross-Site Scripting) ranked **#2**.
- CWE-89 (SQL Injection) ranked **#3**.
- CWE-78 (OS Command Injection) ranked **#5**.
- CWE-22 (Path Traversal) ranked **#8**.
- CWE-94 (Code Injection) ranked **#25**.
- CWE-502 (Deserialization of Untrusted Data) ranked **#12**.
- CWE-918 (Server-Side Request Forgery) entered the Top 25 at **#21**.

All seven target CWEs appear in the Top 25 most dangerous, and four appear in the
top 8. The "sink-shaped" criterion (CWE has a closed alphabet of fix patterns
expressible as taint source → dangerous sink) is what differentiates these seven
from the rest of the Top 25 — and is documented in `PHASE_2B_DESIGN.md §1`.

### Prevalence in Prior Datasets

All seven CWE types appear among the most frequent classes in CVEfixes, BigVul, and
CrossVul, meaning they are well-represented in the vulnerability dataset literature
and enable fair comparison of results with prior work. CWE-89 alone accounts for
approximately 18% of all web application CVEs in NVD data (consistent across multiple
NVD analyses).

### Suitability for Static Detection and Automated Red Teaming

These four CWE types have clear, statically detectable code patterns — user input
flowing to SQL queries (CWE-89), shell commands (CWE-78), file paths (CWE-22), or
`pickle.loads` (CWE-502) — making them tractable for:

1. ML-based static detection in Phase 5 (the model can learn the pattern from source
   code without needing runtime information).
2. Automated red teaming in Phase 6 (exploit payloads for all four CWE types are well-
   defined and can be generated automatically).

CWE types with non-deterministic or cross-request patterns (e.g., race conditions
CWE-362, TOCTOU CWE-367, integer overflow CWE-190) are excluded because they cannot
be reliably detected from a static code snapshot or reliably exploited by a generic
automated red team framework.

---

## Summary Table

| Group | Fields | Count | Primary citation(s) |
|---|---|---|---|
| Identity | `_schema_version`, `id`, `source` | 3 | CVEfixes, BigVul, NVD JSON feed |
| Advisory IDs | `cve_id`, `ghsa_id` | 2 | CVEfixes, BigVul, CrossVul, VCCFinder, OSV schema |
| Vulnerability label | `cwe`, `label_source`, `label_confidence` | 3 | CVEfixes, BigVul, CrossVul, NVD; D2A (label_source/confidence) |
| CVSS severity | `cvss_score`, `cvss_severity`, `cvss_version`, `cvss_vector` | 4 | CVEfixes, BigVul, NVD CVSS v3.1 spec |
| Provenance | `repo`, `file_path`, `fix_commit` | 3 | CVEfixes, SZZ 2005, VCCFinder 2015 |
| Code payload | `code_before`, `code_after` | 2 | CVEfixes (exact field names), LineVul 2022, CrossVul, BigVul, Devign, ReVeal, DiverseVul |
| Code quality signals | `framework`, `sink_pattern` | 2 | Original contributions; framework analogous to ReVeal/Devign domain filters; sink_pattern unique to this benchmark |
| Dataset mgmt & pipeline state | `content_hash`, `pair_id`, `nvd_enriched`, `split` | 4 | DiverseVul (content-hash dedup), CrossVul (pair linking), CVEfixes (enrichment flags), LineVul (split) |
| Phase 2.5 hard-neg provenance | `is_hard_negative`, `parent_sample_id`, `sanitization_transform` | 3 | Original contribution; pattern analogous to adversarial-ML / contrastive-code dataset provenance |
| **Total** | | **26** | |

---

## Fields That Are Original Contributions

Five fields do not have a direct counterpart in any surveyed dataset. They are the
original contributions of this schema and are justified on methodological rather
than precedent grounds:

| Field | Justification |
|---|---|
| `framework` | Different Python web frameworks have different vulnerability patterns; required for per-framework slicing in the eval harness; analogous to the domain filter implicit in ReVeal (Chromium only) and Devign (FFmpeg/QEMU/Linux/Wireshark only) |
| `sink_pattern` | Records which specific regex within a CWE's sink set matched. Supports per-sub-pattern audit and the paper's sink-shaped scoping argument (Phase 2B). No prior Python benchmark publishes this granularity. |
| `is_hard_negative` | Distinguishes naturally-scraped samples from Phase-2.5 sanitization variants; required so hard negatives are evaluated separately from the standard test set. Original to this benchmark. |
| `parent_sample_id` | Links a hard-negative to the vulnerable sample it was derived from. Required for anti-leakage (parent + variant must share splits) and pair-contrastive learning. Pattern analogous to adversarial-ML augmentation provenance. |
| `sanitization_transform` | Records which Phase-2.5 sanitization rule produced each hard-negative. Enables per-transform robustness analysis ("which fix patterns do detectors fail to recognise?") rather than aggregating into a single hard-neg-vs-clean number. |

---

## Appendix: Fields Removed in Schema 3.0

Schema 2.x carried 53 fields. Schema 3.0 (this version) trimmed 27 of them — the
literature justifications for each are preserved here so the deliberate-curation
argument is traceable. Each removed field falls into one of four categories:

**(A) Derivable from a retained field.** No information loss; downstream code can
recompute on demand.

| Removed | Derivable from | Original justification (brief) |
|---|---|---|
| `cwe_name` | `cwe` (lookup table) | Human-readable CWE name; BigVul/CVEfixes both store it for sanity-checking. |
| `vuln_type` | `cwe` (snake_case mapping) | Internal slug for filenames/queries; CrossVul uses an analogous `vulnerability_type`. |
| `cvss_attack_vector`, `cvss_attack_complexity`, `cvss_privileges_required`, `cvss_user_interaction`, `cvss_scope`, `cvss_confidentiality`, `cvss_integrity`, `cvss_availability` | `cvss_vector` (parsing) | Per-CVSS-metric decomposition. **Spanos & Angelis (JSS 2018)** and **CVSS-BERT (ISSREW 2021)** argue these are individually predictive; the vector string preserves the data, only the denormalization is removed. |
| `loc_before`, `loc_after` | `code_before`, `code_after` (line count) | Code-size metric; Nagappan & Ball 2005, Halstead 1977 — 50+ years of defect-prediction precedent. |
| `vulnerable_commit` | `fix_commit` + git API (parent) | SZZ algorithm (Śliwerski et al., MSR 2005); recoverable via one upstream call. |
| `commit_date` | `fix_commit` + git API (date) | Temporal analysis (Finifter et al. 2013); recoverable. |
| `commit_message` | `fix_commit` + git API (message) | VCCFinder (CCS 2015) uses messages as ML features; recoverable. |

**(B) Filter-time-only signals with no downstream readers.** These gated which
samples entered `data/raw/` but were never read again. The filtering decision is
embedded in the dataset's *contents* (failing samples are absent); the boolean flag
itself is redundant once filtering has run.

| Removed | Original justification (brief) |
|---|---|
| `syntax_valid` | `ast.parse()` success; CVEfixes / D2A filter on this. Recomputable if needed. |
| `has_taint_source` | File contains `request.args`/`request.form`/etc. Used by health_check, which now recomputes inline. |
| `is_web_code` | Framework imports + HTTP patterns. Effectively `framework != "unknown"`; redundant with `framework`. |
| `has_cwe_sink` | Sink regex matched. Always True post-filter (failing samples live in `data/raw_rejected/`), so storing the flag is redundant on shipped records. |

**(C) Tied to removed pipeline phases.**

| Removed | Reason |
|---|---|
| `classifier_cwe` | Phase-2 commit classifier removed per supervisor feedback; always `null`. |
| `classifier_confidence` | Same. D2A-style label-provenance pattern preserved via `label_source` + `label_confidence`. |

**(D) Always-null or low-value.**

| Removed | Reason |
|---|---|
| `commit_author` | Always set to `null` in schema 2.x for PII reasons (CVEfixes omits the same); empty field carries no signal. |
| `scraped_at` | UTC timestamp; useful for incremental scraping during construction, never read downstream. |
| `language` | Always `"python"`; constant column. Will re-add if the benchmark expands to multi-language. |
| `osv_id`, `pysec_id` | Redundant with `cve_id` + `source` for cross-database join; only set by their respective scrapers, never read by any consumer. |
| `cvss_source` | Useful for distinguishing NVD-vs-GHSA scoring, but never read; `source` + `cvss_version` provide enough provenance. |

**Restoring any of these fields** is a one-line change in `build_meta()` plus a
re-scrape (or a script that re-computes the field from `code_before` / `fix_commit`
for the derivable ones). The literature citations above and the per-field
discussion preserved in git history (`git show <pre-3.0-commit>:FIELD_JUSTIFICATION.md`)
remain the academic justification if a future revision needs to add any of them back.

---

## References

The following is a full formatted reference list for all works cited in this document,
ordered by year of publication.

---

**[1]** Śliwerski, J., Zimmermann, T., & Zeller, A. (2005).
"When Do Changes Induce Fixes?"
*Proceedings of the International Workshop on Mining Software Repositories (MSR 2005).*
ACM SIGSOFT Software Engineering Notes, vol. 30, no. 4, pp. 1–5.
Available: https://thomas-zimmermann.com/publications/files/sliwerski-wsr-2005.pdf

> Introduced the SZZ algorithm for identifying bug-inducing commits by tracing backward
> from fix commits. Foundational methodology for the `fix_commit` and `vulnerable_commit`
> fields; every vulnerability dataset that links vulnerable code to a fix commit implicitly
> applies SZZ or a variant.

---

**[2]** Bozorgi, M., Saul, L. K., Savage, S., & Voelker, G. M. (2010).
"Beyond Heuristics: Learning to Classify Vulnerabilities and Predict Exploits."
*Proceedings of the 16th ACM SIGKDD International Conference on Knowledge Discovery and
Data Mining (KDD '10)*, pp. 105–114. ACM.
DOI: 10.1145/1835804.1835821

> First large-scale ML study to use individual CVSS base metrics (Attack Vector, Attack
> Complexity, Privileges Required, etc.) as separate features for exploitability
> prediction. Establishes the earliest precedent for treating CVSS sub-metrics as
> individual ML features rather than using the composite score alone.

---

**[3]** Perl, H., Dechand, S., Smith, M., Heid, D., Acar, Y., Fahl, S., & Smith, P. (2015).
"VCCFinder: Finding Potential Vulnerabilities in Open-Source Projects to Assist Code Audits."
*Proceedings of the 22nd ACM SIGSAC Conference on Computer and Communications Security
(CCS '15)*, pp. 426–437. ACM.
DOI: 10.1145/2810103.2813604

> First large-scale mapping of CVEs to GitHub fix commits to build a vulnerable-commit
> database. Uses repository URLs, commit SHAs, and commit messages as features for SVM
> classification. Establishes `repo`, `fix_commit`, and `commit_message` as standard
> provenance fields for code-level vulnerability datasets.

---

**[4]** OWASP Foundation. (2021).
"OWASP Top 10: 2021."
Available: https://owasp.org/Top10/

> Industry-standard list of the ten most critical web application security risk
> categories. CWE-89 (SQL Injection) appears under A03:Injection; CWE-78 (OS Command
> Injection) under A03:Injection; CWE-22 (Path Traversal) under A01:Broken Access
> Control; CWE-502 (Insecure Deserialization) under A08:Software and Data Integrity
> Failures. Justifies the selection of the four target CWE classes.

---

**[5]** Zhou, Y., Liu, S., Siow, J., Du, X., & Liu, Y. (2019).
"Devign: Effective Vulnerability Identification by Learning Comprehensive Program
Semantics via Graph Neural Networks."
*Advances in Neural Information Processing Systems 32 (NeurIPS 2019).*
arXiv: 1909.03496.
Available: https://proceedings.neurips.cc/paper_files/paper/2019/hash/49265d2447bc3bbfe9e76306ce40a31f-Abstract.html

> Introduces the Devign dataset of C function pairs (vulnerable/patched) from FFmpeg,
> QEMU, Linux kernel, and Wireshark, organized around `sha_id` (fix commit SHA). Uses a
> two-round manual labeling process with senior researcher adjudication. Justifies
> `fix_commit` as the primary data collection unit, binary label (vulnerable/non-
> vulnerable), and the concept of `label_confidence` via its inter-annotator agreement
> process.

---

**[6]** Bhandari, G., Naseer, A., & Moonen, L. (2021).
"CVEfixes: Automated Collection of Vulnerabilities and Their Fixes from Open-Source Software."
*Proceedings of the 17th International Conference on Predictive Models and Data Analytics
in Software Engineering (PROMISE '21).*  ACM, 2021.
DOI: 10.1145/3475960.3475985. arXiv: 2107.08760.
Dataset DOI: 10.5281/zenodo.4476563.
GitHub: https://github.com/secureIT-project/CVEfixes

> Introduces the CVEfixes dataset of 12,107 vulnerability-fixing commits across 4,249
> projects and 11,873 CVEs, covering 272 CWE types across multiple programming languages.
> Stores `cve_id`, `cwe_id`, CVSS scores from NVD, `repo_url`, `commit_hash`,
> `commit_message`, `commit_date`, `file_name`, `code_before`, and `code_after` at both
> file and function level — using exact field names that match this schema. The single
> most directly relevant prior dataset.

---

**[7]** Fan, J., Li, Y., Wang, S., & Nguyen, T. N. (2020).
"A C/C++ Code Vulnerability Dataset with Code Changes and CVE Summaries."
*Proceedings of the 17th International Conference on Mining Software Repositories
(MSR '20).* ACM, 2020.
DOI: 10.1145/3379597.3387501.
GitHub: https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset

> Introduces BigVul: 3,754 vulnerable C/C++ projects linked to CVEs, covering 91 CWE
> types. Stores `CVE_ID`, `CWE_ID`, CVSS scores, `commit_message`, `func_before`, and
> `func_after`. One of the most widely cited vulnerability datasets; its 21-field schema
> is a widely adopted template. Justifies `cve_id`, `cwe`, `cvss_score`, `commit_message`,
> `code_before`, and `code_after`.

---

**[8]** Nikitopoulos, G., Dritsa, K., Louridas, P., & Mitropoulos, D. (2021).
"CrossVul: A Cross-Language Vulnerability Dataset with Commit Data."
*Proceedings of the 29th ACM Joint European Software Engineering Conference and Symposium
on the Foundations of Software Engineering (ESEC/FSE '21).* ACM, 2021.
DOI: 10.1145/3468264.3473122.
Dataset DOI: 10.5281/zenodo.4734050.

> Introduces CrossVul: 5,131 unique CVEs across 168 CWE types in 40+ programming
> languages, with paired vulnerable (`bad_*`) and patched (`good_*`) file versions and
> commit metadata. Organises directory structure by CWE ID. Best precedent for the
> multi-language `language` field, the CWE-based `vuln_type` slug, and the `commit_message`
> provenance field. Also provides evidence for the paired `code_before`/`code_after`
> approach.

---

**[9]** Zheng, Y., Pujar, S., Burdet, B., Buratti, L., Epstein, E., Yang, B., Lewis, B.,
Zhang, C., & Farchi, E. (2021).
"D2A: A Dataset Built for AI-Based Vulnerability Detection Methods Using Differential Analysis."
*Proceedings of the IEEE/ACM 43rd International Conference on Software Engineering:
Software Engineering in Practice (ICSE-SEIP '21).* 2021.
DOI: 10.1109/ICSE-SEIP52600.2021.00020. arXiv: 2102.07995.
GitHub: https://github.com/IBM/D2A

> Introduces D2A: vulnerability labels derived by comparing static analysis tool output
> before and after fix commits across six major open-source C/C++ projects. Includes an
> explicit `label_source` field with values `"auto_labeler"` and `"after_fix_extractor"` —
> a direct precedent for this schema's `label_source` and `label_confidence` fields. Also
> justifies `fix_commit`, `file_path`, and `syntax_valid` (files failing analysis are
> excluded).

---

**[10]** Chang, O. et al. (Google Open Source Security Team). (2021–present).
"OSV: A Open, Precise, and Distributed Approach to Vulnerability Management."
OSV Schema Specification v1.x.
Available: https://ossf.github.io/osv-schema/

> Defines the Open Source Vulnerability (OSV) schema, which includes `id`, `aliases`,
> and `related` fields specifically to enable cross-database advisory linking. Defines
> `pysec` (PyPA) and `ghsa` (GitHub) as distinct namespaces with separate ID formats.
> Authoritative reference for the `ghsa_id`, `osv_id`, and `pysec_id` fields in this
> schema.

---

**[11]** Chakraborty, S., Krishna, R., Ding, Y., & Ray, B. (2022).
"Deep Learning based Vulnerability Detection: Are We There Yet?"
*IEEE Transactions on Software Engineering*, vol. 48, no. 9, pp. 3280–3296.
Journal-First at ICSE 2022. arXiv: 2009.07235.
GitHub: https://github.com/VulDetProject/ReVeal

> Introduces ReVeal: C function pairs (vulnerable/patched) extracted from Chromium
> security issues and Debian security tracker. Tests multiple deep learning architectures
> for vulnerability detection. Applies a strong domain filter (web browser and Debian
> packages only), establishes the developer-reported patch commit as the label source,
> and labels pre-patch code as vulnerable (negative class is post-patch). Justifies
> `code_before`/`code_after`, `label_source`, and the `is_web_code` domain filter concept.

---

**[12]** Fu, M., & Tantithamthavorn, C. (2022).
"LineVul: A Transformer-based Line-Level Vulnerability Prediction."
*Proceedings of the 19th International Conference on Mining Software Repositories
(MSR '22).* IEEE, 2022.
IEEE Xplore: 9796256.
GitHub: https://github.com/awsm-research/LineVul

> Fine-tunes a CodeBERT transformer on BigVul for both function-level and line-level
> vulnerability prediction. Introduces a formalised 80/10/10 chronological train/val/test
> split on BigVul that has been adopted as the standard evaluation protocol. Key finding:
> using paired `func_before`/`func_after` examples achieves 160–379% higher F1 than
> prior methods. Justifies `code_before`, `code_after`, and the `split` field.

---

**[13]** Spanos, G., & Angelis, L. (2018).
"A Multi-Target Approach to Estimate Software Vulnerability Characteristics and Severity Scores."
*Journal of Systems and Software*, vol. 146, pp. 152–166. Elsevier.
DOI: 10.1016/j.jss.2018.09.044.
Available: https://www.sciencedirect.com/science/article/abs/pii/S0164121218302061

> Trains multi-target ML models (Random Forest, boosting, decision trees) to predict
> individual CVSS v3 characteristics — Attack Vector, Attack Complexity, Privileges
> Required, Scope, Confidentiality Impact, Integrity Impact, Availability Impact — as
> separate classification targets. Key finding: individual sub-metrics are significantly
> better features than the composite score. Primary academic justification for storing
> all 8 CVSS base metrics as individual fields (`cvss_attack_vector`,
> `cvss_attack_complexity`, `cvss_privileges_required`, `cvss_user_interaction`,
> `cvss_scope`, `cvss_confidentiality`, `cvss_integrity`, `cvss_availability`).

---

**[14]** Shahid, M. R., & Debar, H. (2021).
"CVSS-BERT: Explainable Natural Language Processing to Determine the Severity of a
Computer Security Vulnerability from its Description."
*Proceedings of the IEEE International Symposium on Software Reliability Engineering
Workshops (ISSREW 2021).*
arXiv: 2111.08510.
Available: https://arxiv.org/abs/2111.08510

> Fine-tunes BERT to predict each of the 8 CVSS v3.1 base metrics as a separate
> classification task using 45,926 NVD CVE entries from 2018–2020. Trains one classifier
> per sub-metric, confirming that each metric carries independent predictive signal.
> Corroborates Spanos & Angelis (2018) with a more modern architecture and larger dataset.
> Secondary justification for the individual CVSS sub-metric fields.

---

**[15]** Chen, Y., Ding, Y., Alowain, L., Chen, X., & Wagner, D. (2023).
"DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection."
*Proceedings of the 26th International Symposium on Research in Attacks, Intrusions and
Defenses (RAID 2023).*

> Unifies and deduplicates BigVul, Devign, ReVeal, CrossVul, and CVEfixes into a single
> corpus of 18,945 vulnerable and 330,492 non-vulnerable C/C++ functions across 150 CWEs
> from 7,514 commits. Applies content-hash deduplication and finds ~18% of records are
> duplicates across datasets. Justifies `content_hash` for deduplication and confirms
> CWE labels, `code_before`/`code_after` structure, and `language` field across all five
> upstream datasets.

---

**[16]** NIST — National Institute of Standards and Technology. (2019).
"Common Vulnerability Scoring System v3.1: Specification Document."
Available: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator

> The authoritative specification for CVSS v3.1 base metrics, their allowed values, and
> their mathematical combination into a composite score. Defines the 8 base metrics, 4
> temporal metrics, and 4 environmental metrics. Justifies the structure and allowed
> values of all 13 CVSS fields (`cvss_score`, `cvss_severity`, `cvss_version`,
> `cvss_vector`, `cvss_attack_vector`, `cvss_attack_complexity`,
> `cvss_privileges_required`, `cvss_user_interaction`, `cvss_scope`,
> `cvss_confidentiality`, `cvss_integrity`, `cvss_availability`, `cvss_source`).

---

**[17]** MITRE Corporation & CISA. (2022).
"2022 CWE Top 25 Most Dangerous Software Weaknesses."
Available: https://cwe.mitre.org/top25/archive/2022/2022_cwe_top25.html

> Annual ranking of the 25 most dangerous software weaknesses based on NVD CVE frequency
> and severity data. In 2022: CWE-89 (SQL Injection) ranked #3; CWE-78 (OS Command
> Injection) ranked #5; CWE-22 (Path Traversal) ranked #8; CWE-502 (Insecure
> Deserialization) ranked #12. All four target CWE classes appear in the top 25.
> Justifies the choice of the four target CWE classes for this dataset.
