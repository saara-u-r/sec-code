# Schema Field Justification — Literature Survey

This document provides a detailed, field-by-field justification for every metadata field
in the vulnerability dataset schema (`build_meta()` in `src/utils/file_utils.py`).
Each field is grounded in peer-reviewed vulnerability dataset and vulnerability detection
research. The aim is to demonstrate that every field either (a) directly mirrors a field
used in a published dataset, (b) follows a standard established in the literature, or
(c) is an original contribution motivated by the web-security focus of this pipeline.

The schema has **48 fields** organized into 8 groups. The 4 CWE classes targeted
(CWE-89, CWE-78, CWE-22, CWE-502) are justified separately at the end.

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

## Group 1 — Identity (4 fields)

**Fields:** `_schema_version`, `id`, `source`, `scraped_at`

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

### `scraped_at`

A UTC collection timestamp serves two purposes. First, it enables incremental scraping:
only re-run scrapers for records older than a threshold, rather than re-scraping everything
on every run. Second, it enables temporal analysis of dataset growth over time and lets
you verify that a dataset version was collected before or after a specific advisory was
published (e.g., to avoid including future-knowledge leakage in evaluation).
CVEfixes stores `published_date` and `updated_date` per CVE record for the same reasons.

---

## Group 2 — Advisory IDs (4 fields)

**Fields:** `cve_id`, `ghsa_id`, `osv_id`, `pysec_id`

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

### `osv_id`

The Open Source Vulnerability (OSV) schema (Chang et al., Google, 2021) is the emerging
standard for open-source vulnerability advisories. OSV.dev aggregates advisories from
GHSA, PyPA, Go Vulnerability Database, Rust Advisory DB, and others. The OSV schema
specification explicitly defines `id`, `aliases`, and `related` fields to support
cross-database linking — our four advisory ID fields implement exactly this pattern.
Storing `osv_id` enables enrichment from the OSV API and cross-referencing with
OSV-sourced records in the dataset.

### `pysec_id`

PyPA advisories (format `PYSEC-YYYY-NNN`) are the primary source for Python-package-
specific vulnerabilities. Many Python package vulnerabilities are reported to PyPA before
they receive a CVE from MITRE, so `pysec_id` captures records that would be missed if
we relied solely on `cve_id`. The OSV schema explicitly defines PyPA (`pysec`) as a
distinct namespace with its own ID format, further justifying a separate field.

All four advisory ID fields coexist on every record, with `null` for whichever scrapers
did not produce the record — this is the same pattern used by the OSV schema's `aliases`
array and is consistent with CrossVul's multi-ID design.

---

## Group 3 — Vulnerability Label (5 fields)

**Fields:** `cwe`, `cwe_name`, `vuln_type`, `label_source`, `label_confidence`

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

### `cwe_name`

`cwe_name` is the human-readable string for the CWE ID (e.g., "SQL Injection" for
CWE-89). BigVul includes a `Vulnerability Classification` column with the CWE name
alongside the numeric ID. CVEfixes stores both CWE ID and CWE description. The field
is not used directly in ML training, but it is essential for generating readable
reports, visualisations, and dataset documentation — and for sanity-checking that a
numeric CWE ID was correctly assigned (e.g., confirming that CWE-89 maps to SQL
Injection and not Path Traversal).

### `vuln_type`

`vuln_type` is an internal normalised slug (e.g., `sql_injection`, `path_traversal`)
used as a filename prefix, MongoDB filter key, and dataset folder name. It is derived
deterministically from `cwe`. CrossVul uses a `vulnerability_type` column for the same
purpose — a stable, machine-processable string for the vulnerability class that avoids
the need to parse numeric CWE IDs in downstream code. Without this field, every MongoDB
query for a specific vulnerability class would require a regex or CWE-ID lookup, making
the pipeline more brittle.

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

## Group 4 — CVSS Severity (13 fields)

**Fields:** `cvss_score`, `cvss_severity`, `cvss_version`, `cvss_vector`,
`cvss_attack_vector`, `cvss_attack_complexity`, `cvss_privileges_required`,
`cvss_user_interaction`, `cvss_scope`, `cvss_confidentiality`, `cvss_integrity`,
`cvss_availability`, `cvss_source`

### Purpose

CVSS v3 encodes vulnerability severity across 8 independent dimensions, which combine
mathematically into a 0–10 score. The critical design decision in this schema is to
store each CVSS component as an individual field rather than only the composite score.
This choice is directly justified by two independent peer-reviewed ML studies showing
that individual CVSS components are better predictive features than the aggregate score
alone.

### Why 13 fields instead of just `cvss_score`?

**Spanos & Angelis (2018)** — *Journal of Systems and Software*, vol. 146 — is the
primary justification. Their paper trains multi-target ML models to predict individual
CVSS characteristics from vulnerability descriptions. Their key finding: Attack Vector,
Attack Complexity, Confidentiality Impact, Integrity Impact, and Availability Impact are
each independently predictive, and models using individual sub-metrics as separate
features significantly outperform those using only the composite score. They explicitly
conclude that decomposing CVSS into its components is the correct approach for
ML-based vulnerability analysis.

**CVSS-BERT (Shahid & Debar, ISSREW 2021)** independently confirms this on 45,926 NVD
CVE entries from 2018–2020. It trains a separate BERT-based classifier for each of the
8 CVSS v3 base metrics (Attack Vector, Attack Complexity, Privileges Required, User
Interaction, Scope, Confidentiality, Integrity, Availability). This architecture — one
classifier per sub-metric — would be impossible to implement if the sub-metrics were not
stored as individual fields.

**Bozorgi et al. (KDD 2010)** used CVSS base metrics as individual features for
exploitability prediction at the KDD conference, establishing the earliest academic
precedent for treating CVSS components as separate ML features.

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

### `cvss_attack_vector`

Attack Vector distinguishes remote (NETWORK) from local (LOCAL, ADJACENT, PHYSICAL)
vulnerabilities. This is arguably the most important CVSS component for prioritisation:
NETWORK-exploitable vulnerabilities (SQL injection in a web-facing Flask endpoint) are
dramatically more dangerous than LOCAL ones. Spanos & Angelis (2018) identify Attack
Vector as a high-importance feature in their multi-target model. Bozorgi et al. (2010)
use Attack Vector as a feature for exploitability prediction. In Phase 6, Attack Vector
determines which red team payloads are applicable (only NETWORK vulnerabilities are
targeted by the web-based red team).

### `cvss_attack_complexity`

Attack Complexity (LOW / HIGH) encodes whether an exploit requires special conditions
beyond the attacker's control. LOW means the exploit is reliable and repeatable; HIGH
means it requires a race condition, specific configuration state, or other circumstance
the attacker cannot directly control. Spanos & Angelis (2018) and CVSS-BERT (2021)
both model Attack Complexity as a separately predicted feature. In Phase 6 it informs
the difficulty level of red team exploit payloads.

### `cvss_privileges_required`

Privileges Required (NONE / LOW / HIGH) indicates whether the attacker needs an account
on the system. NONE means the exploit is unauthenticated — the most dangerous scenario
for a public web application. SQL injection vulnerabilities in public Flask routes are
almost always NONE. Bozorgi et al. (2010) and Spanos & Angelis (2018) both use this
component as a feature for exploitability and severity prediction.

### `cvss_user_interaction`

User Interaction (NONE / REQUIRED) indicates whether a victim must take action. Server-
side vulnerabilities like SQL injection and OS command injection are NONE: the attacker
interacts directly with the server and no victim action is required. This field helps
filter for purely server-side vulnerabilities, which are the focus of the Phase 6 red
team engine. CVSS-BERT (2021) trains a dedicated classifier for this metric.

### `cvss_scope`

Scope (UNCHANGED / CHANGED) is unique to CVSS v3 and indicates whether a successful
exploit can affect systems beyond the vulnerable component. CHANGED means the exploit
can "jump" — from the web application to the underlying OS (relevant for CWE-78 command
injection) or database server. Scope-CHANGED vulnerabilities receive higher red team
priority. Spanos & Angelis (2018) model Scope as a separate target in their multi-target
framework.

### `cvss_confidentiality`, `cvss_integrity`, `cvss_availability`

These three fields encode the CIA (Confidentiality, Integrity, Availability) impact
(NONE / LOW / HIGH). Together they represent the classic information security triad:

- CWE-89 SQL Injection: HIGH confidentiality (read entire DB), HIGH integrity (write or
  delete data), potentially HIGH availability (drop tables).
- CWE-22 Path Traversal: HIGH confidentiality (read arbitrary files on the server).
- CWE-502 Insecure Deserialization: typically HIGH across all three (arbitrary code
  execution).
- CWE-78 Command Injection: HIGH across all three (full OS command execution).

Spanos & Angelis (2018) train three separate classifiers — one per CIA component — and
find that each carries distinct predictive signals. CVSS-BERT (2021) similarly treats
each CIA impact as a separate classification task. Storing all three individually is
required to reproduce these methods and to generate per-dimension impact reports.

### `cvss_source`

`cvss_source` records whether CVSS data came from GHSA (available at scrape time,
assigned by GitHub's security team) or NVD (filled in by Phase 3, assigned by NIST
analysts). GHSA and NVD scores for the same CVE sometimes differ. Without this field,
there is no way to audit which records have NIST-assigned scores versus GitHub-assigned
ones, or to detect and resolve scoring discrepancies between the two sources. This is
a data provenance field analogous to `label_source` in Group 3.

---

## Group 5 — Provenance (7 fields)

**Fields:** `repo`, `file_path`, `fix_commit`, `vulnerable_commit`,
`commit_message`, `commit_date`, `commit_author`

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

### `vulnerable_commit`

The SHA of the parent commit (last commit before the fix) identifies the exact code
state that is vulnerable — the version from which `code_before` is fetched. The
methodology for identifying this commit is the **SZZ algorithm** (Śliwerski, Zimmermann
& Zeller, MSR 2005), which introduced the concept of tracing backward from a fix
commit to find the commit that introduced the bug. SZZ and its variants (B-SZZ,
AG-SZZ, MA-SZZ, RA-SZZ) are the standard approach used by CVEfixes, D2A, and BigVul
for locating the vulnerable version of code. Without storing `vulnerable_commit`,
reproducing the dataset would require re-running git bisection for every sample.

### `commit_message`

The developer's commit message documents their own understanding of what was wrong and
how they fixed it. This field is established across the dataset literature:

- CVEfixes stores `commit_message` as an explicit field for every fix commit.
- VCCFinder (Perl et al., 2015) uses commit messages as ML features — showing that
  developers' natural-language descriptions of their changes carry signal for
  vulnerability detection.
- CrossVul includes commit messages in its supporting data tables specifically because
  they aid in verifying that a commit is a security fix (rather than a routine refactor).

In this schema, `commit_message` is retained as a provenance field: it enables qualitative
auditing of label quality (a commit message saying "Fix SQL injection in login form"
corroborates a CWE-89 label) and is useful for consumers who want to understand the
human context behind each fix.

### `commit_date`

The date of the fix commit enables temporal analysis — a standard methodology in
empirical software engineering. Studies such as Finifter et al. (2013) used commit
dates to measure vulnerability lifetimes in Chrome and Firefox. CVEfixes stores
`commit_date` per record for this purpose. Temporal analysis of fix commit dates is
relevant for answering questions such as: How long do vulnerabilities survive before
being patched? Are newer Flask projects patching faster than older ones? The field is
currently not fully populated but is reserved for future enrichment in this pipeline.

### `commit_author`

`commit_author` is intentionally set to `null` in all records for PII (Personally
Identifiable Information) reasons. Developer usernames and email addresses are personal
data subject to privacy regulations including GDPR in Europe and equivalent laws
elsewhere. CVEfixes explicitly omits personally identifiable developer information.
The field is retained in the schema (as a typed null) rather than removed entirely
so that the schema documents the deliberate decision — a future version of the pipeline
could populate it with anonymised author IDs if needed for contribution-analysis studies.

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

## Group 7 — Code Analysis Flags (8 fields)

**Fields:** `framework`, `language`, `loc_before`, `loc_after`,
`syntax_valid`, `has_taint_source`, `is_web_code`, `content_hash`

### Purpose

These fields are computed automatically at scrape time by static analysis of
`code_before` and `code_after`. They serve two purposes: dataset quality control
(filtering out unsuitable samples before training) and feature engineering (providing
additional signals for Phase 5 ML models beyond raw code content).

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
queryable. The red team engine (Phase 6) targets Flask applications specifically, so
`framework` is a mandatory filter field for Phase 6.

### `language`

`language` is always `"python"` in the current dataset and is reserved for future
expansion to other languages. Storing it explicitly follows the standard established by
every multi-language dataset:

- CrossVul covers 40+ programming languages and includes `language` (from file extension)
  as an explicit schema field.
- BigVul covers C/C++ and documents language as a key characteristic of its scope.
- CVEfixes covers multiple languages and uses `programming_language` as a filter field.
- DiverseVul covers both C and C++ and documents language distribution in its statistics.

Storing `language` even when it is always `"python"` future-proofs the schema for
expansion and makes the dataset's scope explicit to consumers.

### `loc_before` and `loc_after`

Lines of code (LOC) is one of the oldest and most widely studied code metrics in
software engineering. Its relevance to vulnerability detection:

- CVEfixes stores the number of lines added and deleted per commit, from which file LOC
  is directly derivable. The paper uses LOC statistics to characterise the dataset.
- BigVul records code-size statistics per function, and LineVul builds on these for its
  line-level analysis.
- The vulnerability detection literature consistently finds that vulnerability density
  (vulnerabilities per KLOC) varies across file sizes, meaning LOC is a useful
  normalisation factor and a feature for ML.
- Software defect prediction literature (Nagappan & Ball, ICSE 2005; Halstead 1977)
  has established LOC as a baseline metric for defect prediction for over 50 years.

In Phase 5, `loc_before` is used to stratify training samples: very small utility
files and very large application modules have different vulnerability pattern densities.
`loc_after` allows computing the patch size delta (the size of the change that fixed
the vulnerability), which is used as a quality signal — patches that change hundreds of
lines are more likely to mix security fixes with unrelated refactoring.

### `syntax_valid`

`syntax_valid` records whether `code_before` passes Python `ast.parse()` without errors.
Files that fail are filtered before Phase 5 training for three reasons:
1. They cannot be tokenised or parsed by any code analysis tool.
2. Syntax errors in scraped code typically indicate truncated file fetches or encoding
   problems during scraping.
3. A model trained on syntactically invalid code learns noise rather than vulnerability
   patterns.

CVEfixes and D2A both include syntax and parsability filtering as explicit cleaning
steps in their pipeline descriptions. D2A specifically notes that files failing static
analysis tool checks are excluded from its dataset. Our `syntax_valid` flag makes this
filtering step explicit and queryable — a transparent cleaning decision rather than a
hidden pre-processing step that could silently bias the dataset.

### `has_taint_source`

`has_taint_source` is `true` when the file contains direct references to user-input
sources such as `request.args`, `request.form`, `request.data`, or `request.json`.
Taint analysis — tracking the flow of user-controlled data from input sources to
dangerous sinks — is the foundational methodology of web application security analysis.
Tools including OWASP's CodeQL integration, Bandit (Python), and FlowDroid all implement
taint analysis.

The Juliet Test Suite (NIST/NSA), which is the standard synthetic vulnerability benchmark,
categorises every sample by whether the taint source is in the same file as the dangerous
sink. This categorisation directly parallels our `has_taint_source` field.

A known limitation of file-level analysis (documented in `DATASET_SCHEMA.md`) is that
`has_taint_source` is `false` for database-layer files like `db.py` where the taint
originates in a Flask route file. The field is retained precisely because this limitation
is informative: it documents a cross-file taint analysis gap that Phase 5 model
consumers need to be aware of.

### `is_web_code`

`is_web_code` indicates whether a file contains web application code (framework imports,
HTTP request/response patterns). It is used to filter out library internals, test
utilities, setup scripts, and configuration files that appear in Flask project
repositories but contain no web-facing vulnerability patterns.

Domain filtering is applied implicitly in every focused vulnerability dataset:
- ReVeal (Chakraborty et al., 2022) is built exclusively from security patches in
  Chromium — a domain filter equivalent in spirit to `is_web_code = true`.
- Devign covers FFmpeg, QEMU, Linux kernel, and Wireshark — a domain filter to
  systems-level C code.
- Our `is_web_code` field makes this domain filter explicit and queryable, consistent
  with the transparency goals of research-grade dataset construction.

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
This is the right behaviour because from an ML perspective, training on the same code
twice (regardless of commit SHA) introduces duplication bias.

---

## Group 8 — ML Pipeline State (6 fields)

**Fields:** `pair_id`, `classifier_cwe`, `classifier_confidence`,
`nvd_enriched`, `split`, and implicitly `content_hash` (also in Group 7)

*(Note: `content_hash` serves double duty as both a quality signal and a pipeline
deduplication key. It is documented fully in Group 7.)*

### Purpose

These fields start as `null` or `false` at scrape time and are progressively populated
by later phases of the pipeline. They enable idempotent execution: any phase can re-run
and safely skip records that have already been processed, and any MongoDB query can
filter for records at a specific pipeline stage.

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

### `classifier_cwe`

`classifier_cwe` stores the CWE label predicted by the Phase 2 commit message
classifier (e.g., `"CWE-89"`). This field provides a **secondary label** for samples
where the advisory CWE is absent, uncertain, or classified as `"other"`.

The use of a classifier-generated secondary label alongside an advisory-sourced primary
label follows the D2A approach: D2A stores both the automated labeler's assignment
(`label_source = "auto_labeler"`) and the post-fix extractor's assignment as separate
fields, allowing downstream consumers to choose their label source or combine both.
In our pipeline, `classifier_cwe` is used in Phase 5 for samples where `label_confidence`
is low or `cwe` is missing — the classifier's prediction fills the gap.

### `classifier_confidence`

`classifier_confidence` stores the confidence score (0–1) of the Phase 2 prediction.
In Phase 2, a DistilBERT model's prediction replaces the SVM prediction only if the
DistilBERT confidence exceeds the SVM confidence. In Phase 5, low-confidence predictions
are down-weighted relative to high-confidence advisory-sourced labels.

The pattern of storing a classifier confidence score alongside a label is standard in
multi-stage NLP pipelines and is consistent with D2A's confidence-tier approach and
Devign's inter-annotator agreement documentation. Storing the confidence as a numeric
field rather than a binary accept/reject allows Phase 5 to apply continuous weighting
rather than a hard threshold.

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
CWE-502 in our scraped data) rather than a chronological split, but the practice of
storing the split assignment per record follows LineVul.

---

## Justification for the 4 Target CWE Classes

The pipeline targets: **CWE-89** (SQL Injection), **CWE-78** (OS Command Injection),
**CWE-22** (Path Traversal), **CWE-502** (Insecure Deserialization).

### OWASP Top 10 (2021)

All four CWE classes appear in the OWASP Top 10 (2021), the industry-standard list of
the most critical web application security risks:

- **A01 — Broken Access Control:** Includes CWE-22 Path Traversal (directory traversal
  is a canonical broken access control vulnerability).
- **A03 — Injection:** Explicitly covers CWE-89 SQL Injection and CWE-78 OS Command
  Injection as its primary examples.
- **A08 — Software and Data Integrity Failures:** Explicitly covers CWE-502 Insecure
  Deserialization as a primary example.

The OWASP Top 10 is the most widely cited web security risk framework in both industry
and academic research (cited in over 1,200 academic papers per Google Scholar).

### MITRE CWE Top 25 (2022)

MITRE and CISA publish an annual list of the 25 most dangerous software weaknesses
based on NVD CVE data. In the 2022 edition:

- CWE-89 (SQL Injection) ranked **#3**.
- CWE-22 (Path Traversal) ranked **#8**.
- CWE-78 (OS Command Injection) ranked **#5**.
- CWE-502 (Deserialization of Untrusted Data) ranked **#12**.

All four target CWEs appear in the top 25 most dangerous, and three appear in the top 8.

### Prevalence in Prior Datasets

All four CWE types appear among the most frequent classes in CVEfixes, BigVul, and
CrossVul, meaning they are well-represented in the vulnerability dataset literature and
enable fair comparison of results with prior work. CWE-89 alone accounts for
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

| Group | Field | Count | Primary citation(s) |
|---|---|---|---|
| Identity | `_schema_version`, `id`, `source`, `scraped_at` | 4 | CVEfixes, BigVul, NVD JSON feed |
| Advisory IDs | `cve_id`, `ghsa_id`, `osv_id`, `pysec_id` | 4 | CVEfixes, BigVul, CrossVul, VCCFinder, OSV schema |
| Vulnerability labels | `cwe`, `cwe_name`, `vuln_type` | 3 | CVEfixes, BigVul, CrossVul, DiverseVul, NVD |
| Label provenance | `label_source`, `label_confidence` | 2 | D2A (exact `label_source` field), Devign, BigVul replication study |
| CVSS score | `cvss_score`, `cvss_severity`, `cvss_version`, `cvss_vector`, `cvss_source` | 5 | CVEfixes, BigVul, NVD CVSS v3.1 spec |
| CVSS sub-metrics | `cvss_attack_vector`, `cvss_attack_complexity`, `cvss_privileges_required`, `cvss_user_interaction`, `cvss_scope`, `cvss_confidentiality`, `cvss_integrity`, `cvss_availability` | 8 | Spanos & Angelis 2018 (multi-target prediction), CVSS-BERT 2021, Bozorgi et al. 2010 |
| Provenance | `repo`, `file_path`, `fix_commit`, `vulnerable_commit`, `commit_message`, `commit_date`, `commit_author` | 7 | CVEfixes, SZZ 2005, VCCFinder 2015, D2A, CrossVul |
| Code payload | `code_before`, `code_after` | 2 | CVEfixes (exact field names), LineVul 2022, CrossVul, BigVul, Devign, ReVeal, DiverseVul |
| Code quality | `language`, `loc_before`, `loc_after`, `syntax_valid`, `content_hash` | 5 | CrossVul, CVEfixes, BigVul, D2A (syntax filtering), DiverseVul (content-hash dedup) |
| Domain filters | `framework`, `has_taint_source`, `is_web_code` | 3 | Original contribution; motivated by ReVeal and Devign domain-filter patterns |
| Pipeline state | `pair_id`, `classifier_cwe`, `classifier_confidence`, `nvd_enriched`, `split` | 5 | LineVul (split), D2A (label source + confidence), CVEfixes (enrichment flags), CrossVul (pair linking) |
| **Total** | | **48** | |

---

## Fields That Are Original Contributions

Three fields in Group 7 do not have a direct counterpart in any surveyed dataset.
They are the original contribution of this schema and are justified on methodological
rather than precedent grounds:

| Field | Justification |
|---|---|
| `framework` | Flask-specific vulnerability patterns differ from Django/FastAPI patterns; required for Phase 6 which targets Flask; analogous to the domain filter implicit in ReVeal (Chromium only) and Devign (FFmpeg/QEMU/Linux/Wireshark only) |
| `has_taint_source` | Grounded in classical taint analysis methodology (the foundational method for web vulnerability detection); documents the cross-file taint limitation explicitly for dataset consumers |
| `is_web_code` | Makes the domain filter explicit that every focused vulnerability dataset applies implicitly; required because GitHub repositories contain both web-application code and library/test code |

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
