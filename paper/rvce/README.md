# RVCE CSE Major Project Report — Scaffold

LaTeX scaffold for the college submission, built from the
**CSE-specific fork** [`nithya333/Major-Proj-Report-CS`](https://github.com/nithya333/Major-Proj-Report-CS)
of the upstream `rvce-latex/Project-Report-Template`. Compiles cleanly
out of the box — populated with placeholders that you replace before
the next professor review. The fork's own README is preserved as
[`TEMPLATE_README.md`](TEMPLATE_README.md).

## What's CSE-specific (vs the generic RVCE template)

- **9 chapters** instead of 6 — the textbook software-engineering flow:
  Intro → Theory → SRS → HLD → Detailed Design → Implementation →
  Software Testing → Experimental Results → Conclusion.
- **Cover page changes** — Dean CSE cluster, USN field on Declaration,
  signature tables, List of Publications front-matter page.
- **Pre-filled CSE defaults** — `Department = Computer Science and
  Engineering`, `HoD = Dr. Shanta Rangaswamy`, `DeanCS = Dr. Ramakanth Kumar P`.

## Build

```bash
cd paper/rvce
latexmk -pdf MajorProjectReport.tex      # produces MajorProjectReport.pdf
latexmk -C                               # clean build artifacts (see .gitignore)
```

## Placeholders to fill in (search for `TODO`)

All in [`MajorProjectReport.tex`](MajorProjectReport.tex):

| Placeholder | What to put |
|---|---|
| `\subCode{TODO Subject Code}` | Subject code from the CSE curriculum (e.g. `21CS84`). |
| `\stuNameA`, `\stuUSNA` | Your full name + USN. |
| `\guideNameA` block | Internal guide's name, designation. (Dept defaults to CSE already.) |
| `\guideNameB` block | External guide (currently commented out — uncomment if applicable). |
| `\panelMemberNameA/B` blocks | CSE department panel members. |
| `\projectCoOrdNameA/B` blocks | CSE department project co-ordinators. |

Already filled (verify before submission, but should be current):

- `\Department[CSE]{Computer Science and Engineering}`
- `\academicYear{2025-26}`
- `\HOD{Dr. Shanta Rangaswamy}` — current CSE HoD
- `\DeanCS{Dr. Ramakanth Kumar P}` — current Dean, School of CS
- `\Principal{Dr. K. N. Subramanya}`
- `\title{PyVulSev: A Benchmark for Adversarial Robustness in Python Vulnerability Detection}` — draft, adjust as the title evolves.

## Active chapters (CSE 9-chapter structure)

`MajorProjectReport.tex` `\input`s these files (the upstream `chapter1-Intro.tex` etc. are commented out and left in place for reference):

| # | File | Migrate from `paper/sections/*.tex` |
|---|---|---|
| 1 | `Chapter1/01_introduction.tex` | `introduction.tex` |
| 2 | `Chapter2/02_theory.tex` | `related_work.tex` (Lit Review / Theory) |
| 3 | `Chapter3/03_srs.tex` | NEW: derive SRS from the dataset spec + eval methodology |
| 4 | `Chapter4/04_hld.tex` | Architecture-level slice of `methodology.tex` |
| 5 | `Chapter5/05_detailed_design.tex` | `dataset.tex` + mutator design from `methodology.tex` |
| 6 | `Chapter6/06_implementation.tex` | Implementation slice of `methodology.tex` + eval-harness code |
| 7 | `Chapter7/07_SoftwareTesting.tex` | NEW: derive from `tests/` + audit reports under `docs/audits/` |
| 8 | `Chapter8/08_ExpResults.tex` | `evaluation.tex` |
| 9 | `Chapter9/09_Conclusion.tex` | `conclusion.tex` + `threats.tex` |

**The 9-chapter structure adds three sections** (SRS, HLD, Software Testing) that don't exist in the academic-paper format. These need to be written from scratch — the academic paper merges those concerns into its methodology and threats-to-validity sections. Reusing the existing audit reports (`docs/audits/BENCHMARK_AUDIT_*`) is the natural input for Chapter 7.

## Cover pages

[`CoverPages/`](CoverPages/) — `Certificate`, `Declaration`, `Ack`, `Abstract`, `Publications` still have the template's sample content. Rewrite once the project's contributions stabilise. The Declaration page on the CSE fork now includes a USN field.

## Bibliography

`AuxFiles/ProjectBib.bib` — empty stub. The academic paper's `paper/bib/references.bib` should be copied in once entries are finalised; the template uses IEEE style via `biblatex`.

## After the professor's feedback

The scaffold compiles in this repo, so we can iterate on content without fighting the build. Style nitpicks (margins, fonts, table formatting) live in [`ecproject.sty`](ecproject.sty) and [`AuxFiles/Packages.tex`](AuxFiles/Packages.tex) — adjustable without touching content. Wait for specifics before tweaking.
