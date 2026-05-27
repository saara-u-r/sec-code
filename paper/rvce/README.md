# RVCE Major Project Report — Scaffold

LaTeX scaffold for the college submission, built from the
[`rvce-latex/Project-Report-Template`](https://github.com/rvce-latex/Project-Report-Template)
(Major Project variant). Compiles cleanly out of the box — populated
with placeholders that you replace before the next professor review.
The upstream template's own README is kept as
[`TEMPLATE_README.md`](TEMPLATE_README.md).

## Build

```bash
cd paper/rvce
latexmk -pdf MajorProjectReport.tex      # produces MajorProjectReport.pdf
latexmk -C                               # clean build artifacts (see .gitignore)
```

Two harmless warnings on first build (`name{glo:rc}` / `name{glo:ic}` undefined glossary refs) come from the template's example chapter content and disappear once the chapter stubs are replaced.

## Placeholders to fill in (search for `TODO`)

All in [`MajorProjectReport.tex`](MajorProjectReport.tex):

| Placeholder | What to put |
|---|---|
| `\subCode{TODO Subject Code}` | Subject code from the curriculum (e.g. `21CS84`). |
| `\Department[TODO]{TODO ...}` | Your branch: short form in `[]` (e.g. `CSE`), full name in `{}` (e.g. `Computer Science and Engineering`). |
| `\stuNameA`, `\stuUSNA` | Your full name + USN. `\stuNameB`–`F` already commented for a solo project. |
| `\guideNameA` block | Internal guide's name, designation, dept, organisation. |
| `\guideNameB` block | External guide (only if you have one — currently commented out). |
| `\panelMemberNameA/B` blocks | Department panel members. |
| `\projectCoOrdNameA/B` blocks | Department project co-ordinators. |
| `\HOD{TODO HoD Name}` | Current Head of Department for your branch. |

Defaults already filled (verify they're still current before submission):

- `\Principal{Dr. K. N. Subramanya}` — Principal, RVCE
- `\DeanAcademics{Dr. M.V. Renukadevi}`
- `\VicePrincipal{Dr. Geetha K S}`
- `\academicYear{2025-26}`
- `\title{PyVulSev: A Benchmark for Adversarial Robustness in Python Vulnerability Detection}` — adjust as the title evolves.

## What's intentionally left untouched

- **Chapter content** ([`Chapter1`](Chapter1/)–[`Chapter6`](Chapter6/)) still has the template's sample text. The plan is to migrate the existing Elsevier-format paper sections (`paper/sections/*.tex`) into these chapters *after* the professor's structural feedback is incorporated:

  | RVCE chapter | Source |
  |---|---|
  | `Chapter1/chapter1-Intro.tex` | `paper/sections/introduction.tex` |
  | `Chapter2/chapter2-Funda.tex` | `paper/sections/related_work.tex` (Literature Review) |
  | `Chapter3/chapter3-design.tex` | `paper/sections/dataset.tex` + dataset-side of `methodology.tex` |
  | `Chapter4/chapter4-implement.tex` | `paper/sections/methodology.tex` (adversarial mutators, eval framework) |
  | `Chapter5/chapter5-result.tex` | `paper/sections/evaluation.tex` |
  | `Chapter6/chapter6-conclution.tex` | `paper/sections/conclusion.tex` + `paper/sections/threats.tex` |

- **Cover pages** ([`CoverPages/`](CoverPages/)) — Certificate, Declaration, Acknowledgement, Abstract still hold the template's sample content. Rewrite once the project's contributions stabilise.

- **Bibliography** (`AuxFiles/ProjectBib.bib`) — empty stub. The academic paper's `paper/bib/references.bib` should be copied in once entries are finalised; the template uses IEEE style via `biblatex`.

## After the professor's feedback

The template is now confirmed to compile in this repo. The professor's style nitpicks (margins, fonts, table formatting) live in [`ecproject.sty`](ecproject.sty) and [`AuxFiles/Packages.tex`](AuxFiles/Packages.tex) — adjustable without touching content. Wait for specifics before tweaking.
