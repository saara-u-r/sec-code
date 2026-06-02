# Progress report — 2026-06-02

**Session focus:** make both papers presentation-ready. Add visual diagrams and per-subsection intros to the Elsevier draft, then stand up a second paper: a condensed IEEE conference version the professors requested.

**Session outcome:** two commits pushed to `origin/main`. The Elsevier paper gained four native TikZ/pgfplots figures (it previously had zero real diagrams) and orienting intros on the subsections that lacked them. A new self-contained `paper_ieee/` IEEE conference paper was written from scratch, condensed to 7 pages, em-dash-free, with a restructured limitations section. Both compile clean. **Work continues this afternoon** (push the IEEE paper to a full 8 pages and fill the author block).

---

## What landed (2 commits pushed to `origin/main`)

```
e1be5d7  Paper: add IEEE conference version (paper_ieee/)
47a4bc1  Paper: add TikZ diagrams and per-subsection intros to Elsevier draft
```

Pushed `c62b307..e1be5d7`; local `main` is up to date with origin.

---

## Elsevier paper (`paper/`) — diagrams + intros

The paper had **no visual diagrams** before today — every existing "figure" was a code listing. Added four native TikZ/pgfplots figures (no external image files, fully reproducible):

| Fig | Location | Content |
|---|---|---|
| 1 | `dataset.tex`, section open | 3-layer validation funnel: raw 1,982 → −749 → audit → −316 → 440+429=869, with audit FP 52%→51%→26% |
| 4 | `dataset.tex`, by Table 4 | Per-CWE FP-rate bar chart across the 3 audit rounds |
| 5 | `methodology.tex`, section open | Mutator taxonomy: 7 mutators → 3 families, † marks held-out probes |
| 13 | `evaluation.tex`, Setup | Harness architecture: benchmark → 4 detector tiers → 5 metrics |

- Added `tikz` + `pgfplots` to `main.tex`; full-width figures wrapped in `\resizebox` so they cannot overflow.
- Per-subsection intros: most subsections already opened with a topic sentence, so intros were added only to the four that jumped straight into a list/table/fact — **Scope and CWE selection**, **Final composition**, **Research questions**, **Setup**. Did not bolt boilerplate onto subsections that already had a lead-in.
- Commit also carries the dataset count corrections that were already in the working tree (869 = 440 positives + 429 safe; splits 610/127/132).
- Compiles clean: 0 overfull boxes, no undefined references. One TikZ bug found and fixed mid-session (mutator taxonomy family boxes overlapped the leaf boxes because they were positioned relative to leaf centers; re-anchored to leaf west edges).

---

## New IEEE conference paper (`paper_ieee/`)

Self-contained second paper built against the uploaded `IEEEtran` `[conference]` template.

**Setup**
- `paper_ieee/main.tex` (single file), local copy of `IEEEtran.cls`, `bib/references.bib` reused via BibTeX (`IEEEtran` bib style — verified installed). `.gitignore` mirrors `paper/` so build artifacts and the PDF stay untracked.
- Same title as the Elsevier paper; **placeholder author blocks** (to fill in).

**Content decisions**
- **Removed all seven mutator before/after code listings** (the space hogs); **kept** the compact taxonomy diagram as the section's single visual.
- Ported the pipeline, FP-progression, taxonomy, and harness figures.
- Tables: final composition, data sources, the 7-detector headline results (full width), per-CWE clean F1, robustness by variant, and robustness drop by family (with ΔSWR).
- **Em dashes: all 13 removed** (replaced with parentheses / colons / commas). En dashes in number ranges kept.
- **Limitations:** Threats section restructured into explicit construct / internal / external / conclusion validity subsections.

**Length**
- Grew 5 → **7 pages** with genuine content (data-sources table, per-family robustness table, LLM + trained-model analysis, label-confidence tiers, audit methodology, metrics rationale, positioning, design principles). Body fills through p.6; references fill ~70% of p.7.
- Compiles clean: 0 overfull boxes, all citations resolved, 0 em dashes.

---

## Decisions worth recording

- **Diagrams are native TikZ, not image files** — reproducible from source, no `figs/` dependency, survives a fresh checkout.
- **Intros added only where missing**, not uniformly — avoids the redundant "This subsection describes…" padding a reviewer would flag.
- **8-page target is a cap, not a quota.** The IEEE paper is a dense 7 pages under the 8-page limit. Pushing to a literal full 8 needs ~1.3 more pages and the substantive source content is exhausted; the remaining options (a real Discussion/Future-Work section, or professor-specified content) are an open decision for the afternoon rather than padding.
- **Template bundle left untracked** — `paper/IEEE_Conference_Template__1_.zip` and its folder are reference material; the only needed file (`IEEEtran.cls`) is copied into `paper_ieee/`.

---

## Carried to this afternoon

1. **IEEE paper to a full 8 pages** — pick the direction: add a genuine Discussion/Future-Work section (~0.7 page), or write professor-specified content. Avoid padding.
2. **Author/affiliation block** — fill in real names + RVCE details in `paper_ieee/main.tex`.
3. **Open question:** apply the em-dash cleanup to the Elsevier paper too (it was only done for the IEEE version).
4. **Open question:** whether to commit the IEEE template bundle for reproducibility.

---

## Repo health snapshot

```
$ git log --oneline -3
e1be5d7  Paper: add IEEE conference version (paper_ieee/)
47a4bc1  Paper: add TikZ diagrams and per-subsection intros to Elsevier draft
c62b307  Docs: progress report for 2026-05-28

$ git status (paper, paper_ieee)
clean except intentionally-untracked template bundle:
  paper/IEEE_Conference_Template__1_.zip
  paper/IEEE_Conference_Template__1_/
```

Both papers compile clean and all of today's source work is committed and pushed.
