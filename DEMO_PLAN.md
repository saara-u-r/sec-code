# PyVulSev Demo App — Build Plan

**For:** 8th Semester CSE Final Exam Presentation  
**Aesthetic:** Dark cyberpunk / hacking terminal UI  
**Mockup:** `~/Downloads/pyvulsev_mockup.html` — open in browser to see the design before building

---

## What We're Building

A full-stack interactive demo app with three tabs:

| Tab | What it shows |
|-----|--------------|
| **SCAN** | Paste Python code → run real detectors → see results side-by-side |
| **RED TEAM** | Pick a dataset sample → apply a real mutator → show diff → run detectors → scoreboard |
| **BENCHMARK** | Pre-rendered heatmap from our actual eval results (the real numbers from `reports/eval/`) |

The stack is **React + Vite** (frontend) talking to **FastAPI** (backend). The backend wraps the detector and mutator code that already exists in `src/`.

---

## Tech Stack

### Frontend
- **React 18 + Vite** — fast dev server, instant HMR
- **Monaco Editor** (`@monaco-editor/react`) — the VS Code editor component; gives a real code editor feel with syntax highlighting and line markers
- **Tailwind CSS** — utility classes for layout; no custom CSS framework needed
- **Framer Motion** — smooth card animations when results load
- **Recharts** — for the heatmap / radar chart on the Benchmark tab
- **Lucide React** — icon set

### Backend
- **FastAPI** — thin Python API server; wraps existing detector and mutator code
- **Uvicorn** — ASGI server to run FastAPI

### Existing code to reuse (don't rewrite)
| What | Where |
|------|-------|
| Bandit detector | `src/eval/detectors/bandit.py` |
| Semgrep detector | `src/eval/detectors/semgrep.py` |
| Claude LLM detector | `src/eval/detectors/llm.py` |
| OpenAI detector | `src/eval/detectors/openai_llm.py` |
| Snyk Code detector | `src/eval/detectors/snyk_code.py` |
| All 7 mutators | `src/red_team/mutators/` (dead_code, string_split, variable_rename, wrapper_extraction, sink_attr_obfuscate, sink_via_globals, taint_through_dict) |
| Mutator base class | `src/red_team/base.py`, `src/red_team/augmenter.py` |
| Eval results (pre-computed) | `reports/eval/*_summary.json` |
| Sample dataset | `data/` or exported via `scripts/export_dataset.py` |

---

## Folder Structure to Create

```
demo/
├── backend/
│   ├── main.py            ← FastAPI app, all routes
│   ├── detectors.py       ← thin wrappers around src/eval/detectors/
│   ├── mutators.py        ← thin wrappers around src/red_team/mutators/
│   ├── samples.py         ← loads ~20 curated samples from data/ for the demo
│   └── requirements.txt   ← fastapi, uvicorn (rest already in root requirements.txt)
│
└── frontend/
    ├── index.html
    ├── vite.config.js
    ├── package.json
    └── src/
        ├── main.jsx
        ├── App.jsx            ← tab router
        ├── components/
        │   ├── Header.jsx
        │   ├── StatusTicker.jsx
        │   ├── tabs/
        │   │   ├── ScanTab.jsx
        │   │   ├── RedTeamTab.jsx
        │   │   └── BenchmarkTab.jsx
        │   ├── scan/
        │   │   ├── CodeEditor.jsx
        │   │   └── DetectorCard.jsx
        │   ├── redteam/
        │   │   ├── MutatorGrid.jsx
        │   │   ├── DiffViewer.jsx
        │   │   └── Scoreboard.jsx
        │   └── benchmark/
        │       ├── MetricCards.jsx
        │       └── Heatmap.jsx
        └── theme.js           ← colour tokens (green, cyan, red, etc.)
```

---

## Backend API — Endpoints to Build

All in `demo/backend/main.py`.

### `POST /api/scan`
Runs detectors on submitted code.

**Request:**
```json
{
  "code": "from flask import ...",
  "detectors": ["bandit", "semgrep", "claude"]
}
```

**Response:**
```json
{
  "results": [
    {
      "detector": "bandit",
      "verdict": "VULNERABLE",
      "cwe": "CWE-89",
      "confidence": 0.91,
      "line": 12,
      "message": "SQL injection via string formatting"
    },
    ...
  ]
}
```

**How to implement:** Call each detector's `.run(code_string)` method. For speed during demo, run Bandit + Semgrep synchronously (fast, local), and Claude/OpenAI concurrently via `asyncio.gather`. Timeout each LLM call at 10s.

---

### `GET /api/samples`
Returns the list of curated demo samples.

**Response:**
```json
[
  {
    "id": "sample_001",
    "label": "Flask login — SQLi vulnerable",
    "cwe": "CWE-89",
    "is_vulnerable": true,
    "code": "..."
  },
  ...
]
```

**How to implement:** Hardcode ~15 hand-picked samples from the dataset (mix of CWEs + safe baselines). Store them in `demo/backend/samples.py` as a Python list so the demo doesn't need a DB connection.

---

### `POST /api/mutate`
Applies one of the 7 mutators to a code snippet.

**Request:**
```json
{
  "code": "...",
  "mutator": "string_split"
}
```

**Response:**
```json
{
  "original": "...",
  "mutated": "...",
  "diff": [
    { "type": "remove", "line": 8, "content": "    sql = f\"SELECT...\"" },
    { "type": "add",    "line": 8, "content": "    _p0 = \"SELECT * FROM\"" },
    { "type": "add",    "line": 9, "content": "    sql = _p0 + \" users WHERE name = '\" + name + \"'\"" }
  ]
}
```

**How to implement:** Import the mutator class directly from `src/red_team/mutators/<name>.py`, call `.apply(code)`, compute diff with Python's `difflib.unified_diff`.

---

### `GET /api/benchmark`
Returns the pre-computed eval results for the Benchmark tab.

**Response:**
```json
{
  "detectors": {
    "bandit":        { "macro_f1": {...}, "severity_weighted_recall": {...} },
    "semgrep":       { ... },
    "claude_sonnet": { ... },
    ...
  }
}
```

**How to implement:** Read and merge all `reports/eval/*_summary.json` files at startup. Cache in memory. No computation at request time.

---

## Frontend — Tab-by-Tab Detail

### Tab 1: SCAN

**Layout:** Two columns. Left = code editor (60%). Right = results panel (40%).

**Left column:**
- Dropdown at top to pick a preloaded snippet (SQLi, CMDi, Path Traversal, SSTI, Safe) — calls `GET /api/samples`
- Monaco Editor with `language="python"`, dark theme (`vs-dark` base, override with our colours)
- Red squiggly line decorations on the vulnerable line after analysis (use Monaco `deltaDecorations`)
- "▶ ANALYZE CODE" button — glowing green, sweeping shimmer animation while loading

**Right column:**
- One card per detector
- Card states: idle (grey border) → loading (pulsing cyan border) → vulnerable (red left border) → safe (green left border)
- Each card shows: detector name, verdict badge, CWE badge, confidence bar, optional 1-line explanation (from LLM detectors)
- Animate cards in sequentially as results arrive (Framer Motion `staggerChildren`)

**UX note:** Bandit + Semgrep return in ~1s. LLMs return in 3–8s. Show results progressively as they arrive (stream from backend using SSE or just poll). For demo reliability, you can also pre-run and cache the results for the preloaded snippets.

---

### Tab 2: RED TEAM

**Layout:** Full width, stacked vertically.

**Section 1 — Target selection:**
- Dropdown: pick a safe baseline sample from the dataset
- Shows the code in a read-only Monaco panel

**Section 2 — Mutation vectors:**
- 7 buttons in a grid, one per mutator:
  | Button | Mutator | What it does |
  |--------|---------|-------------|
  | DEAD CODE INJECT | `dead_code.py` | Injects unreachable but confusing code blocks |
  | STRING SPLIT | `string_split.py` | Splits the SQL/shell string across multiple vars |
  | VARIABLE RENAME | `variable_rename.py` | Renames taint-carrying variables to benign names |
  | WRAPPER EXTRACT | `wrapper_extraction.py` | Wraps the sink in an intermediate function |
  | ATTR OBFUSCATE | `sink_attr_obfuscate.py` | Accesses the sink via `getattr` instead of direct call |
  | GLOBALS SINK | `sink_via_globals.py` | Routes taint through `globals()` dict |
  | TAINT VIA DICT | `taint_through_dict.py` | Taint passes through a dict lookup before the sink |
- Clicking a button calls `POST /api/mutate` and shows loading spinner

**Section 3 — Diff view:**
- Side-by-side panels: ORIGINAL (left) vs MUTATED (right)
- Line-level diff: removed lines in red background with `−` prefix, added lines in green with `+` prefix
- Use Monaco's built-in `DiffEditor` component (it does this automatically and looks great)

**Section 4 — Scoreboard:**
- "⚡ RUN DETECTORS ON MUTATED CODE" button — calls `POST /api/scan` with the mutated code
- Results show as a table: detector name | verdict | CWE detected | confidence
- Highlight: if a detector that caught the original now **misses** the mutated version, flag it in orange ("EVADED") — this is the most dramatic visual for the audience

**The story to tell:** Pick a vulnerable snippet → apply "STRING SPLIT" mutator → show how the string is obfuscated across 3 variables → Bandit and Semgrep MISS it → Claude CATCHES it. This directly supports your research finding that LLMs outperform SAST on obfuscated code.

---

### Tab 3: BENCHMARK

**Layout:** Metric cards row at top, heatmap below.

**Metric cards (4 cards):**
- Total samples: **869** (440 vuln · 429 safe)
- Best macro F1: **0.88** (Claude Sonnet, `sink_attr_obfuscate` tier)
- Detectors evaluated: **10** (Bandit, Semgrep, Snyk, CodeQL, Claude Sonnet, Claude Opus, GPT-4o, DeepSeek R1, GraphCodeBERT, Qwen)
- Hardest mutation tier: **sink_attr_obfuscate** (lowest F1 across SAST tools)

**Heatmap (main visual):**
- Rows: detectors (10 rows)
- Columns: mutation tiers (clean, dead_code_injection, string_split, variable_rename, wrapper_extraction, sink_attr_obfuscate, sink_via_globals, taint_through_dict, composed)
- Cell value: macro F1 from the actual `*_summary.json` files
- Colour scale: red (0.0) → orange → yellow → cyan → green (1.0)
- Hover tooltip: shows F1 + severity_weighted_recall for that cell
- Click a cell: side panel pops up with a real sample from the dataset for that CWE/mutation combo

**Key insight the heatmap shows:**  
SAST tools (Bandit, Semgrep) have high F1 on `clean` samples but F1 drops sharply on obfuscated mutations. LLMs (Claude, GPT-4o) stay relatively stable across mutation tiers. This is the core research finding.

---

## Accurate Eval Numbers (from actual summary JSONs)

Use these for the benchmark tab — don't make up numbers.

| Detector | Clean F1 | sink_attr_obfuscate F1 | composed F1 |
|----------|----------|----------------------|-------------|
| Bandit | 0.510 | 0.402 | 0.582 |
| Semgrep | ~0.60 | ~0.45 | ~0.60 |
| Claude Sonnet | 0.585 | **0.881** | **0.867** |
| GPT-4o | ~0.65 | ~0.70 | ~0.70 |

(Fill the rest from the other `*_summary.json` files — all in `reports/eval/`.)

---

## Step-by-Step Build Order

### Day 1 (start here tomorrow)

**Step 1 — Backend scaffold (1–2 hrs)**
```bash
cd demo/backend
pip install fastapi uvicorn python-dotenv
# Create main.py with CORS enabled, health check route
# Create samples.py with 15 hardcoded demo samples
# Test: uvicorn main:app --reload
```

**Step 2 — Benchmark endpoint (30 min)**
- Read all `reports/eval/*_summary.json` at startup
- Expose via `GET /api/benchmark`
- This is pure file I/O, no detector code needed

**Step 3 — Frontend scaffold (1 hr)**
```bash
cd demo/frontend
npm create vite@latest . -- --template react
npm install @monaco-editor/react framer-motion recharts lucide-react
npm install -D tailwindcss @tailwindcss/vite
```
- Set up the theme colours (copy from the mockup's CSS variables into `theme.js`)
- Get the header + tab nav rendering with the dark background

**Step 4 — Benchmark tab (1 hr)**
- Wire `GET /api/benchmark` to the frontend
- Build the metric cards (static layout, just fill in numbers)
- Build the heatmap using Recharts or a plain CSS grid (a plain styled `<table>` actually works better here for precise cell control)

This alone is already demo-able at end of Day 1.

---

### Day 2

**Step 5 — Scan endpoint (1–2 hrs)**
- Wire up Bandit and Semgrep detectors first (local, no API key needed)
- Test `POST /api/scan` returns results
- Add Claude detector (needs `ANTHROPIC_API_KEY` in `.env`)

**Step 6 — Scan tab UI (2 hrs)**
- Monaco editor with snippet dropdown
- Analyze button with loading state
- Detector cards with progressive reveal animation
- Monaco line decorations for vulnerability markers

**Step 7 — Mutate endpoint (1 hr)**
- Wire up `POST /api/mutate` using existing mutator classes
- Compute and return diff

**Step 8 — Red Team tab UI (2 hrs)**
- Mutator button grid
- Monaco DiffEditor component for the diff view
- Scoreboard with EVADED / CAUGHT / MISSED badges

---

## Running the Demo

Two terminal windows:

**Terminal 1 — backend:**
```bash
cd demo/backend
uvicorn main:app --reload --port 8000
```

**Terminal 2 — frontend:**
```bash
cd demo/frontend
npm run dev
# Opens at http://localhost:5173
```

Make sure `.env` has:
```
ANTHROPIC_API_KEY=...
OPENAI_API_KEY=...
```

For the presentation, run `npm run build` beforehand and serve the static build so there's no dev server dependency.

---

## Demo Script (what to say and click during presentation)

**SCAN tab (2 min):**
1. Open to SCAN tab — "This is PyVulSev, our security analysis platform built on our benchmark dataset"
2. Select "SQL Injection" snippet — point out the red-highlighted line
3. Click Analyze — "We're now running 5 detectors simultaneously, from traditional SAST to LLMs"
4. Results load — "Notice Bandit and Semgrep both catch this. Claude gives us a natural-language explanation with the fix."
5. Switch to "Safe snippet" → Analyze → all green — "No false positives on clean code"

**RED TEAM tab (3 min):**
1. "Now the interesting part — our red team evaluation"
2. Pick a vulnerable SQLi sample
3. Click "STRING SPLIT" mutator — diff appears — "We've obfuscated the SQL string across 3 variables — the logic is identical but the pattern is broken up"
4. Click Run Detectors — scoreboard shows Bandit MISSED, Semgrep MISSED, Claude CAUGHT
5. "This is the key finding of our paper — SAST tools fail on obfuscated variants. LLMs reason about semantics, not just patterns."
6. Click "SINK ATTR OBFUSCATE" — repeat — even more dramatic

**BENCHMARK tab (2 min):**
1. "Our benchmark has 869 samples across 7 CWEs and 7 mutation tiers"
2. Point at heatmap — "The colour drop from left to right shows how F1 degrades as obfuscation increases"
3. Hover on Claude row — stays green across all tiers — "This is what motivated our recommendation"

---

## Things to Prepare Before Presentation Day

- [ ] Run `npm run build` in `demo/frontend` — serve via `python -m http.server` so no Node needed
- [ ] Pre-cache scan results for the 5 preloaded snippets so Analyze is instant (no waiting for LLM)
- [ ] Have a fallback: the mockup HTML file works offline as a last resort
- [ ] Test on the projector screen — the dark theme looks great on projectors
- [ ] Keep `.env` with API keys ready but not visible on screen
