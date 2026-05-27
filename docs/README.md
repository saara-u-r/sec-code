# docs/

All project documentation, organized by purpose. Code output (eval
predictions, logs, health reports) lives under `reports/`, not here.

| Directory | Contents |
|---|---|
| [`progress/`](progress/) | Dated progress reports — one per work session or phase milestone. |
| [`audits/`](audits/) | Benchmark audits (`BENCHMARK_AUDIT_*`), versioned as the dataset rev'd. |
| [`design/`](design/) | Phase design docs, rescopes, deferral decisions, open questions. |
| [`reference/`](reference/) | Methodology, surveys, schema, guides — the load-bearing reference set. |
| [`training/`](training/) | Training-infrastructure handoffs (GPU, JupyterLab, Kaggle). |

## Where to start

- **New to the project:** [`reference/MOTIVATION_REPORT.md`](reference/MOTIVATION_REPORT.md) → [`reference/PROJECT_STRUCTURE.md`](reference/PROJECT_STRUCTURE.md).
- **Running the eval harness:** [`reference/EVALUATION_GUIDE.md`](reference/EVALUATION_GUIDE.md), grounded in [`reference/EVALUATION_METHODOLOGY.md`](reference/EVALUATION_METHODOLOGY.md).
- **Latest status:** the most recent file in [`progress/`](progress/).
- **Why fields are shaped the way they are:** [`reference/FIELD_JUSTIFICATION.md`](reference/FIELD_JUSTIFICATION.md), [`reference/DATASET_SCHEMA.md`](reference/DATASET_SCHEMA.md).
