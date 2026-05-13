# Structural Top-25 Python CWEs — Out of Scope for the Sink-Anchored Benchmark

**Date:** 2026-05-13
**Status:** Reference document. No code or scraping changes implied — this is the writeup-ready justification for the scope choice.

---

## TL;DR

Of the 25 MITRE Top-25 CWEs (2024 list), 16 are Python-relevant. We split those 16 into two methodological categories:

1. **Sink-shaped (9)** — the vulnerability is a misuse of a specific sink call (`cursor.execute(f"...")`, `os.system(...)`, `pickle.loads(...)`, etc.). The fix replaces the unsafe pattern with one of a small alphabet of safe alternatives. **In scope for our benchmark.**

2. **Structural (7)** — the vulnerability is the *absence* of a check (`@login_required`, ownership filter, CSRF token, etc.). There is no sink to pattern-match against. **Deferred — out of scope for the sink-anchored benchmark.**

This document captures the analysis for the 7 deferred CWEs so a paper section can cite it directly.

---

## Why we split this way

The benchmark methodology has three pillars:

1. **Sink-presence quality filter.** Every labeled positive must contain a sink that defines the CWE (`pickle.loads(` for CWE-502, `request.files` for CWE-434, etc.). This filters out commit-level mislabel noise (38–87% rejection across sources in our audit). The filter *requires* a sink token to anchor on.

2. **Closed fix-pattern alphabet.** Sink-shaped CWEs admit a small set of safe alternatives ("parameterized query," "use `shlex.quote`," "use `yaml.safe_load`"). This makes per-tool detection unambiguous — either the tool flags the unsafe sink form or it doesn't.

3. **Four-mutator robustness probe.** `dead_code_injection`, `string_split`, `variable_rename`, `wrapper_extraction` — all four operate on the syntactic form of code around a sink. They have no semantics for *absent* code.

All three pillars assume a sink. Structural CWEs invalidate all three.

---

## The 7 deferred structural CWEs

For each, we describe (a) the canonical fix pattern, (b) why it's not sink-shaped, and (c) what "verification metadata" detection would require.

### CWE-352 — Cross-Site Request Forgery (CSRF)

**The vulnerability:** A state-changing HTTP endpoint accepts a request without verifying the request originated from the user's own session.

**The canonical fix:**
- Django: middleware enforces CSRF token; views opt out via `@csrf_exempt` (which is then the vulnerability marker, but inverted).
- Flask: `flask-wtf`'s `CSRFProtect` decorator on the app + `{{ csrf_token() }}` in templates.
- FastAPI: middleware or `Depends(verify_csrf_token)` per route.

**Why it's not sink-shaped:** The "vulnerable" code is a normal POST handler with no syntactic marker distinguishing it from a safe one. The defense is configuration / middleware / decorator — not a call replacement.

**What detection would require:**
- Project-level analysis (does CSRF middleware exist? on which routes?)
- Inter-file analysis (is the form template emitting a token?)
- Configuration parsing (Django `MIDDLEWARE` setting, Flask app config)

This is **architecture-level**, not pattern-level. Out of scope for a file-level sink benchmark.

---

### CWE-862 — Missing Authorization

**The vulnerability:** A view performs a privileged operation without checking the requester is authorized.

**The canonical fix:**
- Django: `@permission_required('app.add_thing')`, `PermissionRequiredMixin`, or in-body `if not request.user.has_perm(...): return 403`.
- Flask: `@login_required` + role check, `flask-principal` permissions, or in-body `if not g.user.is_admin: abort(403)`.
- FastAPI: `Depends(require_admin)` on the route.

**Why it's not sink-shaped:** There is no "sink." The unsafe code is the *absence* of a check between the handler signature and the privileged operation. The same Python construct (no decorator) is correct for public endpoints and incorrect for privileged ones.

**What detection would require:**
- Application semantics: which endpoints handle privileged operations?
- Route → role taxonomy: is `/admin/users/delete` supposed to require admin?
- Cross-route consistency: if `/api/post/edit` checks ownership and `/api/post/delete` doesn't, the inconsistency is the bug.

This is a **specification-conformance** problem, not a syntactic one.

---

### CWE-863 — Incorrect Authorization

**The vulnerability:** An authorization check is performed but is wrong — wrong role, wrong scope, wrong subject.

**The canonical fix:** Check the *right* thing. E.g., `if obj.owner == request.user` instead of `if request.user.is_authenticated`.

**Why it's not sink-shaped:** The unsafe pattern is `if some_check: do_thing()`. The safe pattern is `if correct_check: do_thing()`. Both look identical structurally; the difference is whether `some_check` is *semantically* the right check for the operation.

**What detection would require:**
- Domain knowledge: what's the right authorization for this operation?
- Semantic parsing of conditional expressions
- Tracking object ownership vs. user attributes

Even modern LLMs struggle with CWE-863 — there's nothing to detect without project context.

---

### CWE-284 — Improper Access Control (umbrella)

The MITRE parent class for CWE-862 / 863 / 639 and other access-control failures. By construction, any sample tagged CWE-284 is more usefully labeled as one of its children. Out of scope by the same arguments above.

---

### CWE-306 — Missing Authentication for a Critical Function

**The vulnerability:** A privileged route lacks an authentication decorator entirely (not just authorization — authentication, the lower bar).

**The canonical fix:**
- Django: `@login_required`.
- Flask: `@login_required` from `flask-login` or `flask-security`.
- FastAPI: `Depends(get_current_user)`.

**Why it's not sink-shaped:** Same shape as CWE-862 — absence of a decorator. The route handler body is unremarkable.

**What detection would require:** Same as CWE-862, plus a list of which routes count as "critical functions."

---

### CWE-639 — Authorization Bypass Through User-Controlled Key (IDOR)

**The vulnerability:** A view fetches an object by a user-supplied primary key without verifying the user is allowed to access *that specific object*.

```python
# Vulnerable — any logged-in user can read any other user's invoice
def get_invoice(request, invoice_id):
    invoice = Invoice.objects.get(pk=invoice_id)
    return render(request, 'invoice.html', {'invoice': invoice})

# Safe — ownership scoped
def get_invoice(request, invoice_id):
    invoice = Invoice.objects.get(pk=invoice_id, customer=request.user)
    return render(request, 'invoice.html', {'invoice': invoice})
```

**The partial sink-shape:** `Model.objects.get(pk=...)` is a sink. The unsafe vs. safe variants differ only in the presence of an extra keyword argument (`customer=request.user`). A regex pattern like `Model\.objects\.(get|filter)\(.*request\.(GET|POST)` *could* anchor a detection.

**But the alphabet doesn't close:**
- "Add a `WHERE user_id = ?` clause" is the safe pattern — but the user attribute might be `customer`, `tenant_id`, `account`, `owned_by`, etc.
- Some objects are scoped via a many-to-many (`request.user.organizations.filter(...)`), not a direct foreign key.
- The "right" check is *application-specific* (which model has which ownership relation).

**Status:** Borderline. Could be revived in Phase 2C with a relaxed alphabet definition. Excluded from Phase 2B because the alphabet would have to enumerate every Django/SQLAlchemy ownership pattern.

---

### CWE-200 — Exposure of Sensitive Information

**The vulnerability:** Sensitive data (password, token, internal IP, stack trace) reaches an output sink (response body, log, error page).

**Partial sink-shape:**
- `logger.info(password)`, `print(api_token)`, `HttpResponse(secret)` — these *are* sinks (`logger.`, `print(`, `HttpResponse(`). Pattern: any output-sink call with a sensitive-keyword argument within proximity.
- DRF serializer with `fields = '__all__'` exposing a `password_hash` column — *structural* (absence of `exclude`).
- Django model `__repr__` printing all attrs — *structural*.
- Exception handler returning `repr(exc)` to the user — borderline sink (the `return repr(exc)` is detectable but only meaningful with knowledge of what the exception type carries).

**Status:** **Hybrid.** Could split into:
- CWE-200a (sink-shaped): output-sink with sensitive-keyword proximity — fits the benchmark methodology
- CWE-200b (structural): serializer/repr/exception-handler patterns — out of scope

For Phase 2B we defer entirely. The sink-shaped subset could be added in Phase 2C as a 10th sink-shaped CWE.

---

## What "verification metadata" would look like (if we ever build it)

The instinct in the original conversation was correct: structural CWEs can be *partially* validated by checking whether a fix commit *added* a check (rather than modifying an existing sink). A concrete schema:

```json
{
  "cwe": "CWE-862",
  "verification": {
    "added_decorators":    ["login_required", "permission_required"],
    "added_imports":       ["from django.contrib.auth.decorators import login_required"],
    "added_conditionals":  ["if not request.user.has_perm(...)"],
    "removed_decorators":  ["csrf_exempt"]
  }
}
```

A fix commit that adds `@permission_required('foo.bar')` to a view is *evidence* the view was previously CWE-862 — but the detector still can't tell which routes need such a decorator on a code snapshot.

**This data would be useful for:**
- Studying patch shape (descriptive statistics)
- Training a "what kind of check is missing here?" model (requires labeled training data)
- Building a Phase 2C structural-CWE evaluation track

**It would NOT be useful for the sink-anchored benchmark methodology.** Including verification-metadata in the Phase 2B dataset would muddy the scope without enabling new detection.

---

## Recommendation for the paper

Include a short subsection — title suggestion: *"Sink-shaped vs structural CWEs: a methodology-driven scope"* — that says:

> The MITRE Top-25 contains 16 Python-relevant CWEs. We classify them by detection methodology: nine admit a sink-shaped fix-pattern alphabet (our benchmark), seven are structural (deferred to future work). The sink-shaped subset is where existing static-analysis and pattern-based approaches are meaningful to evaluate; the structural subset requires application-aware analysis (project-level taint, configuration parsing, ownership taxonomy) that is out of scope for a file-level evaluation framework. We discuss this distinction in §6.2 and propose verification-metadata as the right substrate for a structural-CWE benchmark in §7.

This frames the scope choice as a methodological contribution rather than a limitation.
