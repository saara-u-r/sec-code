"""
test_rules.py — tests for the three concrete sanitization rules.

Contract per rule:
  1. ``applies_to`` returns True iff the vulnerable pattern is present
  2. ``sanitize`` produces a tree that round-trips
  3. The output no longer contains the vulnerable pattern
  4. Required imports are added (and not duplicated)
  5. Function semantics are preserved on safe inputs
  6. The output differs from the input
"""

from __future__ import annotations

import ast
import random

import pytest

from src.red_team.sanitization import sanitize
from src.red_team.sanitization.rules.cwe79_xss import (
    MarkupToEscape,
    WrapRenderTemplateStringWithEscape,
)
from src.red_team.sanitization.rules.cwe94_codei import EvalToLiteralEval
from src.red_team.sanitization.rules.cwe502_deser import (
    PickleToJsonLoads,
    YamlLoadToSafeLoad,
)


# ---------------------------------------------------------------------------
# CWE-94: eval → ast.literal_eval
# ---------------------------------------------------------------------------

class TestCWE94:
    rule = EvalToLiteralEval()

    def test_applies_to_eval(self):
        tree = ast.parse("def f(s): return eval(s)")
        assert self.rule.applies_to(tree)

    def test_applies_to_exec(self):
        tree = ast.parse("def f(s): exec(s)")
        assert self.rule.applies_to(tree)

    def test_does_not_apply_to_safe_code(self):
        tree = ast.parse("def f(s): return int(s)")
        assert not self.rule.applies_to(tree)

    def test_sanitize_replaces_eval(self):
        src = "def f(s):\n    return eval(s)\n"
        out, result = sanitize(src, "CWE-94", random.Random(0))
        assert result.success
        # Verify via AST: no bare `eval` Name calls remain
        tree = ast.parse(out)
        bare_evals = [
            c for c in ast.walk(tree)
            if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Name)
            and c.func.id in {"eval", "exec"}
        ]
        assert len(bare_evals) == 0
        assert "ast.literal_eval(" in out
        assert "import ast" in out

    def test_sanitize_round_trips(self):
        src = "def f(s):\n    return eval(s)\n"
        out, _ = sanitize(src, "CWE-94", random.Random(0))
        ast.parse(out)  # raises if invalid

    def test_runtime_behavior_on_literal_input(self):
        """``eval`` and ``ast.literal_eval`` agree on literal inputs."""
        src = "def f(s):\n    return eval(s)\n"
        out, _ = sanitize(src, "CWE-94", random.Random(0))
        ns: dict = {}
        exec(out, ns)
        assert ns["f"]("[1, 2, 3]") == [1, 2, 3]
        assert ns["f"]("'hello'") == "hello"
        assert ns["f"]("42") == 42


# ---------------------------------------------------------------------------
# CWE-502: yaml.load → yaml.safe_load
# ---------------------------------------------------------------------------

class TestCWE502YamlLoad:
    rule = YamlLoadToSafeLoad()

    def test_applies_to_yaml_load(self):
        tree = ast.parse("import yaml\ndef f(s): return yaml.load(s)")
        assert self.rule.applies_to(tree)

    def test_applies_to_yaml_unsafe_load(self):
        tree = ast.parse("import yaml\ndef f(s): return yaml.unsafe_load(s)")
        assert self.rule.applies_to(tree)

    def test_does_not_apply_when_already_safe(self):
        tree = ast.parse("import yaml\ndef f(s): return yaml.safe_load(s)")
        assert not self.rule.applies_to(tree)

    def test_sanitize_replaces_with_safe_load(self):
        src = "import yaml\ndef f(s):\n    return yaml.load(s)\n"
        out, result = sanitize(src, "CWE-502", random.Random(0))
        assert result.success
        # The token "yaml.load(" should not appear; "yaml.safe_load(" should
        assert "yaml.load(" not in out
        assert "yaml.safe_load(" in out

    def test_drops_loader_kwarg(self):
        """yaml.load(s, Loader=Loader) → yaml.safe_load(s) (no Loader=)."""
        src = (
            "import yaml\n"
            "def f(s):\n"
            "    return yaml.load(s, Loader=yaml.Loader)\n"
        )
        out, result = sanitize(src, "CWE-502", random.Random(0))
        # Force pickle_to_json rule to NOT match — only yaml rule applies here
        assert result.success
        assert "Loader=" not in out


# ---------------------------------------------------------------------------
# CWE-502: pickle.loads → json.loads
# ---------------------------------------------------------------------------

class TestCWE502PickleLoads:
    rule = PickleToJsonLoads()

    def test_applies_to_pickle_loads(self):
        tree = ast.parse("import pickle\ndef f(b): return pickle.loads(b)")
        assert self.rule.applies_to(tree)

    def test_applies_to_marshal_loads(self):
        tree = ast.parse("import marshal\ndef f(b): return marshal.loads(b)")
        assert self.rule.applies_to(tree)

    def test_does_not_apply_to_json_loads(self):
        tree = ast.parse("import json\ndef f(b): return json.loads(b)")
        assert not self.rule.applies_to(tree)

    def test_sanitize_replaces_pickle_with_json(self):
        src = "import pickle\ndef f(b):\n    return pickle.loads(b)\n"
        # Force rule choice deterministically by trying multiple seeds and
        # picking one that triggered this rule. Or call the rule directly.
        from src.red_team.base import unparse_clean
        tree = ast.parse(src)
        out_tree = self.rule.sanitize(tree, random.Random(0))
        out = unparse_clean(out_tree, format_with_black=False)
        assert "pickle.loads" not in out
        assert "json.loads" in out
        assert "import json" in out


# ---------------------------------------------------------------------------
# CWE-79: Markup → escape
# ---------------------------------------------------------------------------

class TestCWE79Markup:
    rule = MarkupToEscape()

    def test_applies_to_bare_markup(self):
        tree = ast.parse("def f(t): return Markup(t)")
        assert self.rule.applies_to(tree)

    def test_applies_to_dotted_markup(self):
        tree = ast.parse("import flask\ndef f(t): return flask.Markup(t)")
        assert self.rule.applies_to(tree)

    def test_applies_to_mark_safe(self):
        tree = ast.parse("def f(t): return mark_safe(t)")
        assert self.rule.applies_to(tree)

    def test_does_not_apply_to_safe(self):
        tree = ast.parse("def f(t): return escape(t)")
        assert not self.rule.applies_to(tree)

    def test_sanitize_replaces_markup_with_escape(self):
        src = (
            "from flask import Markup\n"
            "def render(t):\n"
            "    return Markup(t)\n"
        )
        from src.red_team.base import unparse_clean
        tree = ast.parse(src)
        out_tree = self.rule.sanitize(tree, random.Random(0))
        out = unparse_clean(out_tree, format_with_black=False)
        # Source-level: must no longer call Markup as a sink
        # (the line-level call `Markup(t)` is now `escape(t)`)
        # The original `from flask import Markup` is still there as an
        # untouched import — that's fine; what matters is the call site.
        # Find calls in the resulting AST
        new_tree = ast.parse(out)
        markup_calls = [
            c for c in ast.walk(new_tree)
            if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Name) and c.func.id == "Markup"
        ]
        escape_calls = [
            c for c in ast.walk(new_tree)
            if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Name) and c.func.id == "escape"
        ]
        assert len(markup_calls) == 0
        assert len(escape_calls) >= 1


# ---------------------------------------------------------------------------
# CWE-79: render_template_string wrapping
# ---------------------------------------------------------------------------

class TestCWE79RenderTemplateString:
    rule = WrapRenderTemplateStringWithEscape()

    def test_applies_to(self):
        tree = ast.parse(
            "from flask import render_template_string\n"
            "def f(t): return render_template_string(t)"
        )
        assert self.rule.applies_to(tree)

    def test_does_not_apply_to_safe_calls(self):
        tree = ast.parse(
            "def f(t): return render_template('safe.html', x=t)"
        )
        assert not self.rule.applies_to(tree)

    def test_sanitize_wraps_first_arg(self):
        src = (
            "from flask import render_template_string\n"
            "def f(t):\n"
            "    return render_template_string(t)\n"
        )
        from src.red_team.base import unparse_clean
        tree = ast.parse(src)
        out_tree = self.rule.sanitize(tree, random.Random(0))
        out = unparse_clean(out_tree, format_with_black=False)
        # First arg should now be `escape(t)`
        new_tree = ast.parse(out)
        for c in ast.walk(new_tree):
            if (
                isinstance(c, ast.Call)
                and isinstance(c.func, ast.Name)
                and c.func.id == "render_template_string"
            ):
                first_arg = c.args[0]
                assert isinstance(first_arg, ast.Call)
                assert isinstance(first_arg.func, ast.Name)
                assert first_arg.func.id == "escape"


# ---------------------------------------------------------------------------
# Idempotence — applying the rule twice doesn't break anything
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cwe,src", [
    ("CWE-94",  "def f(s):\n    return eval(s)\n"),
    ("CWE-502", "import yaml\ndef f(s):\n    return yaml.load(s)\n"),
])
def test_sanitize_idempotent(cwe, src):
    """Running sanitize on already-sanitized code should be a no-op skip."""
    out1, r1 = sanitize(src, cwe, random.Random(0))
    assert r1.success
    out2, r2 = sanitize(out1, cwe, random.Random(0))
    # Now the source is already safe → no rule applies
    assert not r2.success
    assert "no applicable rule" in r2.reason


# ---------------------------------------------------------------------------
# Determinism — same seed produces same output
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cwe,src,seed", [
    ("CWE-94",  "def f(s): return eval(s)", 0),
    ("CWE-94",  "def f(s): return eval(s)", 42),
    ("CWE-502", "import yaml\ndef f(s): return yaml.load(s)", 7),
    ("CWE-502", "import pickle\ndef f(b): return pickle.loads(b)", 99),
])
def test_sanitize_deterministic(cwe, src, seed):
    out1, _ = sanitize(src, cwe, random.Random(seed))
    out2, _ = sanitize(src, cwe, random.Random(seed))
    assert out1 == out2


# ---------------------------------------------------------------------------
# Output differs from input
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cwe,src", [
    ("CWE-94",  "def f(s):\n    return eval(s)\n"),
    ("CWE-502", "import yaml\ndef f(s):\n    return yaml.load(s)\n"),
    ("CWE-502", "import pickle\ndef f(b):\n    return pickle.loads(b)\n"),
])
def test_output_differs_from_input(cwe, src):
    out, result = sanitize(src, cwe, random.Random(0))
    assert result.success
    assert out.strip() != src.strip()
