"""
test_complex_rules.py — tests for the 4 more complex sanitization rules:
CWE-89, CWE-78, CWE-22, CWE-918.
"""

from __future__ import annotations

import ast
import random

import pytest

from src.red_team.base import unparse_clean
from src.red_team.sanitization import sanitize


# ---------------------------------------------------------------------------
# CWE-89 — SQL Injection
# ---------------------------------------------------------------------------

class TestCWE89:
    def test_fstring_execute_becomes_parameterized(self):
        src = (
            "def get_user(uid):\n"
            "    return cursor.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n"
        )
        out, result = sanitize(src, "CWE-89", random.Random(0))
        assert result.success
        # The new query should contain ? and a tuple of params
        new_tree = ast.parse(out)
        execute_calls = [
            c for c in ast.walk(new_tree)
            if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Attribute)
            and c.func.attr == "execute"
        ]
        assert len(execute_calls) == 1
        call = execute_calls[0]
        # First arg: plain string with `?`
        assert isinstance(call.args[0], ast.Constant)
        assert "?" in call.args[0].value
        # Second arg: tuple of params
        assert isinstance(call.args[1], ast.Tuple)
        assert len(call.args[1].elts) == 1

    def test_fstring_with_multiple_params(self):
        src = (
            "def f(uid, name):\n"
            "    return cursor.execute(f\"UPDATE users SET name = {name} WHERE id = {uid}\")\n"
        )
        out, result = sanitize(src, "CWE-89", random.Random(0))
        assert result.success
        new_tree = ast.parse(out)
        call = next(
            c for c in ast.walk(new_tree)
            if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Attribute) and c.func.attr == "execute"
        )
        assert isinstance(call.args[1], ast.Tuple)
        assert len(call.args[1].elts) == 2

    def test_percent_interpolation_becomes_parameterized(self):
        src = (
            "def f(uid):\n"
            "    return cursor.execute(\"SELECT * FROM x WHERE id = %s\" % (uid,))\n"
        )
        out, result = sanitize(src, "CWE-89", random.Random(0))
        assert result.success
        new_tree = ast.parse(out)
        call = next(
            c for c in ast.walk(new_tree)
            if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Attribute) and c.func.attr == "execute"
        )
        # Now we have two args: the SQL string and the params tuple
        assert len(call.args) >= 2
        assert isinstance(call.args[0], ast.Constant)
        assert isinstance(call.args[1], ast.Tuple)
        # The original BinOp(%) should be gone
        for n in ast.walk(call):
            if isinstance(n, ast.BinOp):
                assert not isinstance(n.op, ast.Mod), "% interpolation still present"

    def test_does_not_apply_to_already_parameterized(self):
        src = (
            "def f(uid):\n"
            "    return cursor.execute(\"SELECT * FROM x WHERE id = ?\", (uid,))\n"
        )
        out, result = sanitize(src, "CWE-89", random.Random(0))
        assert not result.success


# ---------------------------------------------------------------------------
# CWE-78 — Command Injection
# ---------------------------------------------------------------------------

class TestCWE78:
    def test_os_system_becomes_subprocess_run(self):
        src = (
            "def ping(host):\n"
            "    import os\n"
            "    return os.system(f\"ping -c 1 {host}\")\n"
        )
        out, result = sanitize(src, "CWE-78", random.Random(0))
        assert result.success
        # `os.system(` should not appear
        assert "os.system(" not in out
        # `subprocess.run(` should appear
        assert "subprocess.run(" in out
        # `shlex.split(` wrapping should appear
        assert "shlex.split(" in out
        # shell=False, check=True keywords should appear
        assert "shell=False" in out
        assert "check=True" in out

    def test_subprocess_shell_true_flips_to_false(self):
        src = (
            "import subprocess\n"
            "def run_cmd(cmd):\n"
            "    return subprocess.run(cmd, shell=True)\n"
        )
        out, result = sanitize(src, "CWE-78", random.Random(0))
        assert result.success
        # Check via AST that shell= keyword is now False
        new_tree = ast.parse(out)
        sub_calls = [
            c for c in ast.walk(new_tree)
            if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Attribute)
            and c.func.attr == "run"
        ]
        assert len(sub_calls) == 1
        for kw in sub_calls[0].keywords:
            if kw.arg == "shell":
                assert kw.value.value is False

    def test_does_not_apply_to_safe_subprocess(self):
        src = (
            "import subprocess\n"
            "def f(cmd_list):\n"
            "    return subprocess.run(cmd_list, shell=False)\n"
        )
        out, result = sanitize(src, "CWE-78", random.Random(0))
        assert not result.success


# ---------------------------------------------------------------------------
# CWE-22 — Path Traversal
# ---------------------------------------------------------------------------

class TestCWE22:
    def test_open_user_path_gets_wrapped(self):
        src = (
            "def read_file(filename):\n"
            "    return open(filename).read()\n"
        )
        out, result = sanitize(src, "CWE-22", random.Random(0))
        assert result.success
        # The first arg of `open(...)` should now be `secure_filename(filename)`
        new_tree = ast.parse(out)
        open_calls = [
            c for c in ast.walk(new_tree)
            if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Name) and c.func.id == "open"
        ]
        assert len(open_calls) == 1
        first_arg = open_calls[0].args[0]
        assert (
            isinstance(first_arg, ast.Call)
            and isinstance(first_arg.func, ast.Name)
            and first_arg.func.id == "secure_filename"
        )

    def test_join_path_user_part_wrapped(self):
        """In `os.path.join(BASE, user)`, only `user` should be wrapped."""
        src = (
            "import os\n"
            "BASE = '/data'\n"
            "def read(user):\n"
            "    return open(os.path.join(BASE, user))\n"
        )
        out, result = sanitize(src, "CWE-22", random.Random(0))
        assert result.success
        new_tree = ast.parse(out)
        # Find the path join call
        join_call = next(
            c for c in ast.walk(new_tree)
            if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Attribute) and c.func.attr == "join"
        )
        # The last arg should be wrapped
        last_arg = join_call.args[-1]
        assert (
            isinstance(last_arg, ast.Call)
            and isinstance(last_arg.func, ast.Name)
            and last_arg.func.id == "secure_filename"
        )
        # The first arg (BASE) should NOT be wrapped
        first_arg = join_call.args[0]
        assert not (
            isinstance(first_arg, ast.Call)
            and isinstance(first_arg.func, ast.Name)
            and first_arg.func.id == "secure_filename"
        )

    def test_send_from_directory_wraps_second_arg(self):
        src = (
            "from flask import send_from_directory\n"
            "def serve(filename):\n"
            "    return send_from_directory('/data', filename)\n"
        )
        out, result = sanitize(src, "CWE-22", random.Random(0))
        assert result.success
        new_tree = ast.parse(out)
        sfd_call = next(
            c for c in ast.walk(new_tree)
            if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Name)
            and c.func.id == "send_from_directory"
        )
        second = sfd_call.args[1]
        assert (
            isinstance(second, ast.Call)
            and isinstance(second.func, ast.Name)
            and second.func.id == "secure_filename"
        )

    def test_already_wrapped_skipped(self):
        src = (
            "from werkzeug.utils import secure_filename\n"
            "def read(filename):\n"
            "    return open(secure_filename(filename))\n"
        )
        out, result = sanitize(src, "CWE-22", random.Random(0))
        assert not result.success


# ---------------------------------------------------------------------------
# CWE-918 — SSRF
# ---------------------------------------------------------------------------

class TestCWE918:
    def test_requests_get_gets_guard(self):
        src = (
            "import requests\n"
            "def fetch(url):\n"
            "    return requests.get(url)\n"
        )
        out, result = sanitize(src, "CWE-918", random.Random(0))
        assert result.success
        # The output should contain urlparse, the netloc-allowlist check,
        # and a ValueError raise
        assert "urlparse(" in out
        assert "ALLOWED_HOSTS" in out
        assert "raise ValueError" in out
        # The original requests.get call must STILL be there (we add a
        # guard, we don't remove the call)
        assert "requests.get(url)" in out

    def test_already_guarded_function_skipped(self):
        src = (
            "import requests\n"
            "from urllib.parse import urlparse\n"
            "def fetch(url):\n"
            "    parsed = urlparse(url)\n"
            "    if parsed.netloc not in ('safe.com',):\n"
            "        raise ValueError('bad host')\n"
            "    return requests.get(url)\n"
        )
        out, result = sanitize(src, "CWE-918", random.Random(0))
        assert not result.success

    def test_urlopen_also_guarded(self):
        src = (
            "from urllib.request import urlopen\n"
            "def fetch(url):\n"
            "    return urlopen(url).read()\n"
        )
        out, result = sanitize(src, "CWE-918", random.Random(0))
        assert result.success
        assert "urlparse(" in out


# ---------------------------------------------------------------------------
# All-rules registry sanity
# ---------------------------------------------------------------------------

def test_all_seven_cwes_registered():
    """After adding the 4 complex rules, all 7 target CWEs must have rules."""
    from src.red_team.sanitization import all_rules
    out = all_rules()
    target_cwes = {"CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502", "CWE-918"}
    assert target_cwes.issubset(set(out.keys())), (
        f"Missing CWEs: {target_cwes - set(out.keys())}"
    )


# ---------------------------------------------------------------------------
# End-to-end: vulnerable + sanitization + parses cleanly
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cwe,src", [
    (
        "CWE-89",
        "def get_user(uid):\n    return cursor.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n",
    ),
    (
        "CWE-78",
        "import os\ndef ping(h):\n    return os.system(f\"ping {h}\")\n",
    ),
    (
        "CWE-22",
        "def read(name):\n    return open(name).read()\n",
    ),
    (
        "CWE-918",
        "import requests\ndef fetch(url):\n    return requests.get(url)\n",
    ),
])
def test_complex_rules_round_trip(cwe, src):
    out, result = sanitize(src, cwe, random.Random(0))
    assert result.success, f"Sanitization failed: {result.reason}"
    # Output must be valid Python
    ast.parse(out)
    # Output must differ from input
    assert out.strip() != src.strip()
