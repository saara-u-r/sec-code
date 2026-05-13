#!/usr/bin/env python3
"""
add_canonical_samples.py — hand-curated textbook samples for rare CWEs.

Phase 2B re-scope (2026-05-13) left several CWEs below the audit
threshold of "≥20 real samples per class". To stabilize per-class F1
on the evaluation benchmark, we add canonical textbook samples drawn
from OWASP, SANS, and well-known framework documentation.

Each canonical sample:
  * Is a realistic Python file (10-40 lines, imports + handler).
  * Showcases ONE specific vulnerability variant clearly.
  * Matches a sink in cwe_taxonomy.SINK_PATTERNS so the has_cwe_sink
    quality gate accepts it.
  * Tagged source="canonical", label_source="canonical",
    label_confidence="high" for full audit traceability.
  * Carries a unique deterministic id so re-runs are idempotent
    (content_hash + file path are stable).

These samples double as **calibration points**: if Bandit/Semgrep misses
all canonical CWE-89 samples, something is wrong with the tool setup,
not the dataset.

Usage:
  python scripts/add_canonical_samples.py            # dry-run summary
  python scripts/add_canonical_samples.py --apply    # write to data/raw
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.file_utils import build_meta, has_cwe_sink, hash_code, save_code_sample  # noqa: E402
from src.utils.logger import get_logger  # noqa: E402

logger = get_logger("canonical")


# ---------------------------------------------------------------------------
# Canonical samples — code only. Each entry produces ONE sample.
# ---------------------------------------------------------------------------
# Format: (cwe, vuln_type, framework, label, code)

CANONICAL_SAMPLES: list[tuple[str, str, str, str, str]] = [

    # ── CWE-434 Unrestricted File Upload ─────────────────────────────────
    ("CWE-434", "unrestricted_file_upload", "flask",
     "flask_upload_no_validation",
     """\
import os
from flask import Flask, request

app = Flask(__name__)
UPLOAD_FOLDER = '/var/www/uploads'

@app.route('/upload', methods=['POST'])
def upload_file():
    f = request.files['file']
    save_path = os.path.join(UPLOAD_FOLDER, f.filename)
    f.save(save_path)
    return f'Uploaded {f.filename}'
"""),

    ("CWE-434", "unrestricted_file_upload", "flask",
     "flask_upload_extension_bypass",
     """\
import os
from flask import Flask, request

app = Flask(__name__)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

@app.route('/profile-pic', methods=['POST'])
def set_profile_picture():
    f = request.files['picture']
    if '.' in f.filename:
        ext = f.filename.rsplit('.', 1)[1]
        if ext in ALLOWED_EXTENSIONS:
            f.save(os.path.join('/uploads/profiles', f.filename))
            return 'ok'
    return 'bad ext', 400
"""),

    ("CWE-434", "unrestricted_file_upload", "django",
     "django_filefield_no_validator",
     """\
from django.db import models

class UserDocument(models.Model):
    user_id = models.IntegerField()
    title = models.CharField(max_length=200)
    document = models.FileField(upload_to='documents/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_documents'
"""),

    ("CWE-434", "unrestricted_file_upload", "fastapi",
     "fastapi_upload_no_mime_check",
     """\
from fastapi import FastAPI, UploadFile, File

app = FastAPI()

@app.post('/api/v1/avatar')
async def upload_avatar(user_id: int, file: UploadFile = File(...)):
    contents = await file.read()
    out_path = f'/data/avatars/{user_id}/{file.filename}'
    with open(out_path, 'wb') as f:
        f.write(contents)
    return {'filename': file.filename, 'size': len(contents)}
"""),

    ("CWE-434", "unrestricted_file_upload", "flask",
     "flask_upload_path_join_traversal",
     """\
import os
from flask import Flask, request
from werkzeug.datastructures import FileStorage

app = Flask(__name__)

@app.route('/files', methods=['POST'])
def store():
    f: FileStorage = request.files['document']
    target = os.path.join('/srv/files', f.filename)
    f.save(target)
    return 'stored'
"""),

    ("CWE-434", "unrestricted_file_upload", "flask",
     "flask_upload_mime_only_validation",
     """\
import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/avatar', methods=['POST'])
def avatar():
    f = request.files['avatar']
    if f.mimetype.startswith('image/'):
        f.save(os.path.join('/static/avatars', f.filename))
        return 'ok'
    return 'bad type', 400
"""),

    ("CWE-434", "unrestricted_file_upload", "django",
     "django_imagefield_no_pillow_verify",
     """\
from django.db import models

class Listing(models.Model):
    title = models.CharField(max_length=120)
    cover_image = models.ImageField(upload_to='listings/')
    body = models.TextField()
"""),

    ("CWE-434", "unrestricted_file_upload", "flask",
     "flask_upload_blocklist_bypass",
     """\
import os
from flask import Flask, request

app = Flask(__name__)
BLOCKED = {'php', 'exe', 'sh'}

@app.route('/cms-upload', methods=['POST'])
def cms_upload():
    f = request.files['asset']
    ext = f.filename.rsplit('.', 1)[-1].lower()
    if ext in BLOCKED:
        return 'blocked', 400
    f.save(os.path.join('/var/cms/assets', f.filename))
    return 'ok'
"""),

    # ── CWE-78 OS Command Injection ──────────────────────────────────────
    ("CWE-78", "command_injection", "flask",
     "flask_ping_os_system",
     """\
import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/diagnostics/ping')
def ping():
    host = request.args.get('host', 'localhost')
    os.system(f'ping -c 1 {host}')
    return 'pinged'
"""),

    ("CWE-78", "command_injection", "flask",
     "flask_convert_subprocess_shell",
     """\
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/thumbnail', methods=['POST'])
def make_thumbnail():
    src = request.form['source']
    dst = request.form['dest']
    subprocess.run(f'convert {src} -resize 100x100 {dst}', shell=True)
    return 'done'
"""),

    ("CWE-78", "command_injection", "django",
     "django_view_os_popen",
     """\
import os
from django.http import HttpResponse

def whois_lookup(request):
    domain = request.GET.get('domain', '')
    output = os.popen(f'whois {domain}').read()
    return HttpResponse(output, content_type='text/plain')
"""),

    ("CWE-78", "command_injection", "fastapi",
     "fastapi_dns_resolve_popen",
     """\
import subprocess
from fastapi import FastAPI

app = FastAPI()

@app.get('/api/dns')
async def dns_lookup(name: str):
    proc = subprocess.Popen(f'dig {name} +short', shell=True, stdout=subprocess.PIPE)
    out, _ = proc.communicate()
    return {'records': out.decode().splitlines()}
"""),

    ("CWE-78", "command_injection", "flask",
     "flask_git_log_shell_true",
     """\
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/repo/log')
def git_log():
    branch = request.args.get('branch', 'main')
    result = subprocess.check_output(
        f'git log {branch} --oneline -n 20',
        shell=True,
        text=True,
    )
    return result
"""),

    ("CWE-78", "command_injection", "flask",
     "flask_archive_zip_extraction",
     """\
import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/extract', methods=['POST'])
def extract():
    archive = request.form['file']
    os.system(f'unzip {archive} -d /tmp/extract')
    return 'extracted'
"""),

    ("CWE-78", "command_injection", "flask",
     "flask_ffmpeg_transcode",
     """\
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/transcode', methods=['POST'])
def transcode():
    input_file = request.form['input']
    bitrate = request.form.get('bitrate', '128k')
    subprocess.run(
        f'ffmpeg -i {input_file} -b:a {bitrate} /tmp/out.mp3',
        shell=True,
        check=True,
    )
    return 'ok'
"""),

    ("CWE-78", "command_injection", "flask",
     "flask_curl_proxy",
     """\
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/proxy-fetch')
def proxy_fetch():
    url = request.args['url']
    out = subprocess.check_output(f'curl -sSL {url}', shell=True, text=True)
    return out
"""),

    # ── CWE-94 Code Injection ────────────────────────────────────────────
    ("CWE-94", "code_injection", "flask",
     "flask_calculator_eval",
     """\
from flask import Flask, request

app = Flask(__name__)

@app.route('/calc')
def calc():
    expr = request.args.get('q', '0')
    result = eval(expr)
    return f'result: {result}'
"""),

    ("CWE-94", "code_injection", "flask",
     "flask_python_repl_exec",
     """\
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/run', methods=['POST'])
def run_code():
    src = request.json['source']
    local_ns = {}
    exec(src, {}, local_ns)
    return jsonify({k: repr(v) for k, v in local_ns.items()})
"""),

    ("CWE-94", "code_injection", "django",
     "django_plugin_loader_import_module",
     """\
import importlib
from django.http import HttpResponse

def load_plugin(request):
    name = request.GET.get('plugin', '')
    module = importlib.import_module(name)
    return HttpResponse(repr(module))
"""),

    ("CWE-94", "code_injection", "fastapi",
     "fastapi_filter_eval",
     """\
from fastapi import FastAPI, Query

app = FastAPI()

@app.get('/data/filter')
async def filter_rows(predicate: str = Query(...)):
    rows = [{'id': i, 'value': i * 2} for i in range(100)]
    matches = [r for r in rows if eval(predicate, {'r': r})]
    return matches
"""),

    ("CWE-94", "code_injection", "flask",
     "flask_template_compile",
     """\
from flask import Flask, request

app = Flask(__name__)

@app.route('/preview', methods=['POST'])
def preview():
    template = request.form['template']
    code = compile(template, '<template>', 'eval')
    return repr(eval(code, {}))
"""),

    ("CWE-94", "code_injection", "flask",
     "flask_dynamic_module_dunder_import",
     """\
from flask import Flask, request

app = Flask(__name__)

@app.route('/load-driver')
def load_driver():
    name = request.args['name']
    driver = __import__(f'app.drivers.{name}')
    return f'loaded {driver.__name__}'
"""),

    # ── CWE-502 Insecure Deserialization ─────────────────────────────────
    ("CWE-502", "insecure_deserialization", "flask",
     "flask_pickle_session_loads",
     """\
import base64
import pickle
from flask import Flask, request

app = Flask(__name__)

@app.route('/restore-session', methods=['POST'])
def restore_session():
    blob = base64.b64decode(request.form['session'])
    session_data = pickle.loads(blob)
    return f'restored {session_data.get(\"user\")}'
"""),

    ("CWE-502", "insecure_deserialization", "flask",
     "flask_yaml_load_config",
     """\
import yaml
from flask import Flask, request

app = Flask(__name__)

@app.route('/config/import', methods=['POST'])
def import_config():
    raw = request.data
    config = yaml.load(raw)
    return f'loaded {len(config)} keys'
"""),

    ("CWE-502", "insecure_deserialization", "django",
     "django_pickle_cookie",
     """\
import pickle
import base64
from django.http import HttpResponse

def restore_preferences(request):
    cookie = request.COOKIES.get('prefs', '')
    if not cookie:
        return HttpResponse('no prefs')
    prefs = pickle.loads(base64.b64decode(cookie))
    return HttpResponse(f'theme={prefs.get(\"theme\")}')
"""),

    ("CWE-502", "insecure_deserialization", "fastapi",
     "fastapi_marshal_loads",
     """\
import base64
import marshal
from fastapi import FastAPI, Request

app = FastAPI()

@app.post('/restore-task')
async def restore_task(request: Request):
    body = await request.body()
    task_def = marshal.loads(base64.b64decode(body))
    return {'task': repr(task_def)}
"""),

    ("CWE-502", "insecure_deserialization", "flask",
     "flask_jsonpickle_decode",
     """\
import jsonpickle
from flask import Flask, request

app = Flask(__name__)

@app.route('/import', methods=['POST'])
def import_object():
    payload = request.get_data(as_text=True)
    obj = jsonpickle.loads(payload)
    return f'imported {type(obj).__name__}'
"""),

    ("CWE-502", "insecure_deserialization", "flask",
     "flask_yaml_unsafe_load",
     """\
import yaml
from flask import Flask, request

app = Flask(__name__)

@app.route('/parse-yaml', methods=['POST'])
def parse_yaml():
    data = yaml.unsafe_load(request.get_data())
    return f'{type(data).__name__}: {len(repr(data))} chars'
"""),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default="data/raw")
    parser.add_argument("--apply", action="store_true",
                        help="Actually write samples. Default is dry-run summary.")
    args = parser.parse_args()

    # Group by CWE for the summary
    by_cwe: dict[str, list[str]] = {}
    failed: list[str] = []
    for cwe, vuln_type, fw, label, code in CANONICAL_SAMPLES:
        by_cwe.setdefault(cwe, []).append(label)
        # Quality gate: must pass has_cwe_sink
        sink_ok, sink_pat = has_cwe_sink(code, cwe, file_path=f"{label}.py")
        if not sink_ok:
            failed.append(f"{cwe}: {label}")

    print(f"Canonical samples: {len(CANONICAL_SAMPLES)} total")
    for cwe in sorted(by_cwe):
        print(f"  {cwe}: {len(by_cwe[cwe])} samples")
        for label in by_cwe[cwe]:
            print(f"    - {label}")

    if failed:
        print(f"\nFAILED sink_filter check ({len(failed)}):")
        for f in failed:
            print(f"  - {f}")
        if not args.apply:
            print("\nFix sink patterns in failed samples before --apply.")
            return 1

    if not args.apply:
        print("\nDRY RUN — no files written. Re-run with --apply to save.")
        return 0

    saved = 0
    for cwe, vuln_type, framework, label, code in CANONICAL_SAMPLES:
        h = hash_code(code)
        sample_id = f"canonical_{vuln_type}_{h}"
        meta = build_meta(
            {
                "id":               sample_id,
                "source":           "canonical",
                "cwe":              cwe,
                "vuln_type":        vuln_type,
                "label_source":     "canonical",
                "label_confidence": "high",
                "framework":        framework,
                "repo":             "canonical_examples",
                "file_path":        f"{label}.py",
            },
            code,
            "",  # no paired safe version (kept simple; can extend later)
        )
        save_code_sample(code, meta, args.output_dir)
        saved += 1
        logger.info(f"  [{cwe}] {sample_id} ({label})")

    print(f"\nSaved {saved} canonical samples to {args.output_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
