# Stage-1 Sample Audit Pack — 2026-05-13 10:50 UTC

Per-CWE spot-check of label correctness. For each sample below, read
the code excerpt and decide:

- **PASS** — the labeled CWE matches what the code actually does
- **FAIL** — the code does not exhibit the labeled CWE (note the actual CWE
  or the reason: e.g. "sink call but no taint flow", "test fixture",
  "unrelated co-changed file", etc.)

Sampled with seed=13. Per-CWE sampling: 6 for
populous classes, ALL for classes with ≤25 samples.

Canonical samples are excluded from the audit (they are hand-curated
textbook positives by construction).

---

## Summary

| CWE | Active | Sampled | Audit FP rate (filled after audit) |
|---|---:|---:|---|
| CWE-22 (Path Traversal) | 15 | 15 | __/__ |
| CWE-502 (Deserialization of Untrusted Data) | 72 | 6 | __/__ |
| CWE-78 (OS Command Injection) | 17 | 17 | __/__ |
| CWE-79 (Cross-site Scripting) | 54 | 6 | __/__ |
| CWE-89 (SQL Injection) | 212 | 6 | __/__ |
| CWE-918 (Server-Side Request Forgery) | 22 | 22 | __/__ |
| CWE-94 (Code Injection) | 30 | 6 | __/__ |
| safe (safe) | 429 | 0 | __/__ |

---

## CWE-22 — Path Traversal

Sampled: **15** / 15 on disk.

### #1 — `ghsa_db_path_traversal_60f4c4c6c5c33d72` (ghsa_db, —)

- **Repo:** gradio-app/gradio
- **File path:** `gradio/routes.py`
- **Framework:** fastapi
- **Sink pattern recorded:** `\bos\.path\.join\s*\(`
- **Sink match position:** line 871
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  863       _os_alt_seps: List[str] = [
  864           sep for sep in [os.path.sep, os.path.altsep] if sep is not None and sep != "/"
  865       ]
  866   
  867       if path == "":
  868           raise HTTPException(400)
  869   
  870       filename = posixpath.normpath(path)
  871 →     fullpath = os.path.join(directory, filename)
  872       if (
  873           any(sep in filename for sep in _os_alt_seps)
  874           or os.path.isabs(filename)
  875           or filename == ".."
  876           or filename.startswith("../")
  877           or os.path.isdir(fullpath)
  878       ):
  879           raise HTTPException(403)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_path_traversal_b29d8c9ae9ce6c75` (ghsa_db, CVE-2022-31507)

- **Repo:** ganga-devs/ganga
- **File path:** `ganga/GangaGUI/gui/routes.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 270
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  262   #Edit gangarc
  263   @gui.route("/config_edit",methods=["GET", "POST"])
  264   @login_required
  265   def edit_config_page():
  266       """
  267       Edit gangarc file from the GUI
  268       """
  269       gui_rc = gui.config["GANGA_RC"]
  270 →     with open(gui_rc, "rt") as f:
  271           ganga_config = f.read()
  272       if request.method == 'POST':
  273           config_ganga = request.form['config-data']
  274           with open(gui_rc, 'w') as f1:
  275               f1.write(str(config_ganga))
  276           flash(".gangarc Edited", "success")
  277           with open(gui_rc, "rt") as f2:
  278               ganga_config = f2.read()
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `ghsa_db_path_traversal_3985d910cbb15eea` (ghsa_db, CVE-2025-55149)

- **Repo:** ulab-uiuc/tiny-scientist
- **File path:** `backend/app.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 708
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  700           if not full_path.startswith(os.path.abspath(generated_base)):
  701               return jsonify({"error": "Access denied"}), 403
  702   
  703           if not os.path.exists(full_path):
  704               return jsonify({"error": "File not found"}), 404
  705   
  706           # For text files, return content as JSON
  707           if file_path.endswith((".py", ".txt", ".md", ".json")):
  708 →             with open(full_path, "r", encoding="utf-8") as f:
  709                   content = f.read()
  710               return jsonify({"content": content})
  711           else:
  712               # For other files, serve directly
  713               return send_file(full_path)
  714   
  715       except Exception as e:
  716           print(f"Error serving file {file_path}: {e}")
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `ghsa_db_path_traversal_d44b729740a208ef` (ghsa_db, CVE-2024-2044)

- **Repo:** pgadmin-org/pgadmin4
- **File path:** `web/pgadmin/utils/session.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 217
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  209               fname = os.path.join(self.path, sid)
  210   
  211           # Do not store the session if skip paths
  212           for sp in self.skip_paths:
  213               if request.path.startswith(sp):
  214                   return ManagedSession(sid=sid)
  215   
  216           # touch the file
  217 →         with open(fname, 'wb'):
  218               return ManagedSession(sid=sid)
  219   
  220           return ManagedSession(sid=sid)
  221   
  222       def get(self, sid, digest):
  223           'Retrieve a managed session by session-id, checking the HMAC digest'
  224   
  225           fname = os.path.join(self.path, sid)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `ghsa_db_path_traversal_1e57653ced4a9814` (ghsa_db, CVE-2024-5980)

- **Repo:** lightning-ai/pytorch-lightning
- **File path:** `docs/source-app/examples/file_server/app.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 64
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   56           uploaded_file = self.get_random_filename()
   57           meta_file = uploaded_file + ".meta"
   58           self.uploaded_files[filename] = {
   59               "progress": (0, None), "done": False
   60           }
   61   
   62           # 2: Create a stream and write bytes of
   63           # the file to the disk under `uploaded_file` path.
   64 →         with open(self.get_filepath(uploaded_file), "wb") as out_file:
   65               content = file.read(self.chunk_size)
   66               while content:
   67                   # 2.1 Write the file bytes
   68                   size = out_file.write(content)
   69   
   70                   # 2.2 Update the progress metadata
   71                   self.uploaded_files[filename]["progress"] = (
   72                       self.uploaded_files[filename]["progress"][0] + size,
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `ghsa_db_path_traversal_fc0fd5bdc814d00d` (ghsa_db, CVE-2023-0241)

- **Repo:** akshay-joshi/pgadmin4
- **File path:** `web/pgadmin/tools/restore/__init__.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bos\.path\.join\s*\(`
- **Sink match position:** line 144
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  136   
  137       Returns:
  138           Filename to use for backup with full path taken from preference
  139       """
  140       # Set file manager directory from preference
  141       storage_dir = get_storage_directory()
  142   
  143       if storage_dir:
  144 →         _file = os.path.join(storage_dir, _file.lstrip('/').lstrip('\\'))
  145       elif not os.path.isabs(_file):
  146           _file = os.path.join(document_dir(), _file)
  147   
  148       if not os.path.isfile(_file) and not os.path.exists(_file):
  149           return None
  150   
  151       return fs_short_path(_file)
  152   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `ghsa_db_path_traversal_ed5b19d765e8b982` (ghsa_db, CVE-2024-39903)

- **Repo:** widgetti/solara
- **File path:** `solara/server/flask.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bsend_from_directory\s*\(`
- **Sink match position:** line 179
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  171   @blueprint.route("/static/public/<path:path>")
  172   def public(path):
  173       if not allowed():
  174           abort(401)
  175       directories = [app.directory.parent / "public" for app in appmod.apps.values()]
  176       for directory in directories:
  177           file = directory / path
  178           if file.exists():
  179 →             return send_from_directory(directory, path)
  180       return flask.Response("not found", status=404)
  181   
  182   
  183   @blueprint.route("/static/assets/<path:path>")
  184   def assets(path):
  185       if not allowed():
  186           abort(401)
  187       directories = server.asset_directories()
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #8 — `cvefixes_path_traversal_d759019193a3c2dc` (cvefixes, CVE-2022-24840)

- **Repo:** https://github.com/codingjoe/django-s3file
- **File path:** `test_middleware.py`
- **Framework:** django
- **Sink pattern recorded:** `\bos\.path\.join\s*\(`
- **Sink match position:** line 17
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
    9   
   10   class TestS3FileMiddleware:
   11       def test_get_files_from_storage(self):
   12           content = b"test_get_files_from_storage"
   13           name = storage.save(
   14               "tmp/s3file/test_get_files_from_storage", ContentFile(content)
   15           )
   16           files = S3FileMiddleware.get_files_from_storage(
   17 →             [os.path.join(storage.aws_location, name)]
   18           )
   19           file = next(files)
   20           assert file.read() == content
   21   
   22       def test_process_request(self, rf):
   23           uploaded_file = SimpleUploadedFile("uploaded_file.txt", b"uploaded")
   24           request = rf.post("/", data={"file": uploaded_file})
   25           S3FileMiddleware(lambda x: None)(request)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `cvefixes_path_traversal_e5cde69ce5a585b4` (cvefixes, CVE-2022-24840)

- **Repo:** https://github.com/codingjoe/django-s3file
- **File path:** `middleware.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 36
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   28           """Return S3 file where the name does not include the path."""
   29           for path in paths:
   30               path = pathlib.PurePosixPath(path)
   31               try:
   32                   location = storage.aws_location
   33               except AttributeError:
   34                   location = storage.location
   35               try:
   36 →                 f = storage.open(str(path.relative_to(location)))
   37                   f.name = path.name
   38                   yield f
   39               except (OSError, ValueError):
   40                   logger.exception("File not found: %s", path)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `cvefixes_path_traversal_ff7fdd393b25db9b` (cvefixes, CVE-2020-15239)

- **Repo:** https://github.com/horazont/xmpp-http-upload
- **File path:** `xhu.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 57
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   49   def get_paths(base_path: pathlib.Path):
   50       data_file = pathlib.Path(str(base_path) + ".data")
   51       metadata_file = pathlib.Path(str(base_path) + ".meta")
   52   
   53       return data_file, metadata_file
   54   
   55   
   56   def load_metadata(metadata_file):
   57 →     with metadata_file.open("r") as f:
   58           return json.load(f)
   59   
   60   
   61   def get_info(path: str, root: pathlib.Path) -> typing.Tuple[
   62           pathlib.Path,
   63           dict]:
   64       dest_path = sanitized_join(
   65           path,
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #11 — `ghsa_db_path_traversal_fe909264898420bc` (ghsa_db, CVE-2025-54802)

- **Repo:** pyload/pyload
- **File path:** `src/pyload/webui/app/blueprints/cnl_blueprint.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 93
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   85       package = flask.request.form.get(
   86           "package", flask.request.form.get("source", flask.request.form.get("referer"))
   87       )
   88       dl_path = api.get_config_value("general", "storage_folder")
   89       dlc_path = os.path.join(
   90           dl_path, package.replace("/", "").replace("\\", "").replace(":", "") + ".dlc"
   91       )
   92       dlc = flask.request.form["crypted"].replace(" ", "+")
   93 →     with open(dlc_path, mode="wb") as fp:
   94           fp.write(dlc)
   95   
   96       pack_password = flask.request.form.get("passwords")
   97   
   98       try:
   99           pack = api.add_package(package, [dlc_path], Destination.COLLECTOR)
  100       except Exception as exc:
  101           return "failed " + str(exc) + "\r\n", 500
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #12 — `cvefixes_path_traversal_ec5bad771cdea046` (cvefixes, CVE-2022-31564)

- **Repo:** https://github.com/woduq1414/munhak-moa
- **File path:** `app.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 35
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   27   else:
   28       isLocal = False
   29   
   30   app = Flask(__name__)
   31   
   32   
   33   def update():
   34   
   35 →         gc = gspread.authorize(credentials).open("문학따먹기")
   36   
   37           wks = gc.get_worksheet(0)
   38   
   39           rows = wks.get_all_values()
   40           print(rows)
   41           try:
   42   
   43               data = []
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #13 — `ghsa_path_traversal_6bd85ec7dd577584` (ghsa, CVE-2026-34242)

- **Repo:** WeblateOrg/weblate
- **File path:** `weblate/trans/views/files.py`
- **Framework:** django
- **Sink pattern recorded:** `\bos\.path\.join\s*\(`
- **Sink match position:** line 98
- **label_source / confidence:** ghsa / high

**Code excerpt:**

```python
   90                   continue
   91               components.add(translation.component_id)
   92               for filename in (
   93                   translation.component.template,
   94                   translation.component.new_base,
   95                   translation.component.intermediate,
   96               ):
   97                   if filename:
   98 →                     fullname = os.path.join(translation.component.full_path, filename)
   99                       if os.path.exists(fullname):
  100                           filenames.add(fullname)
  101   
  102       return zip_download(data_dir("vcs"), sorted(filenames), name, extra=extra)
  103   
  104   
  105   def download_component_list(request: AuthenticatedHttpRequest, name):
  106       obj = get_object_or_404(ComponentList, slug__iexact=name)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #14 — `cvefixes_path_traversal_0789ab575c07410b` (cvefixes, CVE-2021-43831)

- **Repo:** https://github.com/gradio-app/gradio
- **File path:** `networking.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 44
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   36   LOCALHOST_NAME = os.getenv(
   37       'GRADIO_SERVER_NAME', "127.0.0.1")
   38   GRADIO_API_SERVER = "https://api.gradio.app/v1/tunnel-request"
   39   GRADIO_FEATURE_ANALYTICS_URL = "https://api.gradio.app/gradio-feature-analytics/"
   40   
   41   STATIC_TEMPLATE_LIB = pkg_resources.resource_filename("gradio", "templates/")
   42   STATIC_PATH_LIB = pkg_resources.resource_filename("gradio", "templates/frontend/static")
   43   VERSION_FILE = pkg_resources.resource_filename("gradio", "version.txt")
   44 → with open(VERSION_FILE) as version_file:
   45       GRADIO_STATIC_ROOT = "https://gradio.s3-us-west-2.amazonaws.com/" + \
   46           version_file.read().strip() + "/static/"
   47   
   48   app = Flask(__name__,
   49               template_folder=STATIC_TEMPLATE_LIB,
   50               static_folder="",
   51               static_url_path="/none/")
   52   app.url_map.strict_slashes = False
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #15 — `ghsa_db_path_traversal_39df6590bfc5fe0c` (ghsa_db, CVE-2024-7340)

- **Repo:** wandb/weave
- **File path:** `weave/weave_server.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bsend_from_directory\s*\(`
- **Sink match position:** line 411
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  403           "/" / pathlib.Path(path)
  404       )  # add preceding slash as werkzeug strips this by default and it is reappended below in send_from_directory
  405       try:
  406           local_artifacts_path = pathlib.Path(filesystem.get_filesystem_dir()).absolute()
  407       except errors.WeaveAccessDeniedError:
  408           abort(403)
  409       if local_artifacts_path not in list(abspath.parents):
  410           abort(403)
  411 →     return send_from_directory("/", path)
  412   
  413   
  414   @blueprint.before_request
  415   def _disable_eager_mode():
  416       context_state._eager_mode.set(False)
  417   
  418   
  419   def frontend_env():
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-502 — Deserialization of Untrusted Data

Sampled: **6** / 78 on disk.

### #1 — `ghsa_db_insecure_deserialization_24957e3290c4752b` (ghsa_db, CVE-2023-23930)

- **Repo:** vantage6/vantage6
- **File path:** `vantage6-node/vantage6/node/docker/task_manager.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 292
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  284                   algo_image_name=self.image
  285               )
  286   
  287           # try reading docker input
  288           deserialized_input = None
  289           if self.docker_input:
  290               self.log.debug("Deserialize input")
  291               try:
  292 →                 deserialized_input = pickle.loads(self.docker_input)
  293               except Exception:
  294                   pass
  295   
  296           # attempt to run the image
  297           try:
  298               if deserialized_input:
  299                   self.log.info(f"Run docker image {self.image} with input "
  300                                 f"{self._printable_input(deserialized_input)}")
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_insecure_deserialization_0e39609207c8a114` (ghsa_db, CVE-2017-16618)

- **Repo:** tadashi-aikawa/owlmixin
- **File path:** `owlmixin/util.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\byaml\.load\s*\((?!.*safe_load)`
- **Sink match position:** line 96
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   88           return json.load(f)
   89   
   90   
   91   def load_yaml(yaml_str):
   92       """
   93       :param unicode yaml_str:
   94       :rtype: dict | list
   95       """
   96 →     return yaml.load(yaml_str)
   97   
   98   
   99   def load_yamlf(fpath, encoding):
  100       """
  101       :param unicode fpath:
  102       :param unicode encoding:
  103       :rtype: dict | list
  104       """
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `ghsa_db_insecure_deserialization_845e0a651d58cfcc` (ghsa_db, CVE-2023-23930)

- **Repo:** vantage6/vantage6
- **File path:** `vantage6-client/vantage6/client/__init__.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 2253
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
 2245           # Encryption is not done at the client level for the container.
 2246           # Although I am not completely sure that the format is always
 2247           # a pickle.
 2248           # for result in results:
 2249           #     self._decrypt_result(result)
 2250           #     res.append(result.get("result"))
 2251           #
 2252           try:
 2253 →             res = [pickle.loads(base64s_to_bytes(result.get("result")))
 2254                      for result in results if result.get("result")]
 2255           except Exception as e:
 2256               self.log.error('Unable to unpickle result')
 2257               self.log.debug(e)
 2258   
 2259           return res
 2260   
 2261       def get_algorithm_addresses(self, task_id: int):
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `ghsa_db_insecure_deserialization_e1ddf825a245fadc` (ghsa_db, CVE-2025-58757)

- **Repo:** Project-MONAI/MONAI
- **File path:** `monai/data/dataset.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 667
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  659               # this runs on multiple processes, each one should have its own env.
  660               self._read_env = self._fill_cache_start_reader(show_progress=False)
  661           with self._read_env.begin(write=False) as txn:
  662               data = txn.get(self.hash_func(item_transformed))
  663           if data is None:
  664               warnings.warn("LMDBDataset: cache key not found, running fallback caching.")
  665               return super()._cachecheck(item_transformed)
  666           try:
  667 →             return pickle.loads(data)
  668           except Exception as err:
  669               raise RuntimeError("Invalid cache value, corrupted lmdb file?") from err
  670   
  671       def info(self):
  672           """
  673           Returns: dataset info dictionary.
  674   
  675           """
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `ghsa_db_insecure_deserialization_d0f8ec9233989c9c` (ghsa_db, CVE-2023-23930)

- **Repo:** vantage6/vantage6
- **File path:** `vantage6-client/vantage6/client/deserialization.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 58
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   50   
   51   @deserializer('json')
   52   def deserialize_json(file):
   53       return json.loads(file)
   54   
   55   
   56   @deserializer('pickle')
   57   def deserialize_pickle(file):
   58 →     return pickle.loads(file)
   59   
   60   
   61   def unpack_legacy_results(result):
   62       return pickle.loads(result.get("result"))
   63   
   64   
   65   def load_data(input_bytes: bytes):
   66       """
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `ghsa_db_insecure_deserialization_24207d69a1016c4c` (ghsa_db, CVE-2025-61765)

- **Repo:** miguelgrinberg/python-socketio
- **File path:** `src/socketio/pubsub_manager.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 201
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  193               try:
  194                   for message in self._listen():
  195                       data = None
  196                       if isinstance(message, dict):
  197                           data = message
  198                       else:
  199                           if isinstance(message, bytes):  # pragma: no cover
  200                               try:
  201 →                                 data = pickle.loads(message)
  202                               except:
  203                                   pass
  204                           if data is None:
  205                               try:
  206                                   data = json.loads(message)
  207                               except:
  208                                   pass
  209                       if data and 'method' in data:
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-78 — OS Command Injection

Sampled: **17** / 25 on disk.

### #1 — `ghsa_db_command_injection_68fead03fd4240d5` (ghsa_db, CVE-2023-38673)

- **Repo:** PaddlePaddle/Paddle
- **File path:** `python/paddle/distributed/utils/launch_utils.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bos\.(system|popen|spawn[lpvP])\s*\(`
- **Sink match position:** line 488
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  480           logger.debug(f"trainer proc env:{current_env}")
  481   
  482           cmd = [sys.executable, "-u", training_script] + training_script_args
  483   
  484           logger.info(f"start trainer proc:{cmd} env:{proc_env}")
  485   
  486           fn = None
  487           if log_dir is not None:
  488 →             os.system(f"mkdir -p {log_dir}")
  489               fn = open("%s/workerlog.%d" % (log_dir, idx), "a")
  490               proc = subprocess.Popen(cmd, env=current_env, stdout=fn, stderr=fn)
  491           else:
  492               proc = subprocess.Popen(cmd, env=current_env)
  493   
  494           tp = TrainerProc()
  495           tp.proc = proc
  496           tp.rank = t.rank
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_command_injection_496139209d95463a` (ghsa_db, CVE-2023-38673)

- **Repo:** PaddlePaddle/Paddle
- **File path:** `python/paddle/distributed/fleet/utils/fs.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bos\.(system|popen|spawn[lpvP])\s*\(`
- **Sink match position:** line 177
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  169   
  170                   client = LocalFS()
  171                   client.mkdirs("test_mkdirs")
  172                   client.delete("test_mkdirs")
  173           """
  174           assert not os.path.isfile(fs_path), "{} is already a file".format(
  175               fs_path
  176           )
  177 →         os.system(f"mkdir -p {fs_path}")
  178   
  179       def rename(self, fs_src_path, fs_dst_path):
  180           """
  181           Rename the file.
  182   
  183           Args:
  184               fs_src_path(str): The actual name of the file or directory
  185               fs_dst_path(str): The new name of the file or directory.
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `ghsa_db_command_injection_generic_fbe083681810f0c6` (ghsa_db, CVE-2026-30625)

- **Repo:** Upsonic/Upsonic
- **File path:** `src/upsonic/ralph/tools/filesystem.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True`
- **Sink match position:** line 431
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  423           Args:
  424               command: Shell command to execute
  425               timeout: Maximum execution time in seconds
  426           
  427           Returns:
  428               Command output (stdout and stderr)
  429           """
  430           try:
  431 →             result = subprocess.run(
  432                   command,
  433                   shell=True,
  434                   cwd=self.workspace,
  435                   capture_output=True,
  436                   text=True,
  437                   timeout=timeout,
  438               )
  439               
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `ghsa_db_command_injection_2f8c29cde2cf1b76` (ghsa_db, CVE-2024-34073)

- **Repo:** aws/sagemaker-python-sdk
- **File path:** `src/sagemaker/serve/save_retrive/version_1_0_0/save/utils.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bos\.(system|popen|spawn[lpvP])\s*\(`
- **Sink match position:** line 104
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   96           sagemaker_dependency = f"{sagemaker.__package__}=={sagemaker.__version__}"
   97           with open(requirements_path, "w") as f:
   98               f.write(sagemaker_dependency)
   99           return
  100   
  101       command = f"pigar gen -f {Path(requirements_path)} {os.getcwd()}"
  102       logging.info("Running command %s", command)
  103   
  104 →     os.system(command)
  105       logger.info("Dependencies captured successfully")
  106   
  107   
  108   def capture_optimization_metadata(model: Model, framework) -> dict:
  109       """Placeholder docstring"""
  110       logging.info("Capturing optimization metadata...")
  111       # get size of the model
  112       model_size = sys.getsizeof(model)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `ghsa_db_command_injection_a37da00713dd6775` (ghsa_db, CVE-2021-43857)

- **Repo:** Gerapy/Gerapy
- **File path:** `gerapy/server/core/views.py`
- **Framework:** django
- **Sink pattern recorded:** `\bPopen\s*\(`
- **Sink match position:** line 259
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  251           data = json.loads(request.body)
  252           configuration = json.dumps(data.get('configuration'), ensure_ascii=False)
  253           project.update(**{'configuration': configuration})
  254           
  255           # for safe protection
  256           project_name = re.sub('[\!\@\#\$\;\&\*\~\"\'\{\}\]\[\-\+\%\^]+', '', project_name)
  257           # execute generate cmd
  258           cmd = ' '.join(['gerapy', 'generate', project_name])
  259 →         p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
  260           stdout, stderr = bytes2str(p.stdout.read()), bytes2str(p.stderr.read())
  261           
  262           if not stderr:
  263               return JsonResponse({'status': '1'})
  264           else:
  265               return JsonResponse({'status': '0', 'message': stderr})
  266   
  267   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `ghsa_db_command_injection_b8cbcfb48e694216` (ghsa_db, CVE-2024-52803)

- **Repo:** hiyouga/LLaMA-Factory
- **File path:** `src/llamafactory/webui/runner.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bPopen\s*\(`
- **Sink match position:** line 323
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  315               save_args(os.path.join(args["output_dir"], LLAMABOARD_CONFIG), self._form_config_dict(data))
  316   
  317               env = deepcopy(os.environ)
  318               env["LLAMABOARD_ENABLED"] = "1"
  319               env["LLAMABOARD_WORKDIR"] = args["output_dir"]
  320               if args.get("deepspeed", None) is not None:
  321                   env["FORCE_TORCHRUN"] = "1"
  322   
  323 →             self.trainer = Popen(f"llamafactory-cli train {save_cmd(args)}", env=env, shell=True)
  324               yield from self.monitor()
  325   
  326       def _form_config_dict(self, data: Dict["Component", Any]) -> Dict[str, Any]:
  327           config_dict = {}
  328           skip_ids = ["top.lang", "top.model_path", "train.output_dir", "train.config_path"]
  329           for elem, value in data.items():
  330               elem_id = self.manager.get_id_by_elem(elem)
  331               if elem_id not in skip_ids:
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `cvefixes_command_injection_caf21169f6b44e9c` (cvefixes, CVE-2022-1813)

- **Repo:** https://github.com/yogeshojha/rengine
- **File path:** `common_func.py`
- **Framework:** django
- **Sink pattern recorded:** `\bos\.(system|popen|spawn[lpvP])\s*\(`
- **Sink match position:** line 672
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  664               'message': 'Domain ' + ip_domain + ' does not exist as target and could not fetch WHOIS from database.'
  665           }
  666   
  667   
  668   def get_cms_details(url):
  669       # this function will fetch cms details using cms_detector
  670       response = {}
  671       cms_detector_command = 'python3 /usr/src/github/CMSeeK/cmseek.py -u {} --random-agent --batch --follow-redirect'.format(url)
  672 →     os.system(cms_detector_command)
  673   
  674       response['status'] = False
  675       response['message'] = 'Could not detect CMS!'
  676   
  677       parsed_url = urlparse(url)
  678   
  679       domain_name = parsed_url.hostname
  680       port = parsed_url.port
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #8 — `ghsa_db_command_injection_generic_71c8897d94963984` (ghsa_db, CVE-2024-0817)

- **Repo:** PaddlePaddle/Paddle
- **File path:** `python/paddle/base/framework.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True`
- **Sink match position:** line 5657
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
 5649               marked_nodes(set(IrNode)): nodes that are needed to be marked.
 5650               Default value is None.
 5651               remove_ctr_var(bool): If it is set True, all control variable nodes
 5652               in the graph will be removed. Default value is True.
 5653           """
 5654   
 5655           def _convert_to_pdf(dot_file_path):
 5656               pdf_save_path = os.path.splitext(dot_file_path)[0] + '.pdf'
 5657 →             exited_code = subprocess.call(
 5658                   'dot -Tpdf ' + dot_file_path + ' -o ' + pdf_save_path,
 5659                   shell=True,
 5660               )
 5661               if exited_code != 0:
 5662                   print('The dot command is needed for creating pdf files.')
 5663                   print(f'The {dot_file_path} is saved as the dot filetype.')
 5664   
 5665           remove_ctr_vars = set()
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `cvefixes_command_injection_bfdbfe150af8a07c` (cvefixes, CVE-2021-21386)

- **Repo:** https://github.com/dwisiswant0/apkleaks
- **File path:** `apkleaks.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bos\.(system|popen|spawn[lpvP])\s*\(`
- **Sink match position:** line 88
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   80   		with ZipFile(self.file) as zipped:
   81   			try:
   82   				dex = self.tempdir + "/" + self.apk.package + ".dex"
   83   				with open(dex, "wb") as classes:
   84   					classes.write(zipped.read("classes.dex"))
   85   			except Exception as e:
   86   				sys.exit(self.writeln(str(e), clr.WARNING))
   87   		dec = "%s %s -d %s --deobf" % (self.jadx, dex, self.tempdir)
   88 → 		os.system(dec)
   89   		return self.tempdir
   90   
   91   	def unique(self, list):
   92   		x = numpy.array(list)
   93   		return (numpy.unique(x))
   94   
   95   	def finder(self, pattern, path):
   96   		matcher = re.compile(pattern)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `vudenc_command_injection_4a5fc1bfb1666d9b` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\bPopen\s*\(`
- **Sink match position:** line 2
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def __call__(self, msg, arguments, errorSink=None):...
    2 → proc = subprocess.Popen(['host', arguments], stdout=subprocess.PIPE)
    3   output, _ = proc.communicate()
    4   output = output.decode().strip()
    5   self.reply(msg, output)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #11 — `ghsa_db_command_injection_5bcb53b471df1d00` (ghsa_db, CVE-2025-58180)

- **Repo:** OctoPrint/OctoPrint
- **File path:** `src/octoprint/events.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True`
- **Sink match position:** line 433
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  425           def commandExecutioner(cmd):
  426               if debug:
  427                   self._logger.info(f"Executing system command: {cmd}")
  428               else:
  429                   self._logger.info("Executing a system command")
  430               # we run this with shell=True since we have to trust whatever
  431               # our admin configured as command and since we want to allow
  432               # shell-alike handling here...
  433 →             subprocess.check_call(cmd, shell=True)
  434   
  435           def process():
  436               try:
  437                   if isinstance(command, (list, tuple, set)):
  438                       for c in command:
  439                           commandExecutioner(c)
  440                   else:
  441                       commandExecutioner(command)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #12 — `ghsa_db_command_injection_88fcd9b62c5e66a9` (ghsa_db, CVE-2021-21386)

- **Repo:** dwisiswant0/apkleaks
- **File path:** `apkleaks/apkleaks.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bos\.(system|popen|spawn[lpvP])\s*\(`
- **Sink match position:** line 88
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   80   		with ZipFile(self.file) as zipped:
   81   			try:
   82   				dex = self.tempdir + "/" + self.apk.package + ".dex"
   83   				with open(dex, "wb") as classes:
   84   					classes.write(zipped.read("classes.dex"))
   85   			except Exception as e:
   86   				sys.exit(self.writeln(str(e), clr.WARNING))
   87   		dec = "%s %s -d %s --deobf" % (self.jadx, dex, self.tempdir)
   88 → 		os.system(dec)
   89   		return self.tempdir
   90   
   91   	def unique(self, list): 
   92   		x = numpy.array(list) 
   93   		return (numpy.unique(x))
   94   
   95   	def finder(self, pattern, path):
   96   		matcher = re.compile(pattern)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #13 — `cvefixes_command_injection_16427fa7bf327903` (cvefixes, CVE-2012-3366)

- **Repo:** https://github.com/Bcfg2/bcfg2
- **File path:** `Trigger.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bos\.(system|popen|spawn[lpvP])\s*\(`
- **Sink match position:** line 12
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
    4   
    5   def async_run(prog, args):
    6       pid = os.fork()
    7       if pid:
    8           os.waitpid(pid, 0)
    9       else:
   10           dpid = os.fork()
   11           if not dpid:
   12 →             os.system(" ".join([prog] + args))
   13           os._exit(0)
   14   
   15   
   16   class Trigger(Bcfg2.Server.Plugin.Plugin,
   17                 Bcfg2.Server.Plugin.Statistics):
   18       """Trigger is a plugin that calls external scripts (on the server)."""
   19       name = 'Trigger'
   20       __version__ = '$Id'
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #14 — `vudenc_command_injection_9a5d91641fe5fe46` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\bos\.(system|popen|spawn[lpvP])\s*\(`
- **Sink match position:** line 10
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    2   """docstring"""
    3   base = os.path.basename(url)
    4   print('Fetching %s...' % base)
    5   fetch_file(url + '.asc')
    6   fetch_file(url)
    7   fetch_file(url + '.sha256')
    8   fetch_file(url + '.asc.sha256')
    9   print('Verifying %s...' % base)
   10 → os.system('shasum -c %s.sha256' % base)
   11   os.system('shasum -c %s.asc.sha256' % base)
   12   os.system('gpg --verify %s.asc %s' % (base, base))
   13   os.system('keybase verify %s.asc' % base)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #15 — `vudenc_command_injection_6015c051da837a13` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\bos\.(system|popen|spawn[lpvP])\s*\(`
- **Sink match position:** line 4
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def install(filename, target):...
    2   """docstring"""
    3   print(' Unpacking %s...' % filename)
    4 → os.system('tar xf ' + filename)
    5   basename = filename.split('.tar')[0]
    6   print(' Installing %s...' % basename)
    7   install_opts = '--prefix=${PWD}/%s --disable-ldconfig' % target
    8   os.system('%s/install.sh %s' % (basename, install_opts))
    9   print(' Cleaning %s...' % basename)
   10   os.system('rm -rf %s' % basename)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #16 — `ghsa_db_command_injection_5d9b7f877a0f38ee` (ghsa_db, CVE-2023-38673)

- **Repo:** PaddlePaddle/Paddle
- **File path:** `python/paddle/distributed/fleet/launch_utils.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bos\.(system|popen|spawn[lpvP])\s*\(`
- **Sink match position:** line 599
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  591               logger.info(
  592                   "details about PADDLE_TRAINER_ENDPOINTS can be found in "
  593                   "{}/endpoints.log, and detail running logs maybe found in "
  594                   "{}/workerlog.0".format(log_dir, log_dir)
  595               )
  596           fn = None
  597           pre_fn = None if os.name == 'nt' else os.setsid
  598           if log_dir is not None:
  599 →             os.system(f"mkdir -p {log_dir}")
  600               if os.path.exists("%s/endpoints.log" % log_dir):
  601                   os.system(f"rm -f {log_dir}/endpoints.log")
  602               with open("%s/endpoints.log" % log_dir, "w") as f:
  603                   f.write("PADDLE_TRAINER_ENDPOINTS: \n")
  604                   f.write("\n".join(cluster.trainers_endpoints()))
  605               if (
  606                   current_env.get("PADDLE_ENABLE_AUTO_MAPPING") is not None
  607                   and current_env.get("PADDLE_NEED_RANK_MAPPING").lower()
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #17 — `ghsa_db_command_injection_698703652e80f562` (ghsa_db, CVE-2024-0815)

- **Repo:** PaddlePaddle/Paddle
- **File path:** `python/paddle/utils/download.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True`
- **Sink match position:** line 212
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  204               'http',
  205               'https',
  206           ), 'Only support https and http url'
  207           # using wget to download url
  208           tmp_fullname = shlex.quote(fullname + "_tmp")
  209           url = shlex.quote(url)
  210           # –user-agent
  211           command = f'wget -O {tmp_fullname} -t {DOWNLOAD_RETRY_LIMIT} {url}'
  212 →         subprc = subprocess.Popen(
  213               command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
  214           )
  215           _ = subprc.communicate()
  216   
  217           if subprc.returncode != 0:
  218               raise RuntimeError(
  219                   f'{command} failed. Please make sure `wget` is installed or {url} exists'
  220               )
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-79 — Cross-site Scripting

Sampled: **6** / 54 on disk.

### #1 — `ghsa_db_cross_site_scripting_fda8b3e4deefffc2` (ghsa_db, CVE-2023-48705)

- **Repo:** nautobot/nautobot
- **File path:** `nautobot/ipam/views.py`
- **Framework:** django
- **Sink pattern recorded:** `\bmark_safe\s*\(`
- **Sink match position:** line 587
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  579               '<p>This <a href="'
  580               + static("docs/models/ipam/prefix.html")
  581               + '#prefix-hierarchy">will be considered invalid data</a> in a future release.</p>'
  582           )
  583           if obj.parent and obj.parent.type != constants.PREFIX_ALLOWED_PARENT_TYPES[obj.type]:
  584               parent_edit_url = reverse("ipam:prefix_edit", kwargs={"pk": obj.parent.pk})
  585               messages.warning(
  586                   request,
  587 →                 mark_safe(
  588                       f'{obj} is a {obj.type.title()} prefix but its parent <a href="{obj.parent.get_absolute_url()}">'
  589                       f"{obj.parent}</a> is a {obj.parent.type.title()}. {warning_msg} "
  590                       f'Consider <a href="{edit_url}">changing the type of {obj}</a> and/or '
  591                       f'<a href="{parent_edit_url}">{obj.parent}</a> to resolve this issue.'
  592                   ),
  593               )
  594   
  595           invalid_children = obj.children.filter(
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_cross_site_scripting_5978cdf2e9cb27ba` (ghsa_db, CVE-2016-6519)

- **Repo:** openstack/manila-ui
- **File path:** `manila_ui/dashboards/admin/shares/tabs.py`
- **Framework:** django
- **Sink pattern recorded:** `\bmark_safe\s*\(`
- **Sink match position:** line 110
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  102               share_types = []
  103               exceptions.handle(self.request,
  104                                 _("Unable to retrieve share types"))
  105           # Convert dict with extra specs to friendly view
  106           for st in share_types:
  107               es_str = ""
  108               for k, v in st.extra_specs.iteritems():
  109                   es_str += "%s=%s\r\n<br />" % (k, v)
  110 →             st.extra_specs = mark_safe(es_str)
  111           return share_types
  112   
  113   
  114   class SecurityServiceTab(tabs.TableTab):
  115       table_classes = (tables.SecurityServiceTable,)
  116       name = _("Security Services")
  117       slug = "security_services_tab"
  118       template_name = "horizon/common/_detail_table.html"
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `ghsa_db_cross_site_scripting_8248d186b41f064c` (ghsa_db, CVE-2016-6519)

- **Repo:** openstack/manila-ui
- **File path:** `manila_ui/dashboards/admin/shares/tabs.py`
- **Framework:** django
- **Sink pattern recorded:** `\bmark_safe\s*\(`
- **Sink match position:** line 110
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  102               share_types = []
  103               exceptions.handle(self.request,
  104                                 _("Unable to retrieve share types"))
  105           # Convert dict with extra specs to friendly view
  106           for st in share_types:
  107               es_str = ""
  108               for k, v in st.extra_specs.iteritems():
  109                   es_str += "%s=%s\r\n<br />" % (k, v)
  110 →             st.extra_specs = mark_safe(es_str)
  111           return share_types
  112   
  113   
  114   class SecurityServiceTab(tabs.TableTab):
  115       table_classes = (tables.SecurityServiceTable,)
  116       name = _("Security Services")
  117       slug = "security_services_tab"
  118       template_name = "horizon/common/_detail_table.html"
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `ghsa_db_cross_site_scripting_47fd6fef55f5d696` (ghsa_db, CVE-2023-48705)

- **Repo:** nautobot/nautobot
- **File path:** `nautobot/utilities/tables.py`
- **Framework:** django
- **Sink pattern recorded:** `\bmark_safe\s*\(`
- **Sink match position:** line 174
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  166           default = kwargs.pop("default", "")
  167           visible = kwargs.pop("visible", False)
  168           if "attrs" not in kwargs:
  169               kwargs["attrs"] = {"td": {"class": "min-width"}}
  170           super().__init__(*args, default=default, visible=visible, **kwargs)
  171   
  172       @property
  173       def header(self):
  174 →         return mark_safe('<input type="checkbox" class="toggle" title="Toggle all" />')
  175   
  176   
  177   class BooleanColumn(tables.Column):
  178       """
  179       Custom implementation of BooleanColumn to render a nicely-formatted checkmark or X icon instead of a Unicode
  180       character.
  181       """
  182   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `ghsa_db_cross_site_scripting_a6d783e4656ff72b` (ghsa_db, CVE-2018-20244)

- **Repo:** apache/airflow
- **File path:** `airflow/www/views.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bMarkup\s*\(`
- **Sink match position:** line 109
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  101   
  102   if conf.getboolean('webserver', 'FILTER_BY_OWNER'):
  103       # filter_by_owner if authentication is enabled and filter_by_owner is true
  104       FILTER_BY_OWNER = not current_app.config['LOGIN_DISABLED']
  105   
  106   
  107   def dag_link(v, c, m, p):
  108       if m.dag_id is None:
  109 →         return Markup()
  110   
  111       dag_id = bleach.clean(m.dag_id)
  112       url = url_for(
  113           'airflow.graph',
  114           dag_id=dag_id,
  115           execution_date=m.execution_date)
  116       return Markup(
  117           '<a href="{}">{}</a>'.format(url, dag_id))
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `ghsa_db_cross_site_scripting_f1abcdb2fbd90201` (ghsa_db, CVE-2023-48705)

- **Repo:** nautobot/nautobot
- **File path:** `nautobot/core/templatetags/helpers.py`
- **Framework:** django
- **Sink pattern recorded:** `\bmark_safe\s*\(`
- **Sink match position:** line 102
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   94       Example:
   95           >>> placeholder("")
   96           '<span class="text-muted">&mdash;</span>'
   97           >>> placeholder("hello")
   98           "hello"
   99       """
  100       if value:
  101           return value
  102 →     return mark_safe(HTML_NONE)
  103   
  104   
  105   @library.filter()
  106   @register.filter()
  107   def add_html_id(element_str, id_str):
  108       """Add an HTML `id="..."` attribute to the given HTML element string.
  109   
  110       Args:
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-89 — SQL Injection

Sampled: **6** / 212 on disk.

### #1 — `vudenc_sql_injection_c841911542b9ec84` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 4
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def get_preset(conn, key):...
    2   cursor = conn.cursor()
    3   quer = 'ALTER TABLE Presets DROP COLUMN id;'
    4 → cursor.execute(quer)
    5   quer = (
    6       'ALTER TABLE Presets ADD COLUMN id INT AUTO_INCREMENT PRIMARY KEY NOT NULL FIRST;'
    7       )
    8   cursor.execute(quer)
    9   extable = Table('Presets')
   10   q = MySQLQuery.from_(extable).select(extable.querval).where(extable.id == key)
   11   print(q)
   12   quer = str(q)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `vudenc_sql_injection_db0e7ef98af6a39b` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 4
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def get_articles_by_subject(subject):...
    2   query = ("SELECT * FROM articles WHERE subject='" + subject +
    3       "' ORDER BY last_submitted DESC")
    4 → cur.execute(query)
    5   articles = cur.fetchall()
    6   return articles
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `vudenc_sql_injection_7a04d5a7c121cbe9` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 5
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def registerPlayer(name):...
    2   """docstring"""
    3   conn = connect()
    4   c = conn.cursor()
    5 → c.execute("INSERT INTO players (playerName) VALUES ('{}')".format(re.sub(
    6       "\\'", '', name)))
    7   conn.commit()
    8   conn.close()
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `vudenc_sql_injection_9932f9650e3158ee` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 7
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def deleteMatches():...
    2   """docstring"""
    3   conn = connect()
    4   c = conn.cursor()
    5   table = 'matches'
    6   playerTable = 'players'
    7 → c.execute('DELETE FROM %s;' % (table,))
    8   c.execute(
    9       """UPDATE %s SET wins = 0,
   10           loss = 0, matchesPlayed = 0""" % (
   11       playerTable,))
   12   conn.commit()
   13   conn.close()
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `vudenc_sql_injection_371ca4a296772c14` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 5
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def insert(key, value):...
    2   connection = psycopg2.connect(host=config['HOST'], port=config['PORT'],
    3       database=config['NAME'], user=config['USER'], password=config['PASSWORD'])
    4   cur = connection.cursor()
    5 → cur.execute("insert into reply_map values('{}', '{}')".format(key, value))
    6   connection.commit()
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `vudenc_sql_injection_53d3d5c4900691f2` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\bSELECT\b.*\bFROM\b`
- **Sink match position:** line 3
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def getPostsByPostid(self, postid):...
    2   sqlText = (
    3 →     'select users.name,post.comment from users,post where                 users.userid=post.userid and post.postid=%d'
    4        % postid)
    5   result = sql.queryDB(self.conn, sqlText)
    6   return result
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-918 — Server-Side Request Forgery

Sampled: **22** / 22 on disk.

### #1 — `cvefixes_ssrf_9a92b4176ccbdd6a` (cvefixes, CVE-2022-23071)

- **Repo:** https://github.com/TandoorRecipes/recipes
- **File path:** `recettetek.py`
- **Framework:** django
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 126
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  118               if file['pictures'][0] != '':
  119                   image_file_name = file['pictures'][0].split('/')[-1]
  120                   for f in self.files:
  121                       if '.rtk' in f['name']:
  122                           import_zip = ZipFile(f['file'])
  123                           self.import_recipe_image(recipe, BytesIO(import_zip.read(image_file_name)), filetype=get_filetype(image_file_name))
  124               else:
  125                   if file['originalPicture'] != '':
  126 →                     response = requests.get(file['originalPicture'])
  127                       if imghdr.what(BytesIO(response.content)) is not None:
  128                           self.import_recipe_image(recipe, BytesIO(response.content), filetype=get_filetype(file['originalPicture']))
  129                       else:
  130                           raise Exception("Original image failed to download.")
  131           except Exception as e:
  132               print(recipe.name, ': failed to import image ', str(e))
  133   
  134           return recipe
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `cvefixes_ssrf_831c3a4f8d1db546` (cvefixes, CVE-2022-23071)

- **Repo:** https://github.com/TandoorRecipes/recipes
- **File path:** `api.py`
- **Framework:** django
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 784
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  776               image = None
  777               filetype = ".jpeg" # fall-back to .jpeg, even if wrong, at least users will know it's an image and most image viewers can open it correctly anyways
  778   
  779               if 'image' in serializer.validated_data:
  780                   image = obj.image
  781                   filetype = mimetypes.guess_extension(serializer.validated_data['image'].content_type) or filetype
  782               elif 'image_url' in serializer.validated_data:
  783                   try:
  784 →                     response = requests.get(serializer.validated_data['image_url'])
  785                       image = File(io.BytesIO(response.content))
  786                       filetype = mimetypes.guess_extension(response.headers['content-type']) or filetype
  787                   except UnidentifiedImageError as e:
  788                       print(e)
  789                       pass
  790                   except MissingSchema as e:
  791                       print(e)
  792                       pass
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `nvd_ssrf_95b2c914c48b3b58` (nvd_targeted, CVE-2026-34981)

- **Repo:** pavelzbornik/whisperX-FastAPI
- **File path:** `app/services/file_service.py`
- **Framework:** fastapi
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 129
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  121   
  122           Raises:
  123               ValueError: If the URL is invalid or file extension is not allowed
  124               HTTPException: If download fails
  125           """
  126           logger.info("Downloading file from URL: %s", url)
  127   
  128           try:
  129 →             with requests.get(url, stream=True, timeout=30) as response:
  130                   response.raise_for_status()
  131   
  132                   # Check for filename in Content-Disposition header
  133                   content_disposition = response.headers.get("Content-Disposition")
  134                   if content_disposition and "filename=" in content_disposition:
  135                       filename = content_disposition.split("filename=")[1].strip('"')
  136                   else:
  137                       # Fall back to extracting from the URL path
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `nvd_ssrf_0f95dad7b4ada6b8` (nvd_targeted, CVE-2026-25991)

- **Repo:** TandoorRecipes/recipes
- **File path:** `cookbook/views/telegram.py`
- **Framework:** django
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 20
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   12   
   13   
   14   @group_required('user')
   15   def setup_bot(request, pk):
   16       bot = get_object_or_404(TelegramBot, pk=pk, space=request.space)
   17   
   18       hook_url = f'{request.build_absolute_uri("/")}telegram/hook/{bot.webhook_token}/'
   19   
   20 →     create_response = requests.get(f'https://api.telegram.org/bot{bot.token}/setWebhook?url={hook_url}')
   21       info_response = requests.get(f'https://api.telegram.org/bot{bot.token}/getWebhookInfo')
   22   
   23       return JsonResponse({'hook_url': hook_url, 'create_response': json.loads(create_response.content.decode()),
   24                           'info_response': json.loads(info_response.content.decode())}, json_dumps_params={'indent': 4})
   25   
   26   
   27   @group_required('user')
   28   def remove_bot(request, pk):
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `ghsa_db_ssrf_20ce87bf185f8ce5` (ghsa_db, CVE-2025-67743)

- **Repo:** LearningCircuit/local-deep-research
- **File path:** `src/local_deep_research/news/flask_api.py`
- **Framework:** flask
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 566
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  558           # Call the main research API endpoint (use the one from research blueprint)
  559           import requests
  560   
  561           # Get configured host and port from settings
  562           settings_manager = get_settings_manager()
  563           host = settings_manager.get_setting("web.host", "127.0.0.1")
  564           port = settings_manager.get_setting("web.port", 5000)
  565   
  566 →         response = requests.post(
  567               f"http://{host}:{port}/research/api/start_research",
  568               json=request_data,
  569               headers={"Content-Type": "application/json"},
  570           )
  571   
  572           if response.ok:
  573               data = response.json()
  574               if data.get("status") == "success":
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `nvd_ssrf_aa155dfaafb3652b` (nvd_targeted, CVE-2026-25991)

- **Repo:** TandoorRecipes/recipes
- **File path:** `cookbook/integration/plantoeat.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 79
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   71                   step.ingredients.add(Ingredient.objects.create(
   72                       food=f, unit=u, amount=amount, note=note, original_text=ingredient, space=self.request.space,
   73                   ))
   74           recipe.steps.add(step)
   75   
   76           if image_url:
   77               try:
   78                   if validate_import_url(image_url):
   79 →                     response = requests.get(image_url)
   80                       self.import_recipe_image(recipe, BytesIO(response.content))
   81               except Exception as e:
   82                   print('failed to import image ', str(e))
   83   
   84           return recipe
   85   
   86       def split_recipe_file(self, file):
   87           recipe_list = []
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `nvd_ssrf_5354a61d68f26fad` (nvd_targeted, CVE-2026-25991)

- **Repo:** TandoorRecipes/recipes
- **File path:** `cookbook/provider/nextcloud.py`
- **Framework:** django
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 82
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   74   
   75           headers = {
   76               "OCS-APIRequest": "true",
   77               "Content-Type": "application/x-www-form-urlencoded"
   78           }
   79   
   80           data = {'path': recipe.file_path, 'shareType': 3}
   81   
   82 →         r = requests.post(url, headers=headers, auth=HTTPBasicAuth(recipe.storage.username, recipe.storage.password), data=data)
   83   
   84           response_json = r.json()
   85   
   86           return response_json['ocs']['data']['url']
   87   
   88       @staticmethod
   89       def get_share_link(recipe):
   90           url = recipe.storage.url + '/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json&path=' + recipe.file_path  # noqa: E501
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #8 — `cvefixes_ssrf_6e9da019592a8c25` (cvefixes, CVE-2022-23071)

- **Repo:** https://github.com/TandoorRecipes/recipes
- **File path:** `dropbox.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 26
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   18               "Authorization": "Bearer " + monitor.storage.token,
   19               "Content-Type": "application/json"
   20           }
   21   
   22           data = {
   23               "path": monitor.path
   24           }
   25   
   26 →         r = requests.post(url, headers=headers, data=json.dumps(data))
   27           try:
   28               recipes = r.json()
   29           except ValueError:
   30               log_entry = SyncLog(status='ERROR', msg=str(r), sync=monitor)
   31               log_entry.save()
   32               return r
   33   
   34           import_count = 0
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `ghsa_db_ssrf_66f82f29d3908ed5` (ghsa_db, CVE-2025-67743)

- **Repo:** LearningCircuit/local-deep-research
- **File path:** `src/local_deep_research/web/routes/api_routes.py`
- **Framework:** flask
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 355
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  347               if raw_ollama_base_url
  348               else "http://localhost:11434"
  349           )
  350   
  351           logger.info(f"Checking Ollama status at: {ollama_base_url}")
  352   
  353           # Check if Ollama is running
  354           try:
  355 →             response = requests.get(f"{ollama_base_url}/api/tags", timeout=5)
  356   
  357               # Add response details for debugging
  358               logger.debug(
  359                   f"Ollama status check response code: {response.status_code}"
  360               )
  361   
  362               if response.status_code == 200:
  363                   # Try to validate the response content
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `nvd_ssrf_86e1e3b4e2b859bb` (nvd_targeted, CVE-2026-25991)

- **Repo:** TandoorRecipes/recipes
- **File path:** `cookbook/views/api.py`
- **Framework:** django
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 1026
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
 1018           food = self.get_object()
 1019   
 1020           if request.data['fdc_id']:
 1021               food.fdc_id = request.data['fdc_id']
 1022   
 1023           if not food.fdc_id:
 1024               return JsonResponse({'msg': 'Food has no FDC ID associated.'}, status=400, json_dumps_params={'indent': 4})
 1025   
 1026 →         response = requests.get(f'https://api.nal.usda.gov/fdc/v1/food/{food.fdc_id}?api_key={FDC_API_KEY}')
 1027           if response.status_code == 429:
 1028               return JsonResponse(
 1029                   {
 1030                       'msg':
 1031                           'API Key Rate Limit reached/exceeded, see https://api.data.gov/docs/rate-limits/ for more information. \
 1032                                   Configure your key in Tandoor using environment FDC_API_KEY variable.'
 1033                   },
 1034                   status=429,
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #11 — `nvd_ssrf_eace54f66847ad44` (nvd_targeted, CVE-2026-25991)

- **Repo:** TandoorRecipes/recipes
- **File path:** `cookbook/integration/recettetek.py`
- **Framework:** django
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 130
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  122                   for f in self.files:
  123                       if '.rtk' in f['name']:
  124                           import_zip = ZipFile(f['file'])
  125                           self.import_recipe_image(recipe, BytesIO(import_zip.read(image_file_name)), filetype=get_filetype(image_file_name))
  126               else:
  127                   if file['originalPicture'] != '':
  128                       url = file['originalPicture']
  129                       if validate_import_url(url):
  130 →                         response = requests.get(url)
  131                           if Image.open(BytesIO(response.content)).verify():
  132                               self.import_recipe_image(recipe, BytesIO(response.content), filetype=get_filetype(file['originalPicture']))
  133                           else:
  134                               raise Exception("Original image failed to download.")
  135           except Exception as e:
  136               print(recipe.name, ': failed to import image ', str(e))
  137   
  138           return recipe
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #12 — `cvefixes_ssrf_43b54a0f95b3bbbf` (cvefixes, CVE-2021-43780)

- **Repo:** https://github.com/getredash/redash
- **File path:** `excel.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 58
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   50               args.pop('user-agent', None)
   51   
   52               if is_private_address(path) and settings.ENFORCE_PRIVATE_ADDRESS_BLOCK:
   53                   raise Exception("Can't query private addresses.")
   54           except:
   55               pass
   56   
   57           try:
   58 →             response = requests.get(url=path, headers={"User-agent": ua})
   59               workbook = pd.read_excel(response.content, **args)
   60   
   61               df = workbook.copy()
   62               data = {'columns': [], 'rows': []}
   63               conversions = [
   64                   {'pandas_type': np.integer, 'redash_type': 'integer',},
   65                   {'pandas_type': np.inexact, 'redash_type': 'float',},
   66                   {'pandas_type': np.datetime64, 'redash_type': 'datetime', 'to_redash': lambda x: x.strftime('%Y-%m-%d %H:%M:%S')},
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #13 — `nvd_ssrf_3f43653827673eb8` (nvd_targeted, CVE-2021-43780)

- **Repo:** getredash/redash
- **File path:** `redash/query_runner/csv.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 62
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   54               args.pop('user-agent', None)
   55   
   56               if is_private_address(path) and settings.ENFORCE_PRIVATE_ADDRESS_BLOCK:
   57                   raise Exception("Can't query private addresses.")
   58           except:
   59               pass
   60   
   61           try:
   62 →             response = requests.get(url=path, headers={"User-agent": ua})
   63               workbook = pd.read_csv(io.BytesIO(response.content),sep=",", **args)
   64   
   65               df = workbook.copy()
   66               data = {'columns': [], 'rows': []}
   67               conversions = [
   68                   {'pandas_type': np.integer, 'redash_type': 'integer',},
   69                   {'pandas_type': np.inexact, 'redash_type': 'float',},
   70                   {'pandas_type': np.datetime64, 'redash_type': 'datetime', 'to_redash': lambda x: x.strftime('%Y-%m-%d %H:%M:%S')},
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #14 — `ghsa_db_ssrf_0f30c55624a32565` (ghsa_db, CVE-2026-26013)

- **Repo:** langchain-ai/langchain
- **File path:** `libs/partners/openai/langchain_openai/chat_models/base.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bhttpx\.\w+\s*\(`
- **Sink match position:** line 989
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  981                       try:
  982                           import httpx
  983                       except ImportError as e:
  984                           msg = (
  985                               "Could not import httpx python package. "
  986                               "Please install it with `pip install httpx`."
  987                           )
  988                           raise ImportError(msg) from e
  989 →                     self.http_client = httpx.Client(
  990                           proxy=self.openai_proxy, verify=global_ssl_context
  991                       )
  992                   sync_specific = {
  993                       "http_client": self.http_client
  994                       or _get_default_httpx_client(
  995                           self.openai_api_base, self.request_timeout
  996                       ),
  997                       "api_key": sync_api_key_value,
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #15 — `cvefixes_ssrf_5fe2f9a58da5379b` (cvefixes, CVE-2022-23071)

- **Repo:** https://github.com/TandoorRecipes/recipes
- **File path:** `recipesage.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 54
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   46                       u = ingredient_parser.get_unit(unit)
   47                       step.ingredients.add(Ingredient.objects.create(
   48                           food=f, unit=u, amount=amount, note=note, original_text=ingredient, space=self.request.space,
   49                       ))
   50               recipe.steps.add(step)
   51   
   52           if len(file['image']) > 0:
   53               try:
   54 →                 response = requests.get(file['image'][0])
   55                   self.import_recipe_image(recipe, BytesIO(response.content))
   56               except Exception as e:
   57                   print('failed to import image ', str(e))
   58   
   59           return recipe
   60   
   61       def get_file_from_recipe(self, recipe):
   62           data = {
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #16 — `nvd_ssrf_28873e0da4c04f6e` (nvd_targeted, CVE-2026-25991)

- **Repo:** TandoorRecipes/recipes
- **File path:** `cookbook/provider/dropbox.py`
- **Framework:** django
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 28
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   20               "Authorization": "Bearer " + monitor.storage.token,
   21               "Content-Type": "application/json"
   22           }
   23   
   24           data = {
   25               "path": monitor.path
   26           }
   27   
   28 →         r = requests.post(url, headers=headers, data=json.dumps(data))
   29           try:
   30               recipes = r.json()
   31           except ValueError:
   32               log_entry = SyncLog(status='ERROR', msg=str(r), sync=monitor)
   33               log_entry.save()
   34               return log_entry
   35   
   36           import_count = 0
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #17 — `cvefixes_ssrf_35abd6708dc42815` (cvefixes, CVE-2022-23071)

- **Repo:** https://github.com/TandoorRecipes/recipes
- **File path:** `cookbookapp.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 62
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   54               f = ingredient_parser.get_food(ingredient['ingredient']['text'])
   55               u = ingredient_parser.get_unit(ingredient['unit']['text'])
   56               step.ingredients.add(Ingredient.objects.create(
   57                   food=f, unit=u, amount=ingredient['amount'], note=ingredient['note'],  space=self.request.space,
   58               ))
   59   
   60           if len(images) > 0:
   61               try:
   62 →                 response = requests.get(images[0])
   63                   self.import_recipe_image(recipe, BytesIO(response.content))
   64               except Exception as e:
   65                   print('failed to import image ', str(e))
   66   
   67           recipe.save()
   68           return recipe
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #18 — `nvd_ssrf_cbf3875a88d13177` (nvd_targeted, CVE-2026-25991)

- **Repo:** TandoorRecipes/recipes
- **File path:** `cookbook/integration/cookbookapp.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 126
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  118                       pass
  119               if nutrition != {}:
  120                   recipe.nutrition = NutritionInformation.objects.create(**nutrition, space=self.request.space)
  121   
  122           # Try to import an image link, this may be blocked by cors or rate-limits
  123           if 'image' in recipe_json and len(recipe_json['image']) > 0:
  124               try:
  125                   url = recipe_json["image"]
  126 →                 response = requests.get(url)
  127                   self.import_recipe_image(recipe, BytesIO(response.content))
  128               except Exception as e:
  129                   print(f'Failed to import image for {recipe.name}', str(e))
  130   
  131           recipe.save()
  132           return recipe
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #19 — `ghsa_db_ssrf_e4d36275d8f974fa` (ghsa_db, CVE-2025-67743)

- **Repo:** LearningCircuit/local-deep-research
- **File path:** `src/local_deep_research/web/routes/settings_routes.py`
- **Framework:** flask
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 1115
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
 1107                       "llm.ollama.url", "http://localhost:11434"
 1108                   )
 1109                   base_url = (
 1110                       normalize_url(raw_base_url)
 1111                       if raw_base_url
 1112                       else "http://localhost:11434"
 1113                   )
 1114   
 1115 →                 ollama_response = requests.get(
 1116                       f"{base_url}/api/tags", timeout=5
 1117                   )
 1118   
 1119                   logger.debug(
 1120                       f"Ollama API response: Status {ollama_response.status_code}"
 1121                   )
 1122   
 1123                   # Try to parse the response even if status code is not 200 to help with debugging
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #20 — `cvefixes_ssrf_2661f2e20ff3c8bc` (cvefixes, CVE-2022-23071)

- **Repo:** https://github.com/TandoorRecipes/recipes
- **File path:** `cookmate.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 67
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   59                   f = ingredient_parser.get_food(food)
   60                   u = ingredient_parser.get_unit(unit)
   61                   recipe.steps.first().ingredients.add(Ingredient.objects.create(
   62                       food=f, unit=u, amount=amount, note=note, original_text=ingredient.text.strip(), space=self.request.space,
   63                   ))
   64   
   65           if recipe_xml.find('imageurl') is not None:
   66               try:
   67 →                 response = requests.get(recipe_xml.find('imageurl').text.strip())
   68                   self.import_recipe_image(recipe, BytesIO(response.content))
   69               except Exception as e:
   70                   print('failed to import image ', str(e))
   71   
   72           recipe.save()
   73   
   74           return recipe
   75   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #21 — `nvd_ssrf_981204e6a61dd1e8` (nvd_targeted, CVE-2026-25991)

- **Repo:** TandoorRecipes/recipes
- **File path:** `cookbook/integration/cookmate.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 73
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   65                           ingredient_step.ingredients.add(Ingredient.objects.create(
   66                               food=f, unit=u, amount=amount, note=note, original_text=ingredient.text.strip(), space=self.request.space,
   67                           ))
   68   
   69           if recipe_xml.find('imageurl') is not None:
   70               try:
   71                   url = recipe_xml.find('imageurl').text.strip()
   72                   if validate_import_url(url):
   73 →                     response = requests.get(url)
   74                   self.import_recipe_image(recipe, BytesIO(response.content))
   75               except Exception as e:
   76                   print('failed to import image ', str(e))
   77   
   78           recipe.save()
   79   
   80           return recipe
   81   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #22 — `nvd_ssrf_ba2192221f3a3f57` (nvd_targeted, CVE-2026-25991)

- **Repo:** TandoorRecipes/recipes
- **File path:** `cookbook/integration/recipesage.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 60
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   52                           food=f, unit=u, amount=amount, note=note, original_text=ingredient, space=self.request.space,
   53                       ))
   54               recipe.steps.add(step)
   55   
   56           if len(file['image']) > 0:
   57               try:
   58                   url = file['image'][0]
   59                   if validate_import_url(url):
   60 →                     response = requests.get(url)
   61                       self.import_recipe_image(recipe, BytesIO(response.content))
   62               except Exception as e:
   63                   print('failed to import image ', str(e))
   64   
   65           return recipe
   66   
   67       def get_file_from_recipe(self, recipe):
   68           data = {
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-94 — Code Injection

Sampled: **6** / 36 on disk.

### #1 — `ghsa_db_code_injection_34b296214315bfbf` (ghsa_db, CVE-2024-4181)

- **Repo:** run-llama/llama_index
- **File path:** `llama-index-integrations/llms/llama-index-llms-rungpt/llama_index/llms/rungpt/base.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 156
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  148                   "Please install requests with `pip install sseclient-py`"
  149               )
  150           client = sseclient.SSEClient(response_gpt)
  151           response_iter = client.events()
  152   
  153           def gen() -> CompletionResponseGen:
  154               text = ""
  155               for item in response_iter:
  156 →                 item_dict = json.loads(json.dumps(eval(item.data)))
  157                   delta = item_dict["choices"][0]["text"]
  158                   additional_kwargs = item_dict["usage"]
  159                   text = text + self._space_handler(delta)
  160                   yield CompletionResponse(
  161                       text=text,
  162                       delta=delta,
  163                       raw=item_dict,
  164                       additional_kwargs=additional_kwargs,
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_code_injection_4ab4bf0aaf4b4f5a` (ghsa_db, CVE-2018-8097)

- **Repo:** pyeve/eve
- **File path:** `eve/io/mongo/parser.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 134
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  126               if node.func.id == 'ObjectId':
  127                   expr = "('" + node.args[0].s + "')"
  128               elif node.func.id == 'datetime':
  129                   values = []
  130                   for arg in node.args:
  131                       values.append(str(arg.n))
  132                   expr = "(" + ", ".join(values) + ")"
  133               if expr:
  134 →                 self.current_value = eval(node.func.id + expr)
  135   
  136       def visit_Attribute(self, node):
  137           """ Attribute handler ('Contact.Id').
  138           """
  139           self.visit(node.value)
  140           self.current_value += "." + node.attr
  141   
  142       def visit_Name(self, node):
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `ghsa_db_code_injection_c80cfaedc6c2c08b` (ghsa_db, CVE-2023-36258)

- **Repo:** langchain-ai/langchain
- **File path:** `libs/langchain/langchain/experimental/cpal/models.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bexec\s*\(`
- **Sink match position:** line 193
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  185           entity_scope = {
  186               entity.name: entity for entity in self.causal_operations.entities
  187           }
  188           for entity in self.causal_operations.entities:
  189               if entity.code == "pass":
  190                   continue
  191               else:
  192                   # gist.github.com/dean0x7d/df5ce97e4a1a05be4d56d1378726ff92
  193 →                 exec(entity.code, globals(), entity_scope)
  194           row_values = [entity.dict() for entity in entity_scope.values()]
  195           self._outcome_table = pd.DataFrame(row_values)
  196   
  197       def _run_query(self) -> None:
  198           def humanize_sql_error_msg(error: str) -> str:
  199               pattern = r"column\s+(.*?)\s+not found"
  200               col_match = re.search(pattern, error)
  201               if col_match:
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `nvd_code_injection_4ab4bf0aaf4b4f5a` (nvd_targeted, CVE-2018-8097)

- **Repo:** pyeve/eve
- **File path:** `eve/io/mongo/parser.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 134
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  126               if node.func.id == 'ObjectId':
  127                   expr = "('" + node.args[0].s + "')"
  128               elif node.func.id == 'datetime':
  129                   values = []
  130                   for arg in node.args:
  131                       values.append(str(arg.n))
  132                   expr = "(" + ", ".join(values) + ")"
  133               if expr:
  134 →                 self.current_value = eval(node.func.id + expr)
  135   
  136       def visit_Attribute(self, node):
  137           """ Attribute handler ('Contact.Id').
  138           """
  139           self.visit(node.value)
  140           self.current_value += "." + node.attr
  141   
  142       def visit_Name(self, node):
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `ghsa_db_code_injection_f65e6d726dcfed78` (ghsa_db, CVE-2023-36258)

- **Repo:** langchain-ai/langchain
- **File path:** `langchain/utilities/python.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bexec\s*\(`
- **Sink match position:** line 19
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   11       globals: Optional[Dict] = Field(default_factory=dict, alias="_globals")
   12       locals: Optional[Dict] = Field(default_factory=dict, alias="_locals")
   13   
   14       def run(self, command: str) -> str:
   15           """Run command with own globals/locals and returns anything printed."""
   16           old_stdout = sys.stdout
   17           sys.stdout = mystdout = StringIO()
   18           try:
   19 →             exec(command, self.globals, self.locals)
   20               sys.stdout = old_stdout
   21               output = mystdout.getvalue()
   22           except Exception as e:
   23               sys.stdout = old_stdout
   24               output = repr(e)
   25           return output
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `ghsa_db_code_injection_1380767e00065d83` (ghsa_db, CVE-2022-21797)

- **Repo:** joblib/joblib
- **File path:** `joblib/parallel.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 1054
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
 1046   
 1047           if pre_dispatch == 'all' or n_jobs == 1:
 1048               # prevent further dispatch via multiprocessing callback thread
 1049               self._original_iterator = None
 1050               self._pre_dispatch_amount = 0
 1051           else:
 1052               self._original_iterator = iterator
 1053               if hasattr(pre_dispatch, 'endswith'):
 1054 →                 pre_dispatch = eval(
 1055                       pre_dispatch,
 1056                       {"n_jobs": n_jobs, "__builtins__": {}},  # globals
 1057                       {}  # locals
 1058                   )
 1059               self._pre_dispatch_amount = pre_dispatch = int(pre_dispatch)
 1060   
 1061               # The main thread will consume the first pre_dispatch items and
 1062               # the remaining items will later be lazily dispatched by async
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---
