# Stage-1 Sample Audit Pack — 2026-05-13 10:44 UTC

Per-CWE spot-check of label correctness. For each sample below, read
the code excerpt and decide:

- **PASS** — the labeled CWE matches what the code actually does
- **FAIL** — the code does not exhibit the labeled CWE (note the actual CWE
  or the reason: e.g. "sink call but no taint flow", "test fixture",
  "unrelated co-changed file", etc.)

Sampled with seed=7. Per-CWE sampling: 10 for
populous classes, ALL for classes with ≤30 samples.

Canonical samples are excluded from the audit (they are hand-curated
textbook positives by construction).

---

## Summary

| CWE | Active | Sampled | Audit FP rate (filled after audit) |
|---|---:|---:|---|
| CWE-22 (Path Traversal) | 52 | 10 | __/__ |
| CWE-502 (Deserialization of Untrusted Data) | 90 | 10 | __/__ |
| CWE-78 (OS Command Injection) | 49 | 10 | __/__ |
| CWE-79 (Cross-site Scripting) | 170 | 10 | __/__ |
| CWE-89 (SQL Injection) | 268 | 10 | __/__ |
| CWE-918 (Server-Side Request Forgery) | 54 | 10 | __/__ |
| CWE-94 (Code Injection) | 55 | 10 | __/__ |
| safe (safe) | 429 | 0 | __/__ |

---

## CWE-22 — Path Traversal

Sampled: **10** / 52 on disk.

### #1 — `ghsa_db_path_traversal_e17be4061de81eac` (ghsa_db, CVE-2024-8859)

- **Repo:** mlflow/mlflow
- **File path:** `mlflow/server/handlers.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 1529
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
 1521           artifact_repo.log_artifact(file, path_to_log)
 1522   
 1523       with tempfile.TemporaryDirectory() as tmpdir:
 1524           dir_path = os.path.join(tmpdir, dirname) if dirname else tmpdir
 1525           file_path = os.path.join(dir_path, basename)
 1526   
 1527           os.makedirs(dir_path, exist_ok=True)
 1528   
 1529 →         with open(file_path, "wb") as f:
 1530               f.write(data)
 1531   
 1532           _log_artifact_to_repo(file_path, run, dirname, artifact_dir)
 1533   
 1534       return Response(mimetype="application/json")
 1535   
 1536   
 1537   @catch_mlflow_exception
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_path_traversal_3c339e08f1532e0d` (ghsa_db, CVE-2025-11201)

- **Repo:** mlflow/mlflow
- **File path:** `mlflow/server/handlers.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 1591
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
 1583           artifact_repo.log_artifact(file, path_to_log)
 1584   
 1585       with tempfile.TemporaryDirectory() as tmpdir:
 1586           dir_path = os.path.join(tmpdir, dirname) if dirname else tmpdir
 1587           file_path = os.path.join(dir_path, basename)
 1588   
 1589           os.makedirs(dir_path, exist_ok=True)
 1590   
 1591 →         with open(file_path, "wb") as f:
 1592               f.write(data)
 1593   
 1594           _log_artifact_to_repo(file_path, run, dirname, artifact_dir)
 1595   
 1596       return Response(mimetype="application/json")
 1597   
 1598   
 1599   @catch_mlflow_exception
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `ghsa_db_path_traversal_dd06c5375d83b34e` (ghsa_db, CVE-2020-25074)

- **Repo:** moinwiki/moin-1.9
- **File path:** `MoinMoin/action/cache.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 213
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  205       meta_cache = caching.CacheEntry(request, cache_arena, key+'.meta', cache_scope, do_locking=do_locking, use_pickle=True)
  206       meta = meta_cache.content()
  207       return meta['last_modified'], meta['headers']
  208   
  209   
  210   def _get_datafile(request, key):
  211       """ get an open data file for the data cached for key """
  212       data_cache = caching.CacheEntry(request, cache_arena, key+'.data', cache_scope, do_locking=do_locking)
  213 →     data_cache.open(mode='r')
  214       return data_cache
  215   
  216   
  217   def _do_get(request, key):
  218       """ send a complete http response with headers/data cached for key """
  219       try:
  220           last_modified, headers = _get_headers(request, key)
  221           if datetime.utcfromtimestamp(int(last_modified)) == request.if_modified_since:
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `osv_path_traversal_30a05a5a5d78eff6` (osv, CVE-2024-39330)

- **Repo:** django/django
- **File path:** `tests/file_uploads/tests.py`
- **Framework:** django
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 89
- **label_source / confidence:** osv / high

**Code excerpt:**

```python
   81                       "c:\\tmp\\.",
   82                   ]
   83               )
   84           for file_name in candidates:
   85               with self.subTest(file_name=file_name):
   86                   self.assertRaises(SuspiciousFileOperation, UploadedFile, name=file_name)
   87   
   88       def test_simple_upload(self):
   89 →         with open(__file__, "rb") as fp:
   90               post_data = {
   91                   "name": "Ringo",
   92                   "file_field": fp,
   93               }
   94               response = self.client.post("/upload/", post_data)
   95           self.assertEqual(response.status_code, 200)
   96   
   97       def test_large_upload(self):
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `ghsa_db_path_traversal_1ed5a24f87906225` (ghsa_db, CVE-2025-58162)

- **Repo:** MobSF/Mobile-Security-Framework-MobSF
- **File path:** `mobsf/DynamicAnalyzer/views/common/device.py`
- **Framework:** django
- **Sink pattern recorded:** `\bPath\s*\(`
- **Sink match position:** line 52
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   44               fil = request.GET['file']
   45               md5_hash = request.GET['hash']
   46               typ = request.GET['type']
   47           if not is_md5(md5_hash):
   48               return print_n_send_error_response(
   49                   request,
   50                   'Invalid Parameters',
   51                   api)
   52 →         src = Path(settings.UPLD_DIR) / md5_hash / 'DYNAMIC_DeviceData'
   53           sfile = src / fil
   54           src = src.as_posix()
   55           if not is_safe_path(src, sfile.as_posix()) or is_path_traversal(fil):
   56               err = 'Path Traversal Attack Detected'
   57               return print_n_send_error_response(request, err, api)
   58           dat = sfile.read_text('ISO-8859-1')
   59           if fil.endswith('.plist') and dat.startswith('bplist0'):
   60               dat = dumps(dat, fmt=FMT_XML).decode('utf-8', 'ignore')
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `ghsa_db_path_traversal_04c9ba5c50b5aef9` (ghsa_db, CVE-2025-58162)

- **Repo:** MobSF/Mobile-Security-Framework-MobSF
- **File path:** `mobsf/MobSF/views/home.py`
- **Framework:** django
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 422
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  414               # Remove CRLF from filename to prevent header injection
  415               safe_filename = filename.replace('\r', '').replace('\n', '')
  416               val = f'attachment; filename="{safe_filename}"'
  417               response['Content-Disposition'] = val
  418           return response
  419   
  420       # Handle SVG files with bleach cleaning to prevent XSS attacks
  421       if dwd_file.suffix == '.svg':
  422 →         with open(dwd_file, 'r', encoding='utf-8') as file:
  423               svg_content = file.read()
  424               cleaned_svg = sanitize_svg(svg_content)
  425               return create_response(cleaned_svg, is_binary=False)
  426   
  427       # Handle all other binary file types
  428       with open(dwd_file, 'rb') as file:
  429           return create_response(file)
  430   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `ghsa_db_path_traversal_e39fbc3e07832f23` (ghsa_db, CVE-2025-54140)

- **Repo:** pyload/pyload
- **File path:** `src/pyload/webui/app/blueprints/json_blueprint.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bos\.path\.join\s*\(`
- **Sink match position:** line 154
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  146   
  147       try:
  148           file = flask.request.files["add_file"]
  149   
  150           if file.filename:
  151               if not package_name or package_name == "New Package":
  152                   package_name = file.filename
  153   
  154 →             file_path = os.path.join(
  155                   api.get_config_value("general", "storage_folder"), "tmp_" + file.filename
  156               )
  157               file.save(file_path)
  158               links.insert(0, file_path)
  159   
  160       except Exception:
  161           pass
  162   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #8 — `osv_path_traversal_ee99c9af78fd4fa7` (osv, CVE-2021-31542)

- **Repo:** django/django
- **File path:** `tests/file_uploads/tests.py`
- **Framework:** django
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 57
- **label_source / confidence:** osv / high

**Code excerpt:**

```python
   49           os.makedirs(MEDIA_ROOT, exist_ok=True)
   50   
   51       @classmethod
   52       def tearDownClass(cls):
   53           shutil.rmtree(MEDIA_ROOT)
   54           super().tearDownClass()
   55   
   56       def test_simple_upload(self):
   57 →         with open(__file__, 'rb') as fp:
   58               post_data = {
   59                   'name': 'Ringo',
   60                   'file_field': fp,
   61               }
   62               response = self.client.post('/upload/', post_data)
   63           self.assertEqual(response.status_code, 200)
   64   
   65       def test_large_upload(self):
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `ghsa_db_path_traversal_fc0fd5bdc814d00d` (ghsa_db, CVE-2023-0241)

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

### #10 — `ghsa_db_path_traversal_24435effd48a01d2` (ghsa_db, CVE-2025-11201)

- **Repo:** B-Step62/mlflow
- **File path:** `mlflow/server/handlers.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 1591
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
 1583           artifact_repo.log_artifact(file, path_to_log)
 1584   
 1585       with tempfile.TemporaryDirectory() as tmpdir:
 1586           dir_path = os.path.join(tmpdir, dirname) if dirname else tmpdir
 1587           file_path = os.path.join(dir_path, basename)
 1588   
 1589           os.makedirs(dir_path, exist_ok=True)
 1590   
 1591 →         with open(file_path, "wb") as f:
 1592               f.write(data)
 1593   
 1594           _log_artifact_to_repo(file_path, run, dirname, artifact_dir)
 1595   
 1596       return Response(mimetype="application/json")
 1597   
 1598   
 1599   @catch_mlflow_exception
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-502 — Deserialization of Untrusted Data

Sampled: **10** / 96 on disk.

### #1 — `ghsa_db_insecure_deserialization_dea83fdd123ebb08` (ghsa_db, CVE-2025-47277)

- **Repo:** vllm-project/vllm
- **File path:** `vllm/distributed/utils.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 170
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  162               if time.time() - timestamp > self.data_expiration_seconds:
  163                   self.store.delete_key(key)
  164                   self.entries.popleft()
  165               else:
  166                   break
  167   
  168       def recv_obj(self, src: int) -> Any:
  169           """Receive an object from a source rank."""
  170 →         obj = pickle.loads(
  171               self.store.get(
  172                   f"send_to/{self.rank}/{self.recv_src_counter[src]}"))
  173           self.recv_src_counter[src] += 1
  174           return obj
  175   
  176       def broadcast_obj(self, obj: Optional[Any], src: int) -> Any:
  177           """Broadcast an object from a source rank to all other ranks.
  178           It does not clean up after all ranks have received the object.
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_insecure_deserialization_b095e20c0ff43889` (ghsa_db, CVE-2022-34668)

- **Repo:** NVIDIA/NVFlare
- **File path:** `nvflare/private/fed/server/server_command_agent.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 51
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   43           self.thread.start()
   44           self.logger.info(f"ServerCommandAgent listening on port: {self.listen_port}")
   45   
   46       def execute_command(self, conn, engine):
   47           while not self.asked_to_stop:
   48               try:
   49                   if conn.poll(1.0):
   50                       msg = conn.recv()
   51 →                     msg = pickle.loads(msg)
   52                       command_name = msg.get(ServerCommandKey.COMMAND)
   53                       data = msg.get(ServerCommandKey.DATA)
   54                       command = ServerCommands.get_command(command_name)
   55                       if command:
   56                           with engine.new_context() as new_fl_ctx:
   57                               reply = command.process(data=data, fl_ctx=new_fl_ctx)
   58                               if reply:
   59                                   conn.send(reply)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `ghsa_db_insecure_deserialization_03ff942e2f5bda44` (ghsa_db, CVE-2022-34668)

- **Repo:** NVIDIA/NVFlare
- **File path:** `nvflare/app_common/state_persistors/storage_state_persistor.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 63
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   55           """Call to load the persisted FL components snapshot from the persisted location.
   56   
   57           Returns:
   58               retrieved Snapshot
   59           """
   60           all_items = self.storage.list_objects(self.uri_root)
   61           fl_snapshot = FLSnapshot()
   62           for item in all_items:
   63 →             snapshot = pickle.loads(self.storage.get_data(item))
   64               fl_snapshot.add_snapshot(snapshot.job_id, snapshot)
   65           return fl_snapshot
   66   
   67       def retrieve_run(self, job_id: str) -> RunSnapshot:
   68           """Call to load the persisted RunSnapshot of a job from the persisted location.
   69   
   70           Args:
   71               job_id: job_id
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `ghsa_db_insecure_deserialization_e62b9f467793e4c3` (ghsa_db, CVE-2026-23946)

- **Repo:** tendenci/tendenci
- **File path:** `tendenci/apps/imports/views.py`
- **Framework:** django
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 134
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  126       # store the recap - so we can retrieve it later
  127       recap_file_name = '%s_recap.txt' % sid
  128       recap_path = os.path.join(import_dict['folder_name'], recap_file_name)
  129   
  130       if default_storage.exists(recap_path):
  131           fd = default_storage.open(recap_path, 'r')
  132           content = fd.read()
  133           fd.close()
  134 →         recap_dict = pickle.loads(content)
  135           recap_dict.update({'users_list': recap_dict['users_list'] +
  136                                           import_dict['users_list'],
  137                              'invalid_list': recap_dict['invalid_list'] +
  138                                               invalid_list,
  139                              'total': import_dict['total'],
  140                              'total_done': import_dict['total_done'],
  141                              'count_insert': recap_dict['count_insert'] +
  142                                               import_dict['count_insert'],
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `ghsa_db_insecure_deserialization_15390d335afe8e9f` (ghsa_db, CVE-2022-34668)

- **Repo:** NVIDIA/NVFlare
- **File path:** `nvflare/apis/dxo.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 172
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  164   
  165       Args:
  166           data: a bytes object
  167   
  168       Returns:
  169           an object loaded by pickle from data
  170   
  171       """
  172 →     x = pickle.loads(data)
  173       if isinstance(x, DXO):
  174           return x
  175       else:
  176           raise ValueError("Data bytes are from type {} and do not represent a valid DXO instance.".format(type(x)))
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `ghsa_db_insecure_deserialization_4a5790622a9f9074` (ghsa_db, CVE-2022-34668)

- **Repo:** NVIDIA/NVFlare
- **File path:** `nvflare/app_common/abstract/learnable.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 41
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   33   
   34           Args:
   35               data: a bytes object
   36   
   37           Returns:
   38               an object loaded by pickle from data
   39   
   40           """
   41 →         return pickle.loads(data)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `ghsa_db_insecure_deserialization_fe21a71eeb2aad32` (ghsa_db, CVE-2014-3539)

- **Repo:** python-rope/rope
- **File path:** `rope/base/oi/doa.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 134
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  126           return str(self.data_port)
  127   
  128       def receive_data(self):
  129           conn, addr = self.server_socket.accept()
  130           self.server_socket.close()
  131           my_file = conn.makefile('rb')
  132           while True:
  133               try:
  134 →                 yield pickle.load(my_file)
  135               except EOFError:
  136                   break
  137           my_file.close()
  138           conn.close()
  139   
  140   
  141   class _FIFOReceiver(_MessageReceiver):
  142   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #8 — `ghsa_db_insecure_deserialization_e86d98b4e16aa83c` (ghsa_db, CVE-2025-61677)

- **Repo:** iterative/datachain
- **File path:** `src/datachain/data_storage/serializer.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 28
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   20           """
   21           return base64.b64encode(pickle.dumps(self.clone_params())).decode()
   22   
   23   
   24   def deserialize(s: str) -> Serializable:
   25       """
   26       Returns a new instance of the class represented by the string.
   27       """
   28 →     (f, args, kwargs) = pickle.loads(base64.b64decode(s.encode()))  # noqa: S301
   29       return f(*args, **kwargs)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `ghsa_db_insecure_deserialization_e7f2e8bf93f80540` (ghsa_db, CVE-2023-23930)

- **Repo:** vantage6/vantage6
- **File path:** `vantage6-client/vantage6/tools/mock_client.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 127
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  119           -------
  120           list[dict]
  121               The results of the task.
  122           """
  123           task = self.tasks[task_id]
  124           results = []
  125           for result in task.get("results"):
  126               print(result)
  127 →             res = pickle.loads(result.get("result"))
  128               results.append(res)
  129   
  130           return results
  131   
  132       def get_organizations_in_my_collaboration(self) -> list[dict]:
  133           """
  134           Get mocked organizations.
  135   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `ghsa_db_insecure_deserialization_aa04a0a86670dc1a` (ghsa_db, CVE-2022-34668)

- **Repo:** NVIDIA/NVFlare
- **File path:** `nvflare/private/fed/client/process_aux_cmd.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 31
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   23   
   24   class AuxRequestProcessor(RequestProcessor):
   25       def get_topics(self) -> [str]:
   26           return [ReservedTopic.AUX_COMMAND]
   27   
   28       def process(self, req: Message, app_ctx) -> Message:
   29           engine = app_ctx
   30   
   31 →         shareable = pickle.loads(req.body)
   32   
   33           job_id = req.get_header(RequestHeader.JOB_ID)
   34           result = engine.send_aux_command(shareable, job_id)
   35           if not result:
   36               result = make_reply(ReturnCode.EXECUTION_EXCEPTION)
   37   
   38           result = pickle.dumps(result)
   39           message = Message(topic="reply_" + req.topic, body=result)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-78 — OS Command Injection

Sampled: **10** / 57 on disk.

### #1 — `cvefixes_command_injection_862071e9e205d10a` (cvefixes, CVE-2022-31137)

- **Repo:** https://github.com/hap-wi/roxy-wi
- **File path:** `options.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bos\.(system|popen|spawn[lpvP])\s*\(`
- **Sink match position:** line 121
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  113               funct.upload(master[0], cert_path, name)
  114               print('success: the SSL file has been uploaded to %s into: %s%s <br/>' % (master[0], cert_path, '/' + name))
  115       try:
  116           error = funct.upload(serv, cert_path, name)
  117           print('success: the SSL file has been uploaded to %s into: %s%s' % (serv, cert_path, '/' + name))
  118       except Exception as e:
  119           funct.logging('localhost', e.args[0], haproxywi=1)
  120       try:
  121 →         os.system("mv %s %s" % (name, cert_local_dir))
  122       except OSError as e:
  123           funct.logging('localhost', e.args[0], haproxywi=1)
  124   
  125       funct.logging(serv, "add.py#ssl uploaded a new SSL cert %s" % name, haproxywi=1, login=1)
  126   
  127   if form.getvalue('backend') is not None:
  128       funct.show_backends(serv)
  129   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_command_injection_a37da00713dd6775` (ghsa_db, CVE-2021-43857)

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

### #3 — `ghsa_db_command_injection_1b2e003af80352d6` (ghsa_db, CVE-2025-12763)

- **Repo:** pgadmin-org/pgadmin4
- **File path:** `web/pgadmin/misc/bgprocess/process_executor.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bPopen\s*\(`
- **Sink match position:** line 328
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  320           kwargs = dict()
  321           kwargs['close_fds'] = False
  322           kwargs['shell'] = True if _IS_WIN else False
  323   
  324           # We need environment variables & values in string
  325           kwargs['env'] = os.environ.copy()
  326   
  327           _log('Starting the command execution...')
  328 →         process = Popen(
  329               command, stdout=PIPE, stderr=PIPE, stdin=None, **kwargs
  330           )
  331           args.update({
  332               'start_time': get_current_time(),
  333               'stdout': process_stdout.log,
  334               'stderr': process_stderr.log,
  335               'pid': process.pid
  336           })
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `cvefixes_command_injection_7658e075098eb050` (cvefixes, CVE-2020-7698)

- **Repo:** https://github.com/Gerapy/Gerapy
- **File path:** `views.py`
- **Framework:** django
- **Sink pattern recorded:** `\bPopen\s*\(`
- **Sink match position:** line 256
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  248       elif request.method == 'POST':
  249           project = Project.objects.filter(name=project_name)
  250           data = json.loads(request.body)
  251           configuration = json.dumps(data.get('configuration'), ensure_ascii=False)
  252           project.update(**{'configuration': configuration})
  253   
  254           # execute generate cmd
  255           cmd = ' '.join(['gerapy', 'generate', project_name])
  256 →         p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
  257           stdout, stderr = bytes2str(p.stdout.read()), bytes2str(p.stderr.read())
  258   
  259           if not stderr:
  260               return JsonResponse({'status': '1'})
  261           else:
  262               return JsonResponse({'status': '0', 'message': stderr})
  263   
  264   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `cvefixes_command_injection_bfdbfe150af8a07c` (cvefixes, CVE-2021-21386)

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

### #6 — `ghsa_db_command_injection_79944d2f1b3df900` (ghsa_db, CVE-2021-23422)

- **Repo:** tabatkins/bikeshed
- **File path:** `bikeshed/inlineTags/__init__.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bPopen\s*\(`
- **Sink match position:** line 14
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
    6   
    7   def processTags(doc):
    8       for el in findAll("[data-span-tag]", doc):
    9           tag = el.get("data-span-tag")
   10           if tag not in doc.md.inlineTagCommands:
   11               die("Unknown inline tag '{0}' found:\n  {1}", tag, outerHTML(el), el=el)
   12               continue
   13           command = doc.md.inlineTagCommands[tag]
   14 →         with Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True) as p:
   15               out, err = p.communicate(innerHTML(el).encode("utf-8"))
   16               try:
   17                   out = out.decode("utf-8")
   18               except UnicodeDecodeError as e:
   19                   die(
   20                       "When trying to process {0}, got invalid unicode in stdout:\n{1}",
   21                       outerHTML(el),
   22                       e,
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `ghsa_db_command_injection_698703652e80f562` (ghsa_db, CVE-2024-0815)

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

### #8 — `cvefixes_command_injection_b8058992e37f7657` (cvefixes, CVE-2019-25066)

- **Repo:** https://github.com/ajenti/ajenti
- **File path:** `auth.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bPopen\s*\(`
- **Sink match position:** line 143
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  135           raise AuthenticationError('Authentication provider %s is unavailable' % provider_id)
  136   
  137       def check_password(self, username, password):
  138           return self.get_provider().authenticate(username, password)
  139   
  140       def check_sudo_password(self, username, password):
  141           if not aj.config.data['auth'].get('allow_sudo', False):
  142               return False
  143 →         sudo = subprocess.Popen(
  144               ['sudo', '-S', '-k', '-u', username, '--', 'ls'],
  145               stdin=subprocess.PIPE,
  146               stdout=subprocess.PIPE,
  147               stderr=subprocess.PIPE,
  148           )
  149           o, e = sudo.communicate(password + '\n')
  150           if sudo.returncode != 0:
  151               raise SudoError((o + e).splitlines()[-1].strip())
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `ghsa_db_command_injection_2aab7ccc3335af48` (ghsa_db, CVE-2024-22423)

- **Repo:** yt-dlp/yt-dlp
- **File path:** `yt_dlp/YoutubeDL.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bPopen\s*\(`
- **Sink match position:** line 682
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  674           if self.params.get('bidi_workaround', False):
  675               try:
  676                   import pty
  677                   master, slave = pty.openpty()
  678                   width = shutil.get_terminal_size().columns
  679                   width_args = [] if width is None else ['-w', str(width)]
  680                   sp_kwargs = {'stdin': subprocess.PIPE, 'stdout': slave, 'stderr': self._out_files.error}
  681                   try:
  682 →                     self._output_process = Popen(['bidiv'] + width_args, **sp_kwargs)
  683                   except OSError:
  684                       self._output_process = Popen(['fribidi', '-c', 'UTF-8'] + width_args, **sp_kwargs)
  685                   self._output_channel = os.fdopen(master, 'rb')
  686               except OSError as ose:
  687                   if ose.errno == errno.ENOENT:
  688                       self.report_warning(
  689                           'Could not find fribidi executable, ignoring --bidi-workaround. '
  690                           'Make sure that  fribidi  is an executable file in one of the directories in your $PATH.')
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `nvd_command_injection_generic_abd254ee9895f0d8` (nvd_targeted, CVE-2025-6775)

- **Repo:** xiaoyunjie/openvpn-cms-flask
- **File path:** `app/libs/shell.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True`
- **Sink match position:** line 16
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
    8   
    9   import subprocess
   10   import paramiko
   11   
   12   
   13   class Cmd(object):
   14   
   15       def onetime_shell(self, cmd):
   16 →         cmd = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
   17           cmd = cmd.communicate()
   18           cmd = cmd[0].decode().rstrip()
   19           return cmd
   20   
   21   
   22   class Remote_cmd(object):
   23   
   24       def __init__(self, IP, Port, User, Password):
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-79 — Cross-site Scripting

Sampled: **10** / 170 on disk.

### #1 — `cvefixes_cross_site_scripting_cc5ed04f704a6bf2` (cvefixes, CVE-2021-41132)

- **Repo:** https://github.com/ome/omero-web
- **File path:** `views.py`
- **Framework:** django
- **Sink pattern recorded:** `\brender\s*\(\s*request`
- **Sink match position:** line 330
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  322               )
  323               client_download_tag_re = "^v%s\\.%s\\.[^-]+$" % (
  324                   ver.group("major"),
  325                   ver.group("minor"),
  326               )
  327               context["client_download_tag_re"] = client_download_tag_re
  328               context["client_download_repo"] = settings.CLIENT_DOWNLOAD_GITHUB_REPO
  329   
  330 →         return render(request, self.template, context)
  331   
  332   
  333   @login_required(ignore_login_fail=True)
  334   def keepalive_ping(request, conn=None, **kwargs):
  335       """Keeps the OMERO session alive by pinging the server"""
  336   
  337       # login_required handles ping, timeout etc, so we don't need to do
  338       # anything else
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_cross_site_scripting_52a6dfbb3a1fa3c7` (ghsa_db, CVE-2020-17515)

- **Repo:** apache/airflow
- **File path:** `airflow/www/views.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bMarkup\s*\(`
- **Sink match position:** line 117
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  109   
  110   if conf.getboolean('webserver', 'FILTER_BY_OWNER'):
  111       # filter_by_owner if authentication is enabled and filter_by_owner is true
  112       FILTER_BY_OWNER = not current_app.config['LOGIN_DISABLED']
  113   
  114   
  115   def dag_link(v, c, m, p):
  116       if m.dag_id is None:
  117 →         return Markup()
  118   
  119       kwargs = {'dag_id': m.dag_id}
  120   
  121       # This is called with various objects, TIs, (ORM) DAG - some have this,
  122       # some don't
  123       if hasattr(m, 'execution_date'):
  124           kwargs['execution_date'] = m.execution_date
  125   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `cvefixes_cross_site_scripting_b35efb67fe441dfc` (cvefixes, CVE-2022-24710)

- **Repo:** https://github.com/WeblateOrg/weblate
- **File path:** `reports.py`
- **Framework:** django
- **Sink pattern recorded:** `\bHttpResponse\s*\(`
- **Sink match position:** line 122
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  114               translator_start
  115               + "\n".join(translator_format.format(*t) for t in translators)
  116               + translator_end
  117           )
  118           result.append(row_end)
  119   
  120       result.append(end)
  121   
  122 →     return HttpResponse("\n".join(result), content_type=f"{mime}; charset=utf-8")
  123   
  124   
  125   COUNT_DEFAULTS = {
  126       field: 0
  127       for field in (
  128           "t_chars",
  129           "t_words",
  130           "chars",
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `ghsa_db_cross_site_scripting_e78d2bea1c5caa27` (ghsa_db, CVE-2023-48705)

- **Repo:** nautobot/nautobot
- **File path:** `nautobot/utilities/error_handlers.py`
- **Framework:** django
- **Sink pattern recorded:** `\bmark_safe\s*\(`
- **Sink match position:** line 26
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   18       dependent_objects = []
   19       for dependent in protected_objects[:50]:
   20           if hasattr(dependent, "get_absolute_url"):
   21               dependent_objects.append(f'<a href="{dependent.get_absolute_url()}">{escape(dependent)}</a>')
   22           else:
   23               dependent_objects.append(str(dependent))
   24       err_message += ", ".join(dependent_objects)
   25   
   26 →     messages.error(request, mark_safe(err_message))
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `ghsa_db_cross_site_scripting_1a142d26e0604a2d` (ghsa_db, CVE-2023-48705)

- **Repo:** nautobot/nautobot
- **File path:** `nautobot/extras/models/models.py`
- **Framework:** django
- **Sink pattern recorded:** `\bHttpResponse\s*\(`
- **Sink match position:** line 436
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  428       def render_to_response(self, queryset):
  429           """
  430           Render the template to an HTTP response, delivered as a named file attachment
  431           """
  432           output = self.render(queryset)
  433           mime_type = "text/plain" if not self.mime_type else self.mime_type
  434   
  435           # Build the response
  436 →         response = HttpResponse(output, content_type=mime_type)
  437           extension = f".{self.file_extension}" if self.file_extension else ""
  438           filename = f"{settings.BRANDING_PREPENDED_FILENAME}{queryset.model._meta.verbose_name_plural}{extension}"
  439           response["Content-Disposition"] = f'attachment; filename="{filename}"'
  440   
  441           return response
  442   
  443       def get_absolute_url(self):
  444           return reverse("extras:exporttemplate", kwargs={"pk": self.pk})
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `ghsa_db_cross_site_scripting_6c97b5e3df143ab1` (ghsa_db, CVE-2023-48705)

- **Repo:** nautobot/nautobot
- **File path:** `nautobot/dcim/models/devices.py`
- **Framework:** django
- **Sink pattern recorded:** `\bmark_safe\s*\(`
- **Sink match position:** line 260
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  252   
  253           # If modifying the height of an existing DeviceType to 0U, check for any instances assigned to a rack position.
  254           elif self.present_in_database and self._original_u_height > 0 and self.u_height == 0:
  255               racked_instance_count = Device.objects.filter(device_type=self, position__isnull=False).count()
  256               if racked_instance_count:
  257                   url = f"{reverse('dcim:device_list')}?manufacturer={self.manufacturer_id}&device_type={self.pk}"
  258                   raise ValidationError(
  259                       {
  260 →                         "u_height": mark_safe(
  261                               f'Unable to set 0U height: Found <a href="{url}">{racked_instance_count} instances</a> already '
  262                               f"mounted within racks."
  263                           )
  264                       }
  265                   )
  266   
  267           if (self.subdevice_role != SubdeviceRoleChoices.ROLE_PARENT) and self.device_bay_templates.count():
  268               raise ValidationError(
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `ghsa_db_cross_site_scripting_a8646974d959232c` (ghsa_db, CVE-2019-0216)

- **Repo:** apache/airflow
- **File path:** `airflow/www/utils.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bMarkup\s*\(`
- **Sink match position:** line 250
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  242           dag_id=dag_id,
  243           task_id=task_id,
  244           execution_date=execution_date.isoformat())
  245       url_root = url_for(
  246           'Airflow.graph',
  247           dag_id=dag_id,
  248           root=task_id,
  249           execution_date=execution_date.isoformat())
  250 →     return Markup(
  251           """
  252           <span style="white-space: nowrap;">
  253           <a href="{url}">{task_id}</a>
  254           <a href="{url_root}" title="Filter on this task and upstream">
  255           <span class="glyphicon glyphicon-filter" style="margin-left: 0px;"
  256               aria-hidden="true"></span>
  257           </a>
  258           </span>
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #8 — `ghsa_db_cross_site_scripting_1ebc5edd35979b76` (ghsa_db, CVE-2026-27645)

- **Repo:** dgtlmoon/changedetection.io
- **File path:** `changedetectionio/blueprint/ui/__init__.py`
- **Framework:** flask
- **Sink pattern recorded:** `\brender_template\s*\(`
- **Sink match position:** line 185
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  177                   threading.Thread(target=clear_history_background, daemon=True).start()
  178   
  179                   flash(gettext("History clearing started in background"))
  180               else:
  181                   flash(gettext('Incorrect confirmation text.'), 'error')
  182   
  183               return redirect(url_for('watchlist.index'))
  184   
  185 →         output = render_template("clear_all_history.html")
  186           return output
  187   
  188       # Clear all statuses, so we do not see the 'unviewed' class
  189       @ui_blueprint.route("/form/mark-all-viewed", methods=['GET'])
  190       @login_optionally_required
  191       def mark_all_viewed():
  192           # Save the current newest history as the most recently viewed
  193           with_errors = request.args.get('with_errors') == "1"
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `ghsa_db_cross_site_scripting_df64ee529ecafb75` (ghsa_db, CVE-2024-28233)

- **Repo:** jupyterhub/jupyterhub
- **File path:** `jupyterhub/apihandlers/base.py`
- **Framework:** tornado
- **Sink pattern recorded:** `\bself\.write\s*\(`
- **Sink match position:** line 173
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  165               # since exception handler clears headers
  166               headers = getattr(exception, 'headers', None)
  167               if headers:
  168                   for key, value in headers.items():
  169                       self.set_header(key, value)
  170               # Content-Length must be recalculated.
  171               self.clear_header('Content-Length')
  172   
  173 →         self.write(
  174               json.dumps({'status': status_code, 'message': message or status_message})
  175           )
  176   
  177       def server_model(self, spawner, *, user=None):
  178           """Get the JSON model for a Spawner
  179           Assume server permission already granted
  180           """
  181           if isinstance(spawner, orm.Spawner):
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `ghsa_db_cross_site_scripting_12a8b1d111aa0769` (ghsa_db, CVE-2022-39348)

- **Repo:** twisted/twisted
- **File path:** `src/twisted/web/_auth/wrapper.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\brender\s*\(\s*request`
- **Sink match position:** line 138
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  130               return util.DeferredResource(self._login(credentials))
  131   
  132       def render(self, request):
  133           """
  134           Find the L{IResource} avatar suitable for the given request, if
  135           possible, and render it.  Otherwise, perhaps render an error page
  136           requiring authorization or describing an internal server failure.
  137           """
  138 →         return self._authorizedResource(request).render(request)
  139   
  140       def getChildWithDefault(self, path, request):
  141           """
  142           Inspect the Authorization HTTP header, and return a deferred which,
  143           when fired after successful authentication, will return an authorized
  144           C{Avatar}. On authentication failure, an C{UnauthorizedResource} will
  145           be returned, essentially halting further dispatch on the wrapped
  146           resource and all children
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-89 — SQL Injection

Sampled: **10** / 268 on disk.

### #1 — `vudenc_sql_injection_963060897f56a5e2` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 3
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def delete_where(self, table, where):...
    2   """docstring"""
    3 → self.cursor.execute('DELETE FROM {0} WHERE {1}'.format(table, where))
    4   print('Erro: {}'.format(error))
    5   self.__connection.commit()
    6   return self.cursor
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `osv_sql_injection_b1e9540ebd415d89` (osv, CVE-2022-28346)

- **Repo:** django/django
- **File path:** `tests/annotations/tests.py`
- **Framework:** django
- **Sink pattern recorded:** `\bSELECT\b.*\bFROM\b`
- **Sink match position:** line 534
- **label_source / confidence:** osv / high

**Code excerpt:**

```python
  526           publishers = Publisher.objects.values("id", "book__rating").annotate(
  527               total=Sum("book__rating")
  528           )
  529           for publisher in publishers.filter(pk=self.p1.pk):
  530               self.assertEqual(publisher["book__rating"], publisher["total"])
  531   
  532       @skipUnlessDBFeature("allows_group_by_pk")
  533       def test_rawsql_group_by_collapse(self):
  534 →         raw = RawSQL("SELECT MIN(id) FROM annotations_book", [])
  535           qs = (
  536               Author.objects.values("id")
  537               .annotate(
  538                   min_book_id=raw,
  539                   count_friends=Count("friends"),
  540               )
  541               .order_by()
  542           )
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `osv_sql_injection_2dfd5164fc7af466` (osv, CVE-2022-34265)

- **Repo:** django/django
- **File path:** `django/db/backends/base/operations.py`
- **Framework:** django
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 327
- **label_source / confidence:** osv / high

**Code excerpt:**

```python
  319           Return the value to use during an INSERT statement to specify that
  320           the field should use its default value.
  321           """
  322           return "DEFAULT"
  323   
  324       def prepare_sql_script(self, sql):
  325           """
  326           Take an SQL script that may contain multiple lines and return a list
  327 →         of statements to feed to successive cursor.execute() calls.
  328   
  329           Since few databases are able to process raw SQL scripts in a single
  330           cursor.execute() call and PEP 249 doesn't talk about this use case,
  331           the default implementation is conservative.
  332           """
  333           return [
  334               sqlparse.format(statement, strip_comments=True)
  335               for statement in sqlparse.split(sql)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `osv_sql_injection_05b2b78ca2a5f93f` (osv, CVE-2024-42005)

- **Repo:** django/django
- **File path:** `django/db/models/sql/query.py`
- **Framework:** django
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 152
- **label_source / confidence:** osv / high

**Code excerpt:**

```python
  144           elif params_type is dict:
  145               params = {key: adapter(val) for key, val in self.params.items()}
  146           elif params_type is None:
  147               params = None
  148           else:
  149               raise RuntimeError("Unexpected params type: %s" % params_type)
  150   
  151           self.cursor = connection.cursor()
  152 →         self.cursor.execute(self.sql, params)
  153   
  154   
  155   ExplainInfo = namedtuple("ExplainInfo", ("format", "options"))
  156   
  157   
  158   class Query(BaseExpression):
  159       """A single SQL query."""
  160   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `vudenc_sql_injection_3adad465b5c15a5b` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 18
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
   10                      FROM user_event
   11                      WHERE event_id = {0}
   12                      AND user_event.attending = 0)
   13                      AS declined
   14                    FROM events
   15                    WHERE event_id = {0};
   16                    """
   17       .format(event_id))
   18 → self.cur.execute(sql)
   19   return self.cur.fetchall()
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `vudenc_sql_injection_edceb058d7194ba3` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 10
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    2   update_sql = (
    3       """
    4               UPDATE Clients
    5               SET message = '{}'
    6               WHERE client_id = '{}'
    7           """
    8       .format(new_message, logged_user.get_client_id()))
    9   cursor = self.__conn.cursor()
   10 → cursor.execute(update_sql)
   11   self.__conn.commit()
   12   logged_user.set_message(new_message)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `vudenc_sql_injection_b9ec4d486b86bf07` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 9
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def register(self, username, password):...
    2   insert_sql = (
    3       """
    4               INSERT INTO Clients (username, password)
    5               VALUES ('{}', '{}')
    6           """
    7       .format(username, password))
    8   cursor = self.__conn.cursor()
    9 → cursor.execute(insert_sql)
   10   self.__conn.commit()
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #8 — `vudenc_sql_injection_71f55074606c0902` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 7
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def getAvailabilityForCalendar(calendarId, sqlInstance):...
    2   conn = sqlInstance.connect()
    3   cursor = conn.cursor()
    4   queryString = (
    5       "SELECT Users.userEmail,  TimeSlots.one, TimeSlots.two, TimeSlots.three, TimeSlots.four, TimeSlots.five, TimeSlots.six, TimeSlots.seven, TimeSlots.eight, TimeSlots.nine, TimeSlots.ten, TimeSlots.eleven, TimeSlots.twelve, TimeSlots.thirteen, TimeSlots.fourteen, TimeSlots.fifteen, TimeSlots.sixteen, TimeSlots.seventeen, TimeSlots.eighteen, TimeSlots.nineteen, TimeSlots.twenty, TimeSlots.twentyone, TimeSlots.twentytwo, TimeSlots.twentythree, TimeSlots.zero FROM TimeSlots, Users WHERE Users.userId = TimeSlots.userId AND TimeSlots.calendarId='{0}'"
    6       .format(calendarId))
    7 → cursor.execute(queryString)
    8   results = cursor.fetchall()
    9   return results
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `vudenc_sql_injection_d5926c32e399db87` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 6
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def insert_result_feedback(self, qhash, is_know, reason, label, ip, browser):...
    2   sql = (
    3       'INSERT INTO feedback_result (query_hash, reported_at, is_know, reason, feedback_label, client_ip, client_browser) VALUES'
    4        + "('%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (qhash, datetime.now(
    5       ), is_know, reason, label, ip, browser))
    6 → self.cur.execute(sql)
    7   self.conn.commit()
    8   return self.cur.lastrowid
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `vudenc_sql_injection_cc24b419b9e2aaba` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 6
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   async def insert_user_info(self, member_id: int, column: str, col_value):...
    2   execute = f"""INSERT INTO user_info (member_id, {column})
    3                       VALUES ({member_id}, {col_value})
    4                       ON CONFLICT (member_id)
    5                           DO UPDATE SET {column} = {col_value};"""
    6 → await self.db_conn.execute(execute)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-918 — Server-Side Request Forgery

Sampled: **10** / 54 on disk.

### #1 — `ghsa_db_ssrf_7d573c63ee50d902` (ghsa_db, —)

- **Repo:** danielgatis/rembg
- **File path:** `rembg/commands/s_command.py`
- **Framework:** fastapi
- **Sink pattern recorded:** `\baiohttp\.\w+\s*\(`
- **Sink match position:** line 253
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  245           description="Removes the background from an image obtained by retrieving an URL.",
  246       )
  247       async def get_index(
  248           url: str = Query(
  249               default=..., description="URL of the image that has to be processed."
  250           ),
  251           commons: CommonQueryParams = Depends(),
  252       ):
  253 →         async with aiohttp.ClientSession() as session:
  254               async with session.get(url) as response:
  255                   file = await response.read()
  256                   return await asyncify(im_without_bg)(file, commons)
  257   
  258       @app.post(
  259           path="/api/remove",
  260           tags=["Background Removal"],
  261           summary="Remove from Stream",
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_ssrf_66f82f29d3908ed5` (ghsa_db, CVE-2025-67743)

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

### #3 — `ghsa_db_ssrf_4d10a01660b7600e` (ghsa_db, CVE-2022-0339)

- **Repo:** janeczku/calibre-web
- **File path:** `cps/helper.py`
- **Framework:** flask
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 587
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  579                   return get_cover_on_failure(use_generic_cover_on_failure)
  580       else:
  581           return get_cover_on_failure(use_generic_cover_on_failure)
  582   
  583   
  584   # saves book cover from url
  585   def save_cover_from_url(url, book_path):
  586       try:
  587 →         img = requests.get(url, timeout=(10, 200))      # ToDo: Error Handling
  588           img.raise_for_status()
  589           return save_cover(img, book_path)
  590       except (requests.exceptions.HTTPError,
  591               requests.exceptions.ConnectionError,
  592               requests.exceptions.Timeout) as ex:
  593           log.info(u'Cover Download Error %s', ex)
  594           return False, _("Error Downloading Cover")
  595       except MissingDelegateError as ex:
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `nvd_ssrf_ba2192221f3a3f57` (nvd_targeted, CVE-2026-25991)

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

### #6 — `nvd_ssrf_3f43653827673eb8` (nvd_targeted, CVE-2021-43780)

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

### #7 — `nvd_ssrf_cbf3875a88d13177` (nvd_targeted, CVE-2026-25991)

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

### #9 — `ghsa_ssrf_0cfd1c539d6b045d` (ghsa, CVE-2026-33440)

- **Repo:** WeblateOrg/weblate
- **File path:** `weblate/utils/requests.py`
- **Framework:** django
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 33
- **label_source / confidence:** ghsa / high

**Code excerpt:**

```python
   25       raise_for_status: bool = True,
   26       **kwargs,
   27   ) -> Response:
   28       agent = {"User-Agent": USER_AGENT}
   29       if headers is None:
   30           headers = agent
   31       else:
   32           headers.update(agent)
   33 →     response = requests.request(method, url, headers=headers, timeout=timeout, **kwargs)
   34       if raise_for_status:
   35           response.raise_for_status()
   36       return response
   37   
   38   
   39   def get_uri_error(uri: str) -> str | None:
   40       """Return error for fetching the URL or None if it works."""
   41       if uri.startswith("https://nonexisting.weblate.org/"):
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `nvd_ssrf_eace54f66847ad44` (nvd_targeted, CVE-2026-25991)

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

## CWE-94 — Code Injection

Sampled: **10** / 61 on disk.

### #1 — `ghsa_db_code_injection_56e1f757cd75550a` (ghsa_db, CVE-2023-36258)

- **Repo:** langchain-ai/langchain
- **File path:** `libs/langchain/langchain/prompts/loading.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bexec\s*\(`
- **Sink match position:** line 152
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  144       elif file_path.suffix == ".py":
  145           spec = importlib.util.spec_from_loader(
  146               "prompt", loader=None, origin=str(file_path)
  147           )
  148           if spec is None:
  149               raise ValueError("could not load spec")
  150           helper = importlib.util.module_from_spec(spec)
  151           with open(file_path, "rb") as f:
  152 →             exec(f.read(), helper.__dict__)
  153           if not isinstance(helper.PROMPT, BasePromptTemplate):
  154               raise ValueError("Did not get object of type BasePromptTemplate.")
  155           return helper.PROMPT
  156       else:
  157           raise ValueError(f"Got unsupported file type {file_path.suffix}")
  158       # Load the prompt from the config now.
  159       return load_prompt_from_config(config)
  160   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_code_injection_095d7b97a9b6ad13` (ghsa_db, CVE-2023-37659)

- **Repo:** refraction-ray/xalpha
- **File path:** `xalpha/info.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 584
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  576               raise ParserFailure("Unrecognized fund, please check fund code you input.")
  577           if self._page.text[:800].find("Data_millionCopiesIncome") >= 0:
  578               raise FundTypeError("This code seems to be a mfund, use mfundinfo instead")
  579   
  580           l = re.match(
  581               r"[\s\S]*Data_netWorthTrend = ([^;]*);[\s\S]*", self._page.text
  582           ).groups()[0]
  583           l = l.replace("null", "None")  # 暂未发现基金净值有 null 的基金，若有，其他地方也很可能出问题！
  584 →         l = eval(l)
  585           ltot = re.match(
  586               r"[\s\S]*Data_ACWorthTrend = ([^;]*);[\s\S]*", self._page.text
  587           ).groups()[
  588               0
  589           ]  # .* doesn't match \n
  590           ltot = ltot.replace("null", "None")  ## 096001 总值数据中有 null！
  591           ltot = eval(ltot)
  592           ## timestamp transform tzinfo must be taken into consideration
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `ghsa_db_code_injection_7031b72135827c68` (ghsa_db, CVE-2024-3098)

- **Repo:** run-llama/llama_index
- **File path:** `llama-index-core/llama_index/core/exec_utils.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 140
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  132       __source: Union[str, bytes, CodeType],
  133       __globals: Union[Dict[str, Any], None] = None,
  134       __locals: Union[Mapping[str, object], None] = None,
  135   ) -> Any:
  136       """
  137       eval within safe global context.
  138       """
  139       _verify_source_safety(__source)
  140 →     return eval(__source, _get_restricted_globals(__globals), __locals)
  141   
  142   
  143   def safe_exec(
  144       __source: Union[str, bytes, CodeType],
  145       __globals: Union[Dict[str, Any], None] = None,
  146       __locals: Union[Mapping[str, object], None] = None,
  147   ) -> None:
  148       """
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `ghsa_db_code_injection_d4e20ce237c48b52` (ghsa_db, CVE-2024-45201)

- **Repo:** run-llama/llama_index
- **File path:** `llama-index-core/llama_index/core/download/integration.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bexec\s*\(`
- **Sink match position:** line 21
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   13   def download_integration(module_str: str, module_import_str: str, cls_name: str) -> Any:
   14       """Returns an integration class by first pip installing its parent module."""
   15       try:
   16           pip_install(module_str)  # this works for any integration not just packs
   17       except Exception as e:
   18           raise Exception(f"Failed to pip install `{module_str}`") from e
   19   
   20       try:
   21 →         exec(f"from {module_import_str} import {cls_name}")
   22           module_spec = importlib.util.find_spec(module_import_str)
   23           module = importlib.util.module_from_spec(module_spec)
   24           module_spec.loader.exec_module(module)
   25           pack_cls = getattr(module, cls_name)
   26       except ImportError as e:
   27           raise ImportError(f"Unable to import {cls_name}") from e
   28       return pack_cls
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `cvefixes_code_injection_5e31e4c0f4f01323` (cvefixes, CVE-2018-1000070)

- **Repo:** https://github.com/Bitmessage/PyBitmessage
- **File path:** `__init__.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 15
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
    7   
    8   class MsgBase(object):
    9       def encode(self):
   10           self.data = {"": lower(type(self).__name__)}
   11   
   12   
   13   def constructObject(data):
   14       try:
   15 →         classBase = eval(data[""] + "." + data[""].title())
   16       except NameError:
   17           logger.error("Don't know how to handle message type: \"%s\"", data[""])
   18           return None
   19       try:
   20           returnObj = classBase()
   21           returnObj.decode(data)
   22       except KeyError as e:
   23           logger.error("Missing mandatory key %s", e)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `cvefixes_code_injection_7c329af7619a9db8` (cvefixes, CVE-2019-19010)

- **Repo:** https://github.com/ProgVal/Limnoria
- **File path:** `plugin.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 223
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  215                   # use of str() on large numbers loses information:
  216                   # str(float(33333333333333)) => '3.33333333333e+13'
  217                   # float('3.33333333333e+13') => 33333333333300.0
  218                   return '%.16f' % x
  219               return str(x)
  220           text = self._mathRe.sub(handleMatch, text)
  221           try:
  222               self.log.info('evaluating %q from %s', text, msg.prefix)
  223 →             x = complex(eval(text, self._mathSafeEnv, self._mathSafeEnv))
  224               irc.reply(self._complexToString(x))
  225           except OverflowError:
  226               maxFloat = math.ldexp(0.9999999999999999, 1024)
  227               irc.error(_('The answer exceeded %s or so.') % maxFloat)
  228           except TypeError:
  229               irc.error(_('Something in there wasn\'t a valid number.'))
  230           except NameError as e:
  231               irc.error(_('%s is not a defined function.') % str(e).split()[1])
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `ghsa_db_code_injection_ba44db771752bd6a` (ghsa_db, CVE-2025-2945)

- **Repo:** pgadmin-org/pgadmin4
- **File path:** `web/pgadmin/tools/sqleditor/__init__.py`
- **Framework:** flask
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 2159
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
 2151           sql = None
 2152           query_commited = data.get('query_commited', False)
 2153           # Iterate through CombinedMultiDict to find query.
 2154           for key, value in data.items():
 2155               if key == 'query':
 2156                   sql = value
 2157               if key == 'query_commited':
 2158                   query_commited = (
 2159 →                     eval(value) if isinstance(value, str) else value
 2160                   )
 2161           if not sql:
 2162               sql = trans_obj.get_sql(sync_conn)
 2163           if sql and query_commited:
 2164               # Re-execute the query to ensure the latest data is included
 2165               sync_conn.execute_async(sql)
 2166           # This returns generator of records.
 2167           status, gen, conn_obj = \
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #8 — `ghsa_db_code_injection_03b7aaad750f088d` (ghsa_db, CVE-2023-39631)

- **Repo:** pydata/numexpr
- **File path:** `numexpr/necompiler.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 289
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  281                   names[name] = True
  282               elif name == "False":
  283                   names[name] = False
  284               else:
  285                   t = types.get(name, default_type)
  286                   names[name] = expressions.VariableNode(name, type_to_kind[t])
  287           names.update(expressions.functions)
  288           # now build the expression
  289 →         ex = eval(c, names)
  290           if expressions.isConstant(ex):
  291               ex = expressions.ConstantNode(ex, expressions.getKind(ex))
  292           elif not isinstance(ex, expressions.ExpressionNode):
  293               raise TypeError("unsupported expression type: %s" % type(ex))
  294       finally:
  295           expressions._context.set_new_context(old_ctx)
  296       return ex
  297   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `ghsa_db_code_injection_64cb070ee0d922b3` (ghsa_db, CVE-2025-59042)

- **Repo:** pyinstaller/pyinstaller
- **File path:** `PyInstaller/building/build_main.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bexec\s*\(`
- **Sink match position:** line 942
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  934   
  935       # Execute the specfile. Read it as a binary file...
  936       try:
  937           with open(spec, 'rb') as f:
  938               # ... then let Python determine the encoding, since ``compile`` accepts byte strings.
  939               code = compile(f.read(), spec, 'exec')
  940       except FileNotFoundError:
  941           raise SystemExit(f'Spec file "{spec}" not found!')
  942 →     exec(code, spec_namespace)
  943   
  944   
  945   def __add_options(parser):
  946       parser.add_argument(
  947           "--distpath",
  948           metavar="DIR",
  949           default=DEFAULT_DISTPATH,
  950           help="Where to put the bundled app (default: ./dist)",
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `ghsa_db_code_injection_c02e0359154c0067` (ghsa_db, CVE-2025-46724)

- **Repo:** langroid/langroid
- **File path:** `langroid/agent/special/table_chat_agent.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 218
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  210   
  211           # Temporarily redirect standard output to our string-based I/O stream
  212           sys.stdout = code_out
  213   
  214           # Evaluate the last line and get the result;
  215           # SECURITY: eval only with empty globals and {"df": df} in locals to
  216           # prevent arbitrary Python code execution.
  217           try:
  218 →             eval_result = eval(exprn, {}, local_vars)
  219           except Exception as e:
  220               eval_result = f"ERROR: {type(e)}: {e}"
  221   
  222           if eval_result is None:
  223               eval_result = ""
  224   
  225           # Always restore the original standard output
  226           sys.stdout = sys.__stdout__
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---
