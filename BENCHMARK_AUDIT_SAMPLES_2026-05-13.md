# Stage-1 Sample Audit Pack — 2026-05-13 10:31 UTC

Per-CWE spot-check of label correctness. For each sample below, read
the code excerpt and decide:

- **PASS** — the labeled CWE matches what the code actually does
- **FAIL** — the code does not exhibit the labeled CWE (note the actual CWE
  or the reason: e.g. "sink call but no taint flow", "test fixture",
  "unrelated co-changed file", etc.)

Sampled with seed=42. Per-CWE sampling: 10 for
populous classes, ALL for classes with ≤30 samples.

Canonical samples are excluded from the audit (they are hand-curated
textbook positives by construction).

---

## Summary

| CWE | Active | Sampled | Audit FP rate (filled after audit) |
|---|---:|---:|---|
| CWE-22 (Path Traversal) | 174 | 10 | __/__ |
| CWE-434 (Unrestricted Upload of File with Dangerous Type) | 7 | 7 | __/__ |
| CWE-502 (Deserialization of Untrusted Data) | 95 | 10 | __/__ |
| CWE-78 (OS Command Injection) | 51 | 10 | __/__ |
| CWE-79 (Cross-site Scripting) | 229 | 10 | __/__ |
| CWE-89 (SQL Injection) | 282 | 10 | __/__ |
| CWE-918 (Server-Side Request Forgery) | 63 | 10 | __/__ |
| CWE-94 (Code Injection) | 85 | 10 | __/__ |
| safe (safe) | 429 | 0 | __/__ |

---

## CWE-22 — Path Traversal

Sampled: **10** / 174 on disk.

### #1 — `osv_path_traversal_9f4d22f441630a01` (osv, CVE-2024-39330)

- **Repo:** django/django
- **File path:** `tests/file_storage/tests.py`
- **Framework:** django
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 153
- **label_source / confidence:** osv / high

**Code excerpt:**

```python
  145           self.assertEqual(storage.base_location, "")
  146           self.assertEqual(storage.location, os.getcwd())
  147   
  148       def test_file_access_options(self):
  149           """
  150           Standard file access options are available, and work as expected.
  151           """
  152           self.assertFalse(self.storage.exists("storage_test"))
  153 →         f = self.storage.open("storage_test", "w")
  154           f.write("storage contents")
  155           f.close()
  156           self.assertTrue(self.storage.exists("storage_test"))
  157   
  158           f = self.storage.open("storage_test", "r")
  159           self.assertEqual(f.read(), "storage contents")
  160           f.close()
  161   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_path_traversal_60f4c4c6c5c33d72` (ghsa_db, —)

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

### #3 — `cvefixes_path_traversal_847e9253c120af36` (cvefixes, CVE-2022-31506)

- **Repo:** https://github.com/cmusatyalab/opendiamond
- **File path:** `augment_store.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 184
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  176       Assuming name of files NEGATIVE (e.g:subset YFCC), POSITIVE
  177       """
  178   
  179       filepath_split = ['STREAM', "{:.2f}".format(base_rate), str(rank), str(total_servers), str(seed)]
  180       filepath = '_'.join(filepath_split)
  181       filepath = os.path.join(base_dir, filepath)
  182       positive_path = os.path.join(base_dir, 'POSITIVE')
  183       negative_path = os.path.join(base_dir, 'NEGATIVE')
  184 →     positive_firstline = open(positive_path).readline().rstrip()
  185       keyword = positive_firstline.split('/')[-2] # Assuming all positives are in the same parent dir
  186   
  187       _log.info("Dir {} BR: {} Seed:{} FP{}".format(base_dir, base_rate, seed, filepath))
  188       sys.stdout.flush()
  189   
  190       if not os.path.exists(filepath):
  191           positive_data = read_file_list(positive_path) # same across servers
  192           negative_data = read_file_list(negative_path) # different across servers
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `ghsa_db_path_traversal_f2a2207f4a57ba11` (ghsa_db, CVE-2024-0964)

- **Repo:** gradio-app/gradio
- **File path:** `gradio/routes.py`
- **Framework:** fastapi
- **Sink pattern recorded:** `\bos\.path\.join\s*\(`
- **Sink match position:** line 834
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  826       _os_alt_seps: List[str] = [
  827           sep for sep in [os.path.sep, os.path.altsep] if sep is not None and sep != "/"
  828       ]
  829   
  830       if path == "":
  831           raise HTTPException(400)
  832   
  833       filename = posixpath.normpath(path)
  834 →     fullpath = os.path.join(directory, filename)
  835       if (
  836           any(sep in filename for sep in _os_alt_seps)
  837           or os.path.isabs(filename)
  838           or filename == ".."
  839           or filename.startswith("../")
  840           or os.path.isdir(fullpath)
  841       ):
  842           raise HTTPException(403)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `osv_path_traversal_16631be9fe1b263d` (osv, CVE-2021-3281)

- **Repo:** django/django
- **File path:** `tests/utils_tests/test_archive.py`
- **Framework:** django
- **Sink pattern recorded:** `\bos\.path\.join\s*\(`
- **Sink match position:** line 13
- **label_source / confidence:** osv / high

**Code excerpt:**

```python
    5   import unittest
    6   
    7   from django.utils import archive
    8   
    9   
   10   class TestArchive(unittest.TestCase):
   11   
   12       def setUp(self):
   13 →         self.testdir = os.path.join(os.path.dirname(__file__), 'archives')
   14           self.old_cwd = os.getcwd()
   15           os.chdir(self.testdir)
   16   
   17       def tearDown(self):
   18           os.chdir(self.old_cwd)
   19   
   20       def test_extract_function(self):
   21           for entry in os.scandir(self.testdir):
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `ghsa_db_path_traversal_0a1106e888368a43` (ghsa_db, CVE-2024-10833)

- **Repo:** eosphoros-ai/DB-GPT
- **File path:** `dbgpt/app/knowledge/api.py`
- **Framework:** fastapi
- **Sink pattern recorded:** `\bos\.path\.join\s*\(`
- **Sink match position:** line 343
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  335       space_name: str,
  336       doc_name: str = Form(...),
  337       doc_type: str = Form(...),
  338       doc_file: UploadFile = File(...),
  339   ):
  340       print(f"/document/upload params: {space_name}")
  341       try:
  342           if doc_file:
  343 →             if not os.path.exists(os.path.join(KNOWLEDGE_UPLOAD_ROOT_PATH, space_name)):
  344                   os.makedirs(os.path.join(KNOWLEDGE_UPLOAD_ROOT_PATH, space_name))
  345               # We can not move temp file in windows system when we open file in context of `with`
  346               tmp_fd, tmp_path = tempfile.mkstemp(
  347                   dir=os.path.join(KNOWLEDGE_UPLOAD_ROOT_PATH, space_name)
  348               )
  349               with os.fdopen(tmp_fd, "wb") as tmp:
  350                   tmp.write(await doc_file.read())
  351               shutil.move(
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `ghsa_db_path_traversal_c7b8944048f91b6c` (ghsa_db, CVE-2023-0241)

- **Repo:** akshay-joshi/pgadmin4
- **File path:** `web/pgadmin/utils/__init__.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 462
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  454               storage_manager_path,
  455               file_path.lstrip('/').lstrip('\\')
  456           )
  457   
  458       # write to file
  459       file_content = json.dumps(object_dict, indent=4)
  460       error_str = "Error: {0}"
  461       try:
  462 →         with open(file_path, 'w') as output_file:
  463               output_file.write(file_content)
  464       except IOError as e:
  465           err_msg = error_str.format(e.strerror)
  466           return _handle_error(err_msg, from_setup)
  467       except Exception as e:
  468           err_msg = error_str.format(e.strerror)
  469           return _handle_error(err_msg, from_setup)
  470   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #8 — `cvefixes_path_traversal_e1f237553a36b341` (cvefixes, CVE-2021-41127)

- **Repo:** https://github.com/RasaHQ/rasa
- **File path:** `model.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 231
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  223       """
  224       import tarfile
  225   
  226       if working_directory is None:
  227           working_directory = tempfile.mkdtemp()
  228   
  229       # All files are in a subdirectory.
  230       try:
  231 →         with tarfile.open(model_file, mode="r:gz") as tar:
  232               tar.extractall(working_directory)
  233               logger.debug(f"Extracted model to '{working_directory}'.")
  234       except (tarfile.TarError, ValueError) as e:
  235           logger.error(f"Failed to extract model at {model_file}. Error: {e}")
  236           raise
  237   
  238       return TempDirectoryPath(working_directory)
  239   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `osv_path_traversal_3b95fd3d513a77b6` (osv, CVE-2021-45452)

- **Repo:** django/django
- **File path:** `tests/file_storage/tests.py`
- **Framework:** django
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 117
- **label_source / confidence:** osv / high

**Code excerpt:**

```python
  109           self.assertEqual(storage.base_location, '')
  110           self.assertEqual(storage.location, os.getcwd())
  111   
  112       def test_file_access_options(self):
  113           """
  114           Standard file access options are available, and work as expected.
  115           """
  116           self.assertFalse(self.storage.exists('storage_test'))
  117 →         f = self.storage.open('storage_test', 'w')
  118           f.write('storage contents')
  119           f.close()
  120           self.assertTrue(self.storage.exists('storage_test'))
  121   
  122           f = self.storage.open('storage_test', 'r')
  123           self.assertEqual(f.read(), 'storage contents')
  124           f.close()
  125   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `ghsa_db_path_traversal_7c7b42de10e921bd` (ghsa_db, CVE-2026-28786)

- **Repo:** open-webui/open-webui
- **File path:** `backend/open_webui/routers/audio.py`
- **Framework:** fastapi
- **Sink pattern recorded:** `\bopen\s*\(`
- **Sink match position:** line 400
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  392                       url=f"{request.app.state.config.TTS_OPENAI_API_BASE_URL}/audio/speech",
  393                       json=payload,
  394                       headers=headers,
  395                       ssl=AIOHTTP_CLIENT_SESSION_SSL,
  396                   )
  397   
  398                   r.raise_for_status()
  399   
  400 →                 async with aiofiles.open(file_path, "wb") as f:
  401                       await f.write(await r.read())
  402   
  403                   async with aiofiles.open(file_body_path, "w") as f:
  404                       await f.write(json.dumps(payload))
  405   
  406               return FileResponse(file_path)
  407   
  408           except Exception as e:
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-434 — Unrestricted Upload of File with Dangerous Type

Sampled: **7** / 15 on disk.

### #1 — `ghsa_db_unrestricted_file_upload_1e57653ced4a9814` (ghsa_db, CVE-2024-8019)

- **Repo:** lightning-ai/pytorch-lightning
- **File path:** `docs/source-app/examples/file_server/app.py`
- **Framework:** flask
- **Sink pattern recorded:** `\brequest\.files\b`
- **Sink match position:** line 146
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  138           # 2: Create a flask app
  139           flask_app = Flask(__name__)
  140           CORS(flask_app)
  141   
  142           # 3: Define the upload file endpoint
  143           @flask_app.post("/upload_file/")
  144           def upload_file():
  145               """Upload a file directly as form data."""
  146 →             f = request.files["file"]
  147               return self.upload_file(f)
  148   
  149           @flask_app.get("/")
  150           def list_files():
  151               return self.list_files(str(Path(self.base_dir).resolve()))
  152   
  153           # 5: Start the flask app while providing the `host` and `port`.
  154           flask_app.run(host=self.host, port=self.port, load_dotenv=False)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `cvefixes_unrestricted_file_upload_76c5f08163bd4e25` (cvefixes, CVE-2021-43829)

- **Repo:** https://github.com/Patrowl/PatrowlManager
- **File path:** `forms.py`
- **Framework:** django
- **Sink pattern recorded:** `\bFileField\s*\(`
- **Sink match position:** line 23
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   15   
   16       engine = forms.CharField(widget=forms.Select(
   17           attrs={'class': 'form-control form-control-sm'},
   18           choices=ENGINE_TYPES))
   19       min_level = forms.CharField(widget=forms.Select(
   20           attrs={'class': 'form-control form-control-sm'},
   21           choices=FINDING_SEVERITIES),
   22           label='Minimum severity')
   23 →     file = forms.FileField()
   24   
   25   
   26   class FindingForm(forms.ModelForm):
   27       class Meta:
   28           model = Finding
   29           fields = ['title', 'type', 'severity', 'status', 'description', 'tags',
   30               'solution', 'risk_info', 'vuln_refs', 'links', 'comments', 'asset']
   31           widgets = {
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `ghsa_db_unrestricted_file_upload_09d91b158e01adec` (ghsa_db, CVE-2021-31542)

- **Repo:** django/django
- **File path:** `django/db/models/fields/files.py`
- **Framework:** django
- **Sink pattern recorded:** `\bFileField\s*\(`
- **Sink match position:** line 216
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  208   
  209           # That was fun, wasn't it?
  210           return instance.__dict__[self.field.attname]
  211   
  212       def __set__(self, instance, value):
  213           instance.__dict__[self.field.attname] = value
  214   
  215   
  216 → class FileField(Field):
  217   
  218       # The class to wrap instance attributes in. Accessing the file object off
  219       # the instance will always return an instance of attr_class.
  220       attr_class = FieldFile
  221   
  222       # The descriptor to use for accessing the attribute off of the class.
  223       descriptor_class = FileDescriptor
  224   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `ghsa_db_unrestricted_file_upload_380675ff8d6eb452` (ghsa_db, CVE-2021-31542)

- **Repo:** django/django
- **File path:** `django/db/models/fields/files.py`
- **Framework:** django
- **Sink pattern recorded:** `\bFileField\s*\(`
- **Sink match position:** line 222
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  214   
  215           # That was fun, wasn't it?
  216           return instance.__dict__[self.field.name]
  217   
  218       def __set__(self, instance, value):
  219           instance.__dict__[self.field.name] = value
  220   
  221   
  222 → class FileField(Field):
  223   
  224       # The class to wrap instance attributes in. Accessing the file object off
  225       # the instance will always return an instance of attr_class.
  226       attr_class = FieldFile
  227   
  228       # The descriptor to use for accessing the attribute off of the class.
  229       descriptor_class = FileDescriptor
  230   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `ghsa_db_unrestricted_file_upload_58d7c1707c2aa7ed` (ghsa_db, CVE-2024-8060)

- **Repo:** open-webui/open-webui
- **File path:** `backend/open_webui/routers/audio.py`
- **Framework:** fastapi
- **Sink pattern recorded:** `\bUploadFile\b`
- **Sink match position:** line 22
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   14   import mimetypes
   15   
   16   from fastapi import (
   17       Depends,
   18       FastAPI,
   19       File,
   20       HTTPException,
   21       Request,
   22 →     UploadFile,
   23       status,
   24       APIRouter,
   25   )
   26   from fastapi.middleware.cors import CORSMiddleware
   27   from fastapi.responses import FileResponse
   28   from pydantic import BaseModel
   29   
   30   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `ghsa_db_unrestricted_file_upload_c0589e06ec6175e4` (ghsa_db, CVE-2022-2872)

- **Repo:** octoprint/octoprint
- **File path:** `src/octoprint/server/api/files.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bFileStorage\b`
- **Sink match position:** line 1287
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
 1279       else:
 1280           return filename == "/".join(
 1281               map(lambda x: fileManager.sanitize_name(target, x), filename.split("/"))
 1282           )
 1283   
 1284   
 1285   class WerkzeugFileWrapper(octoprint.filemanager.util.AbstractFileWrapper):
 1286       """
 1287 →     A wrapper around a Werkzeug ``FileStorage`` object.
 1288   
 1289       Arguments:
 1290           file_obj (werkzeug.datastructures.FileStorage): The Werkzeug ``FileStorage`` instance to wrap.
 1291   
 1292       .. seealso::
 1293   
 1294          `werkzeug.datastructures.FileStorage <http://werkzeug.pocoo.org/docs/0.10/datastructures/#werkzeug.datastructures.FileStorage>`_
 1295               The documentation of Werkzeug's ``FileStorage`` class.
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `ghsa_db_unrestricted_file_upload_a1192012ab6fc506` (ghsa_db, CVE-2021-31542)

- **Repo:** django/django
- **File path:** `django/db/models/fields/files.py`
- **Framework:** django
- **Sink pattern recorded:** `\bFileField\s*\(`
- **Sink match position:** line 212
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  204   
  205           # That was fun, wasn't it?
  206           return instance.__dict__[self.field.name]
  207   
  208       def __set__(self, instance, value):
  209           instance.__dict__[self.field.name] = value
  210   
  211   
  212 → class FileField(Field):
  213   
  214       # The class to wrap instance attributes in. Accessing the file object off
  215       # the instance will always return an instance of attr_class.
  216       attr_class = FieldFile
  217   
  218       # The descriptor to use for accessing the attribute off of the class.
  219       descriptor_class = FileDescriptor
  220   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-502 — Deserialization of Untrusted Data

Sampled: **10** / 101 on disk.

### #1 — `ghsa_db_insecure_deserialization_d0f8ec9233989c9c` (ghsa_db, CVE-2023-23930)

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

### #2 — `ghsa_db_insecure_deserialization_39194e29e90e3955` (ghsa_db, CVE-2025-61622)

- **Repo:** apache/fory
- **File path:** `python/pyfory/_registry.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\b__reduce__\b`
- **Sink match position:** line 555
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  547               if cls is types.FunctionType:
  548                   # Use FunctionSerializer for function types (including lambdas)
  549                   serializer = FunctionSerializer(self.fory, cls)
  550               elif dataclasses.is_dataclass(cls):
  551                   # lazy create serializer to handle nested struct fields.
  552                   serializer = DataClassStubSerializer(self.fory, cls, xlang=not self.fory.is_py)
  553               elif issubclass(cls, enum.Enum):
  554                   serializer = EnumSerializer(self.fory, cls)
  555 →             elif (hasattr(cls, "__reduce__") and cls.__reduce__ is not object.__reduce__) or (
  556                   hasattr(cls, "__reduce_ex__") and cls.__reduce_ex__ is not object.__reduce_ex__
  557               ):
  558                   # Use ReduceSerializer for objects that have custom __reduce__ or __reduce_ex__ methods
  559                   # This has higher precedence than StatefulSerializer and ObjectSerializer
  560                   # Only use it for objects with custom reduce methods, not default ones from the object
  561                   module_name = getattr(cls, "__module__", "")
  562                   if module_name.startswith("pandas.") or module_name == "builtins" or cls.__name__ in ("type", "function", "method"):
  563                       # Exclude pandas, built-ins, and certain system types
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `nvd_insecure_deserialization_a5e51c570dc1116d` (nvd_targeted, CVE-2026-23946)

- **Repo:** tendenci/tendenci
- **File path:** `tendenci/apps/helpdesk/views/staff.py`
- **Framework:** django
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 764
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  756           try:
  757               saved_query = SavedSearch.objects.get(pk=request.GET.get('saved_query'))
  758           except SavedSearch.DoesNotExist:
  759               return HttpResponseRedirect(reverse('helpdesk_list'))
  760           if not (saved_query.shared or saved_query.user == request.user):
  761               return HttpResponseRedirect(reverse('helpdesk_list'))
  762           from base64 import b64decode
  763           query_params = simplejson.loads(b64decode(saved_query.query))
  764 →         #query_params = pickle.loads(b64decode(str(saved_query.query).encode()))
  765       elif not (  'queue' in request.GET
  766               or  'assigned_to' in request.GET
  767               or  'status' in request.GET
  768               or  'q' in request.GET
  769               or  'sort' in request.GET
  770               or  'sortreverse' in request.GET
  771                   ):
  772   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `ghsa_db_insecure_deserialization_fe21a71eeb2aad32` (ghsa_db, CVE-2014-3539)

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

### #5 — `nvd_insecure_deserialization_8ba9f2da72be670d` (nvd_targeted, CVE-2025-5174)

- **Repo:** erdogant/pypickle
- **File path:** `pypickle/pypickle.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 95
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   87       fix_imports : bool, default=True
   88           Compatibility option for loading Python 2 pickles in Python 3.
   89       encoding : str, default="ASCII"
   90           Encoding for loading legacy Python 2 pickles.
   91       errors : str, default="strict"
   92           Error handling strategy for decoding.
   93       safe : bool or dict, default=True
   94           - True: Use safe unpickler with restricted modules.
   95 →         - False: Use standard pickle.load (unsafe).
   96           - dict: Use safe unpickler and allow additional custom modules.
   97       verbose : str, default='info'
   98           Verbosity level for logging.
   99   
  100       Returns
  101       -------
  102       object
  103           The deserialized Python object from the pickle file.
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `ghsa_db_insecure_deserialization_cb9896947d24f22f` (ghsa_db, CVE-2018-8021)

- **Repo:** apache/superset
- **File path:** `superset/views/core.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bpickle\.loads?\s*\(`
- **Sink match position:** line 1121
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
 1113       @log_this
 1114       @has_access
 1115       @expose('/import_dashboards', methods=['GET', 'POST'])
 1116       def import_dashboards(self):
 1117           """Overrides the dashboards using pickled instances from the file."""
 1118           f = request.files.get('file')
 1119           if request.method == 'POST' and f:
 1120               current_tt = int(time.time())
 1121 →             data = pickle.load(f)
 1122               # TODO: import DRUID datasources
 1123               for table in data['datasources']:
 1124                   ds_class = ConnectorRegistry.sources.get(table.type)
 1125                   ds_class.import_obj(table, import_time=current_tt)
 1126               db.session.commit()
 1127               for dashboard in data['dashboards']:
 1128                   models.Dashboard.import_obj(
 1129                       dashboard, import_time=current_tt)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `ghsa_db_insecure_deserialization_aa04a0a86670dc1a` (ghsa_db, CVE-2022-34668)

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

### #8 — `ghsa_db_insecure_deserialization_431eccb8b5828877` (ghsa_db, CVE-2024-49375)

- **Repo:** RasaHQ/rasa
- **File path:** `rasa/core/featurizers/tracker_featurizers.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bjsonpickle\.`
- **Sink match position:** line 469
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  461           rasa.shared.utils.io.create_directory_for_file(featurizer_file)
  462   
  463           # entity tags are persisted in TED policy, they are not needed for prediction
  464           if self.state_featurizer is not None:
  465               self.state_featurizer.entity_tag_specs = []
  466   
  467           # noinspection PyTypeChecker
  468           rasa.shared.utils.io.write_text_file(
  469 →             str(jsonpickle.encode(self)), featurizer_file
  470           )
  471   
  472       @staticmethod
  473       def load(path: Union[Text, Path]) -> Optional[TrackerFeaturizer]:
  474           """Loads the featurizer from file.
  475   
  476           Args:
  477               path: The path to load the tracker featurizer from.
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `ghsa_db_insecure_deserialization_b095e20c0ff43889` (ghsa_db, CVE-2022-34668)

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

### #10 — `ghsa_db_insecure_deserialization_e62b9f467793e4c3` (ghsa_db, CVE-2026-23946)

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

## CWE-78 — OS Command Injection

Sampled: **10** / 59 on disk.

### #1 — `ghsa_db_command_injection_e251a5ee13ae1948` (ghsa_db, CVE-2020-1734)

- **Repo:** ansible/ansible
- **File path:** `lib/ansible/plugins/lookup/pipe.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bPopen\s*\(`
- **Sink match position:** line 61
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   53               The shell argument (which defaults to False) specifies whether to use the
   54               shell as the program to execute. If shell is True, it is recommended to pass
   55               args as a string rather than as a sequence
   56   
   57               https://github.com/ansible/ansible/issues/6550
   58               '''
   59               term = str(term)
   60   
   61 →             p = subprocess.Popen(term, cwd=self._loader.get_basedir(), shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
   62               (stdout, stderr) = p.communicate()
   63               if p.returncode == 0:
   64                   ret.append(stdout.decode("utf-8").rstrip())
   65               else:
   66                   raise AnsibleError("lookup_plugin.pipe(%s) returned %d" % (term, p.returncode))
   67           return ret
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_command_injection_79944d2f1b3df900` (ghsa_db, CVE-2021-23422)

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

### #3 — `cvefixes_command_injection_7658e075098eb050` (cvefixes, CVE-2020-7698)

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

### #4 — `cvefixes_command_injection_259531a675339a52` (cvefixes, CVE-2021-23422)

- **Repo:** https://github.com/tabatkins/bikeshed
- **File path:** `cli.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bos\.(system|popen|spawn[lpvP])\s*\(`
- **Sink match position:** line 669
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  661           )
  662           sys.exit(0 if result else 1)
  663   
  664   
  665   def handleProfile(options):
  666       root = f'--root="{options.root}"' if options.root else ""
  667       leaf = f'--leaf="{options.leaf}"' if options.leaf else ""
  668       if options.svgFile:
  669 →         os.system(
  670               "time python -m cProfile -o stat.prof -m bikeshed -f spec && gprof2dot -f pstats --skew=.0001 {root} {leaf} stat.prof | dot -Tsvg -o {svg} && rm stat.prof".format(
  671                   root=root, leaf=leaf, svg=options.svgFile
  672               )
  673           )
  674       else:
  675           os.system(
  676               "time python -m cProfile -o /tmp/stat.prof -m bikeshed -f spec && gprof2dot -f pstats --skew=.0001 {root} {leaf} /tmp/stat.prof | xdot &".format(
  677                   root=root, leaf=leaf
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

### #6 — `ghsa_db_command_injection_1b2e003af80352d6` (ghsa_db, CVE-2025-12763)

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

### #7 — `ghsa_db_command_injection_28dd18b7c67b4d93` (ghsa_db, CVE-2023-52311)

- **Repo:** PaddlePaddle/Paddle
- **File path:** `python/paddle/utils/download.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True`
- **Sink match position:** line 204
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  196           return False
  197   
  198   
  199   def _wget_download(url, fullname):
  200       # using wget to download url
  201       tmp_fullname = fullname + "_tmp"
  202       # –user-agent
  203       command = f'wget -O {tmp_fullname} -t {DOWNLOAD_RETRY_LIMIT} {url}'
  204 →     subprc = subprocess.Popen(
  205           command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
  206       )
  207       _ = subprc.communicate()
  208   
  209       if subprc.returncode != 0:
  210           raise RuntimeError(
  211               f'{command} failed. Please make sure `wget` is installed or {url} exists'
  212           )
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #8 — `ghsa_db_command_injection_925853f13a99a99b` (ghsa_db, CVE-2024-22423)

- **Repo:** yt-dlp/yt-dlp
- **File path:** `yt_dlp/utils/_utils.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bPopen\s*\(`
- **Sink match position:** line 802
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  794   
  795   class netrc_from_content(netrc.netrc):
  796       def __init__(self, content):
  797           self.hosts, self.macros = {}, {}
  798           with io.StringIO(content) as stream:
  799               self._parse('-', stream, False)
  800   
  801   
  802 → class Popen(subprocess.Popen):
  803       if sys.platform == 'win32':
  804           _startupinfo = subprocess.STARTUPINFO()
  805           _startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
  806       else:
  807           _startupinfo = None
  808   
  809       @staticmethod
  810       def _fix_pyinstaller_ld_path(env):
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `ghsa_db_command_injection_e6cbc0aee3fbf653` (ghsa_db, CVE-2023-24816)

- **Repo:** ipython/ipython
- **File path:** `IPython/utils/terminal.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bos\.(system|popen|spawn[lpvP])\s*\(`
- **Sink match position:** line 27
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   19   
   20   # This variable is part of the expected API of the module:
   21   ignore_termtitle = True
   22   
   23   
   24   
   25   if os.name == 'posix':
   26       def _term_clear():
   27 →         os.system('clear')
   28   elif sys.platform == 'win32':
   29       def _term_clear():
   30           os.system('cls')
   31   else:
   32       def _term_clear():
   33           pass
   34   
   35   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `nvd_command_injection_generic_cdd5f24fdc13d5bf` (nvd_targeted, CVE-2026-27811)

- **Repo:** roxy-wi/roxy-wi
- **File path:** `app/modules/config/config.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bos\.(system|popen|spawn[lpvP])\s*\(`
- **Sink match position:** line 218
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  210   		config_path = _replace_config_path_to_correct(kwargs.get('config_file_name'))
  211   
  212   	if service in ('haproxy', 'keepalived'):
  213   		config_path = sql.get_setting(f'{service}_config_path')
  214   
  215   	common.check_is_conf(config_path)
  216   
  217   	try:
  218 → 		os.system(f"dos2unix -q {cfg}")
  219   	except OSError as e:
  220   		roxywi_common.handle_exceptions(e, 'Roxy-WI server', 'There is no dos2unix')
  221   
  222   	try:
  223   		upload(server_ip, tmp_file, cfg)
  224   	except Exception as e:
  225   		roxywi_common.handle_exceptions(e, 'Roxy-WI server', 'Cannot upload config')
  226   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-79 — Cross-site Scripting

Sampled: **10** / 229 on disk.

### #1 — `ghsa_db_cross_site_scripting_2827ef4e05f4e18f` (ghsa_db, CVE-2015-3219)

- **Repo:** openstack/horizon
- **File path:** `openstack_dashboard/dashboards/project/stacks/forms.py`
- **Framework:** django
- **Sink pattern recorded:** `\brequest\.(args|form|data|json|values|files|cookies|GET|POST)`
- **Sink match position:** line 133
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  125   
  126       def __init__(self, *args, **kwargs):
  127           self.next_view = kwargs.pop('next_view')
  128           super(TemplateForm, self).__init__(*args, **kwargs)
  129   
  130       def clean(self):
  131           cleaned = super(TemplateForm, self).clean()
  132   
  133 →         files = self.request.FILES
  134           self.clean_uploaded_files('template', _('template'), cleaned, files)
  135           self.clean_uploaded_files('environment', _('environment'), cleaned,
  136                                     files)
  137   
  138           # Validate the template and get back the params.
  139           kwargs = {}
  140           if cleaned['template_data']:
  141               kwargs['template'] = cleaned['template_data']
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_cross_site_scripting_e8ed95bac52c841f` (ghsa_db, CVE-2022-22818)

- **Repo:** django/django
- **File path:** `django/template/defaulttags.py`
- **Framework:** django
- **Sink pattern recorded:** `\|\s*safe\b`
- **Sink match position:** line 716
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  708       If you want to disable auto-escaping of variables you can use::
  709   
  710           {% autoescape off %}
  711               {% firstof var1 var2 var3 "<strong>fallback value</strong>" %}
  712           {% autoescape %}
  713   
  714       Or if only some variables should be escaped, you can use::
  715   
  716 →         {% firstof var1 var2|safe var3 "<strong>fallback value</strong>"|safe %}
  717       """
  718       bits = token.split_contents()[1:]
  719       asvar = None
  720       if not bits:
  721           raise TemplateSyntaxError("'firstof' statement requires at least one argument")
  722   
  723       if len(bits) >= 2 and bits[-2] == 'as':
  724           asvar = bits[-1]
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `ghsa_db_cross_site_scripting_5978cdf2e9cb27ba` (ghsa_db, CVE-2016-6519)

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

### #4 — `ghsa_db_cross_site_scripting_0777ca0dd8e5006d` (ghsa_db, CVE-2016-6186)

- **Repo:** django/django
- **File path:** `django/views/debug.py`
- **Framework:** django
- **Sink pattern recorded:** `\|\s*safe\b`
- **Sink match position:** line 1235
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
 1227   <body>
 1228   <div id="summary">
 1229     <h1>{{ heading }}</h1>
 1230     <h2>{{ subheading }}</h2>
 1231   </div>
 1232   
 1233   <div id="instructions">
 1234     <p>
 1235 →     {{ instructions|safe }}
 1236     </p>
 1237   </div>
 1238   
 1239   <div id="explanation">
 1240     <p>
 1241       {{ explanation|safe }}
 1242     </p>
 1243   </div>
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `ghsa_db_cross_site_scripting_03a23c6353ee1324` (ghsa_db, CVE-2015-3219)

- **Repo:** openstack/horizon
- **File path:** `openstack_dashboard/dashboards/project/stacks/forms.py`
- **Framework:** django
- **Sink pattern recorded:** `\brequest\.(args|form|data|json|values|files|cookies|GET|POST)`
- **Sink match position:** line 128
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  120   
  121       def __init__(self, *args, **kwargs):
  122           self.next_view = kwargs.pop('next_view')
  123           super(TemplateForm, self).__init__(*args, **kwargs)
  124   
  125       def clean(self):
  126           cleaned = super(TemplateForm, self).clean()
  127   
  128 →         files = self.request.FILES
  129           self.clean_uploaded_files('template', _('template'), cleaned, files)
  130           self.clean_uploaded_files('environment',
  131               _('environment'),
  132               cleaned,
  133               files)
  134   
  135           # Validate the template and get back the params.
  136           kwargs = {}
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `ghsa_db_cross_site_scripting_68c4c469d3906bcd` (ghsa_db, CVE-2009-2967)

- **Repo:** buildbot/buildbot
- **File path:** `buildbot/status/web/builder.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bfrom\s+twisted\b`
- **Sink match position:** line 1
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
    1 → from twisted.web.error import NoResource
    2   from twisted.web import html, static
    3   from twisted.web.util import Redirect
    4   
    5   import re, urllib, time
    6   from twisted.python import log
    7   from buildbot import interfaces
    8   from buildbot.status.web.base import HtmlResource, make_row, \
    9        make_force_build_form, OneLineMixin, path_to_build, path_to_slave, \
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `ghsa_db_cross_site_scripting_05ed0ddea2088545` (ghsa_db, CVE-2018-12104)

- **Repo:** airbnb/knowledge-repo
- **File path:** `knowledge_repo/app/routes/comment.py`
- **Framework:** flask
- **Sink pattern recorded:** `\brequest\.(args|form|data|json|values|files|cookies|GET|POST)`
- **Sink match position:** line 29
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   21   
   22   
   23   @blueprint.route('/comment', methods=['POST'])
   24   @PageView.logged
   25   @permissions.post_comment.require()
   26   def post_comment():
   27       """ Post a comment underneath a post """
   28   
   29 →     path = request.args.get('path', '')
   30       comment_id = request.args.get('comment_id')
   31       data = request.get_json()
   32   
   33       post = (db_session.query(Post)
   34                         .filter(Post.path == path)
   35                         .first())
   36   
   37       if not post:
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #8 — `ghsa_db_cross_site_scripting_612d75bb91a5d12c` (ghsa_db, CVE-2020-17515)

- **Repo:** apache/airflow
- **File path:** `airflow/www/views.py`
- **Framework:** flask
- **Sink pattern recorded:** `\bMarkup\s*\(`
- **Sink match position:** line 809
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  801           all_errors = ""
  802           dag_orm = None
  803           dag_id = None
  804   
  805           try:
  806               dag_id = request.args.get('dag_id')
  807               dag_orm = DagModel.get_dagmodel(dag_id, session=session)
  808               code = DagCode.get_code_by_fileloc(dag_orm.fileloc)
  809 →             html_code = Markup(
  810                   highlight(
  811                       code, lexers.PythonLexer(), HtmlFormatter(linenos=True)  # pylint: disable=no-member
  812                   )
  813               )
  814   
  815           except Exception as e:  # pylint: disable=broad-except
  816               all_errors += (
  817                   "Exception encountered during "
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `ghsa_db_cross_site_scripting_fca667f2b932f938` (ghsa_db, CVE-2024-23345)

- **Repo:** nautobot/nautobot
- **File path:** `nautobot/core/templatetags/helpers.py`
- **Framework:** django
- **Sink pattern recorded:** `\bmark_safe\s*\(`
- **Sink match position:** line 24
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   16   import yaml
   17   
   18   from nautobot.apps.config import get_app_settings_or_config
   19   from nautobot.core import forms
   20   from nautobot.core.utils import color, config, data, lookup
   21   from nautobot.core.utils.requests import add_nautobot_version_query_param_to_url
   22   
   23   # S308 is suspicious-mark-safe-usage, but these are all using static strings that we know to be safe
   24 → HTML_TRUE = mark_safe('<span class="text-success"><i class="mdi mdi-check-bold" title="Yes"></i></span>')  # noqa: S308
   25   HTML_FALSE = mark_safe('<span class="text-danger"><i class="mdi mdi-close-thick" title="No"></i></span>')  # noqa: S308
   26   HTML_NONE = mark_safe('<span class="text-muted">&mdash;</span>')  # noqa: S308
   27   
   28   DEFAULT_SUPPORT_MESSAGE = (
   29       "If further assistance is required, please join the `#nautobot` channel "
   30       "on [Network to Code's Slack community](https://slack.networktocode.com/) and post your question."
   31   )
   32   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `ghsa_db_cross_site_scripting_5c641abeb528fd84` (ghsa_db, CVE-2026-28222)

- **Repo:** wagtail/wagtail
- **File path:** `wagtail/contrib/table_block/templatetags/table_block_tags.py`
- **Framework:** django
- **Sink pattern recorded:** `\bmark_safe\s*\(`
- **Sink match position:** line 16
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
    8   def cell_classname(context, row_index, col_index, table_header=None):
    9       classnames = context.get("classnames")
   10       if classnames:
   11           if table_header is not None:
   12               row_index += 1
   13           index = (row_index, col_index)
   14           cell_class = classnames.get(index)
   15           if cell_class:
   16 →             return mark_safe(f'class="{cell_class}"')
   17       return ""
   18   
   19   
   20   @register.simple_tag(takes_context=True)
   21   def cell_hidden(context, row_index, col_index, table_header=None):
   22       hidden = context.get("hidden")
   23       if hidden:
   24           if table_header is not None:
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-89 — SQL Injection

Sampled: **10** / 282 on disk.

### #1 — `vudenc_sql_injection_7e2a2713ff80f8cd` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\bSELECT\b.*\bFROM\b`
- **Sink match position:** line 3
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def get_n_tournaments_before_date(db, scene, date, limit):...
    2   sql = (
    3 →     "select url, date from matches where scene='{}' and date<='{}' group by url, date order by date desc limit {};"
    4       .format(scene, date, limit))
    5   res = db.exec(sql)
    6   urls = [r[0] for r in res]
    7   return urls, date
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `vudenc_sql_injection_2461a50171261d80` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 13
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    5               SET
    6                   TimeStamp='%s',
    7                   Status='%s',
    8                   eToday='%s',
    9                   eTotal='%s'
   10               WHERE Serial='%s';
   11           """
   12        % (ts, status, etoday, etotal, inverter_serial))
   13 → self.c.execute(query)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `osv_sql_injection_187821cbb62330b8` (osv, CVE-2022-28346)

- **Repo:** django/django
- **File path:** `tests/queries/tests.py`
- **Framework:** django
- **Sink pattern recorded:** `\bSELECT\b.*\bFROM\b`
- **Sink match position:** line 2153
- **label_source / confidence:** osv / high

**Code excerpt:**

```python
 2145   
 2146   class RawQueriesTests(TestCase):
 2147       @classmethod
 2148       def setUpTestData(cls):
 2149           Note.objects.create(note="n1", misc="foo", id=1)
 2150   
 2151       def test_ticket14729(self):
 2152           # Test representation of raw query with one or few parameters passed as list
 2153 →         query = "SELECT * FROM queries_note WHERE note = %s"
 2154           params = ["n1"]
 2155           qs = Note.objects.raw(query, params=params)
 2156           self.assertEqual(
 2157               repr(qs), "<RawQuerySet: SELECT * FROM queries_note WHERE note = n1>"
 2158           )
 2159   
 2160           query = "SELECT * FROM queries_note WHERE note = %s and misc = %s"
 2161           params = ["n1", "foo"]
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #4 — `ghsa_db_sql_injection_c0165fa15a55d172` (ghsa_db, CVE-2024-4215)

- **Repo:** pgadmin-org/pgadmin4
- **File path:** `web/pgadmin/tools/sqleditor/__init__.py`
- **Framework:** flask
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 887
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  879   
  880       connect = 'connect' in request.args and request.args['connect'] == '1'
  881       is_error, errmsg = check_and_upgrade_to_qt(trans_id, connect)
  882       if is_error:
  883           return make_json_response(success=0, errormsg=errmsg,
  884                                     info=ERROR_MSG_FAIL_TO_PROMOTE_QT,
  885                                     status=404)
  886   
  887 →     return StartRunningQuery(blueprint, current_app.logger).execute(
  888           sql, trans_id, session, connect
  889       )
  890   
  891   
  892   def extract_sql_from_network_parameters(request_data, request_arguments,
  893                                           request_form_data):
  894       if request_data:
  895           sql_parameters = json.loads(request_data)
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `vudenc_sql_injection_3bdbfe3d9a0e3ac7` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 5
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def add_input(self, data):...
    2   connection = self.connect()
    3   query = "INSERT INTO crimes(description) VALUES ('{}');".format(data)
    4   connection.close()
    5 → cursor.execute(query)
    6   connection.commit()
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `vudenc_sql_injection_5a98388feaa4bdb4` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 6
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def update_sql(self, column, location_nw, title):...
    2   sql_update = (
    3       f"UPDATE `artikelen` SET `{column}` = '{location_nw}' WHERE `title` = '{title}'"
    4       )
    5   print(sql_update)
    6 → cursor.execute(sql_update)
    7   return
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `osv_sql_injection_5139445be08955ef` (osv, CVE-2026-1287)

- **Repo:** django/django
- **File path:** `django/db/models/sql/query.py`
- **Framework:** django
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 220
- **label_source / confidence:** osv / high

**Code excerpt:**

```python
  212           elif params_type is dict:
  213               params = {key: adapter(val) for key, val in self.params.items()}
  214           elif params_type is None:
  215               params = None
  216           else:
  217               raise RuntimeError("Unexpected params type: %s" % params_type)
  218   
  219           self.cursor = connection.cursor()
  220 →         self.cursor.execute(self.sql, params)
  221   
  222   
  223   ExplainInfo = namedtuple("ExplainInfo", ("format", "options"))
  224   
  225   
  226   class Query(BaseExpression):
  227       """A single SQL query."""
  228   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #8 — `vudenc_sql_injection_3f451c47cbb70d19` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 4
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def create_video(playlist_id, title, thumbnail, position):...
    2   db = connect_to_database()
    3   cursor = db.cursor()
    4 → cursor.execute(
    5       "INSERT INTO video (playlist_id, title, thumbnail, position) VALUES('{playlist_id}', '{title}', '{thumbnail}', '{position}');"
    6       .format(playlist_id=playlist_id, title=title, thumbnail=thumbnail,
    7       position=position))
    8   db.commit()
    9   db.close()
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `osv_sql_injection_8377676dec535251` (osv, CVE-2022-28346)

- **Repo:** django/django
- **File path:** `django/db/models/sql/query.py`
- **Framework:** django
- **Sink pattern recorded:** `\.execute(?:many|script)?\s*\(`
- **Sink match position:** line 142
- **label_source / confidence:** osv / high

**Code excerpt:**

```python
  134           elif params_type is dict:
  135               params = {key: adapter(val) for key, val in self.params.items()}
  136           elif params_type is None:
  137               params = None
  138           else:
  139               raise RuntimeError("Unexpected params type: %s" % params_type)
  140   
  141           self.cursor = connection.cursor()
  142 →         self.cursor.execute(self.sql, params)
  143   
  144   
  145   ExplainInfo = namedtuple("ExplainInfo", ("format", "options"))
  146   
  147   
  148   class Query(BaseExpression):
  149       """A single SQL query."""
  150   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `vudenc_sql_injection_8ec70d7ab18f1821` (vudenc, —)

- **Repo:** —
- **File path:** `—`
- **Framework:** unknown
- **Sink pattern recorded:** `\bSELECT\b.*\bFROM\b`
- **Sink match position:** line 3
- **label_source / confidence:** vudenc_commit / medium

**Code excerpt:**

```python
    1   def get_last_ranked_month(db, scene, player):...
    2   sql = (
    3 →     "select date from ranks where scene='{}' and player='{}' order by date desc limit 1;"
    4       .format(scene, player))
    5   res = db.exec(sql)
    6   date = res[0][0]
    7   return date
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

## CWE-918 — Server-Side Request Forgery

Sampled: **10** / 63 on disk.

### #1 — `ghsa_db_ssrf_4d10a01660b7600e` (ghsa_db, CVE-2022-0339)

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

### #2 — `ghsa_db_ssrf_828bf62b55a67f6a` (ghsa_db, CVE-2026-27696)

- **Repo:** dgtlmoon/changedetection.io
- **File path:** `changedetectionio/store/__init__.py`
- **Framework:** flask
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 688
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  680           apply_extras = deepcopy(extras)
  681           apply_extras['tags'] = [] if not apply_extras.get('tags') else apply_extras.get('tags')
  682   
  683           # Was it a share link? try to fetch the data
  684           if (url.startswith("https://changedetection.io/share/")):
  685               import requests
  686   
  687               try:
  688 →                 r = requests.request(method="GET",
  689                                        url=url,
  690                                        # So we know to return the JSON instead of the human-friendly "help" page
  691                                        headers={'App-Guid': self.__data['app_guid']},
  692                                        timeout=5.0)  # 5 second timeout to prevent blocking
  693                   res = r.json()
  694   
  695                   # List of permissible attributes we accept from the wild internet
  696                   for k in [
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #3 — `ghsa_db_ssrf_e4d36275d8f974fa` (ghsa_db, CVE-2025-67743)

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

### #4 — `nvd_ssrf_59622ba4e8c1f9b8` (nvd_targeted, CVE-2026-25991)

- **Repo:** TandoorRecipes/recipes
- **File path:** `cookbook/integration/paprika.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 96
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   88               # If a user takes an image himself, only photo_data will be set.
   89               # If a user imports an image, both will be set. But the photo_data will be a center-cropped square resized version, so the image_url is preferred.
   90   
   91               # Try to download image if possible
   92               try:
   93                   if recipe_json.get("image_url", None):
   94                       url = recipe_json.get("image_url", None)
   95                       if validate_import_url(url):
   96 →                         response = requests.get(url)
   97                           if response.status_code == 200 and len(response.content) > 0:
   98                               self.import_recipe_image(recipe, BytesIO(response.content))
   99               except Exception:
  100                   pass
  101   
  102               # If no image downloaded, try to extract from photo_data
  103               if not recipe.image:
  104                   if recipe_json.get("photo_data", None):
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `ghsa_db_ssrf_66f82f29d3908ed5` (ghsa_db, CVE-2025-67743)

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

### #6 — `ghsa_db_ssrf_049c2a7d6f7d2821` (ghsa_db, CVE-2026-34753)

- **Repo:** vllm-project/vllm
- **File path:** `vllm/entrypoints/openai/run_batch.py`
- **Framework:** fastapi
- **Sink pattern recorded:** `\baiohttp\.\w+`
- **Sink match position:** line 325
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  317               disable=not enable_tqdm,
  318               bar_format=_BAR_FORMAT,
  319           )
  320           return self._pbar
  321   
  322   
  323   async def read_file(path_or_url: str) -> str:
  324       if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
  325 →         async with aiohttp.ClientSession() as session, session.get(path_or_url) as resp:
  326               resp.raise_for_status()
  327               return await resp.text()
  328       else:
  329           with open(path_or_url, encoding="utf-8") as f:
  330               return f.read()
  331   
  332   
  333   async def write_local_file(
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `nvd_ssrf_b16537c9982e2244` (nvd_targeted, CVE-2026-25738)

- **Repo:** indico/indico
- **File path:** `indico/util/network.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 74
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
   66           validate_request_url(target)
   67       except InsecureRequestError as exc:
   68           raise InsecureRequestError('Request redirected to disallowed URL') from exc
   69   
   70   
   71   def make_validate_request_url_hook():
   72       """Util to get the requests hook in a more concise way.
   73   
   74 →     Use it like this: ``requests.get(..., **make_validate_request_url_hook())``
   75       """
   76       return {'hooks': {'response': validate_redirect_target_hook}}
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #8 — `ghsa_db_ssrf_66f247bb488bc347` (ghsa_db, CVE-2022-0766)

- **Repo:** janeczku/calibre-web
- **File path:** `cps/helper.py`
- **Framework:** flask
- **Sink pattern recorded:** `\brequests\.(get|post|put|delete|head|options|patch|request)\s*\(`
- **Sink match position:** line 740
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  732   def save_cover_from_url(url, book_path):
  733       try:
  734           if not cli.allow_localhost:
  735               # 127.0.x.x, localhost, [::1], [::ffff:7f00:1]
  736               ip = socket.getaddrinfo(urlparse(url).hostname, 0)[0][4][0]
  737               if ip.startswith("127.") or ip.startswith('::ffff:7f') or ip == "::1":
  738                   log.error("Localhost was accessed for cover upload")
  739                   return False, _("You are not allowed to access localhost for cover uploads")
  740 →         img = requests.get(url, timeout=(10, 200))      # ToDo: Error Handling
  741           img.raise_for_status()
  742           return save_cover(img, book_path)
  743       except (socket.gaierror,
  744               requests.exceptions.HTTPError,
  745               requests.exceptions.ConnectionError,
  746               requests.exceptions.Timeout) as ex:
  747           log.info(u'Cover Download Error %s', ex)
  748           return False, _("Error Downloading Cover")
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `ghsa_db_ssrf_2e94147bd8064620` (ghsa_db, CVE-2026-24779)

- **Repo:** vllm-project/vllm
- **File path:** `vllm/connections.py`
- **Framework:** aiohttp
- **Sink pattern recorded:** `\baiohttp\.\w+`
- **Sink match position:** line 23
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   15       """Helper class to send HTTP requests."""
   16   
   17       def __init__(self, *, reuse_client: bool = True) -> None:
   18           super().__init__()
   19   
   20           self.reuse_client = reuse_client
   21   
   22           self._sync_client: requests.Session | None = None
   23 →         self._async_client: aiohttp.ClientSession | None = None
   24   
   25       def get_sync_client(self) -> requests.Session:
   26           if self._sync_client is None or not self.reuse_client:
   27               self._sync_client = requests.Session()
   28   
   29           return self._sync_client
   30   
   31       # NOTE: We intentionally use an async function even though it is not
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `ghsa_ssrf_0cfd1c539d6b045d` (ghsa, CVE-2026-33440)

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

## CWE-94 — Code Injection

Sampled: **10** / 91 on disk.

### #1 — `nvd_code_injection_e6cdd80f1f94bc45` (nvd_targeted, CVE-2024-8374)

- **Repo:** Ultimaker/Cura
- **File path:** `plugins/3MFReader/ThreeMFReader.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 185
- **label_source / confidence:** nvd / high

**Code excerpt:**

```python
  177                           um_node.callDecoration("setActiveExtruder", extruder_stack.getId())
  178                       else:
  179                           Logger.log("w", "Unable to find extruder in position %s", setting_value)
  180                       continue
  181                   if key == "print_order":
  182                       um_node.printOrder = int(setting_value)
  183                       continue
  184                   if key =="drop_to_buildplate":
  185 →                     um_node.setSetting(SceneNodeSettings.AutoDropDown, eval(setting_value))
  186                       continue
  187                   if key in known_setting_keys:
  188                       setting_container.setProperty(key, "value", setting_value)
  189                   else:
  190                       um_node.metadata[key] = settings[key]
  191   
  192           if len(um_node.getChildren()) > 0 and um_node.getMeshData() is None:
  193               if len(um_node.getAllChildren()) == 1:
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #2 — `ghsa_db_code_injection_1380767e00065d83` (ghsa_db, CVE-2022-21797)

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

### #3 — `cvefixes_code_injection_5e31e4c0f4f01323` (cvefixes, CVE-2018-1000070)

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

### #4 — `ghsa_db_code_injection_5b604b8b19cd4da5` (ghsa_db, CVE-2024-21513)

- **Repo:** langchain-ai/langchain
- **File path:** `libs/experimental/langchain_experimental/sql/vector_sql.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 81
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   73           if start >= 0:
   74               end = text.upper().find("FROM")
   75               text = text.replace(text[start + len("SELECT") + 1 : end - 1], "*")
   76           return super().parse(text)
   77   
   78   
   79   def _try_eval(x: Any) -> Any:
   80       try:
   81 →         return eval(x)
   82       except Exception:
   83           return x
   84   
   85   
   86   def get_result_from_sqldb(
   87       db: SQLDatabase, cmd: str
   88   ) -> Union[str, List[Dict[str, Any]], Dict[str, Any]]:
   89       result = db._execute(cmd, fetch="all")  # type: ignore
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #5 — `ghsa_db_code_injection_53a0e6b1b9a4e465` (ghsa_db, CVE-2020-10684)

- **Repo:** ansible/ansible
- **File path:** `lib/ansible/vars/clean.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bcompile\s*\(`
- **Sink match position:** line 138
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  130   
  131       # remove common connection vars
  132       remove_keys.update(fact_keys.intersection(C.COMMON_CONNECTION_VARS))
  133   
  134       # next we remove any connection plugin specific vars
  135       for conn_path in connection_loader.all(path_only=True):
  136           try:
  137               conn_name = os.path.splitext(os.path.basename(conn_path))[0]
  138 →             re_key = re.compile('^ansible_%s_' % conn_name)
  139               for fact_key in fact_keys:
  140                   # most lightweight VM or container tech creates devices with this pattern, this avoids filtering them out
  141                   if (re_key.match(fact_key) and not fact_key.endswith(('_bridge', '_gwbridge'))) or re_key.startswith('ansible_become_'):
  142                       remove_keys.add(fact_key)
  143           except AttributeError:
  144               pass
  145   
  146       # remove some KNOWN keys
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #6 — `ghsa_db_code_injection_3eadbdbbfd57e029` (ghsa_db, CVE-2014-0472)

- **Repo:** django/django
- **File path:** `django/core/urlresolvers.py`
- **Framework:** django
- **Sink pattern recorded:** `\bcompile\s*\(`
- **Sink match position:** line 174
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  166           """
  167           language_code = get_language()
  168           if language_code not in self._regex_dict:
  169               if isinstance(self._regex, six.string_types):
  170                   regex = self._regex
  171               else:
  172                   regex = force_text(self._regex)
  173               try:
  174 →                 compiled_regex = re.compile(regex, re.UNICODE)
  175               except re.error as e:
  176                   raise ImproperlyConfigured(
  177                       '"%s" is not a valid regular expression: %s' %
  178                       (regex, six.text_type(e)))
  179   
  180               self._regex_dict[language_code] = compiled_regex
  181           return self._regex_dict[language_code]
  182   
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #7 — `ghsa_db_code_injection_1c3818dae3303a7a` (ghsa_db, CVE-2025-46724)

- **Repo:** langroid/langroid
- **File path:** `langroid/vector_store/base.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 162
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  154           """Compute a result on a set of documents,
  155           using a dataframe calc string like `df.groupby('state')['income'].mean()`.
  156           """
  157           # convert each doc to a dict, using dotted paths for nested fields
  158           dicts = [flatten_dict(doc.dict(by_alias=True)) for doc in docs]
  159           df = pd.DataFrame(dicts)
  160   
  161           try:
  162 →             # SECURITY: Use Python's eval() with NO globals and only {"df": df}
  163               # in locals. This allows pandas operations on `df` while preventing
  164               # access to builtins or other potentially harmful global functions,
  165               # mitigating risks associated with executing untrusted `calc` strings.
  166               result = eval(calc, {}, {"df": df})  # type: ignore
  167           except Exception as e:
  168               # return error message so LLM can fix the calc string if needed
  169               err = f"""
  170               Error encountered in pandas eval: {str(e)}
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #8 — `ghsa_db_code_injection_13680991eb145aa6` (ghsa_db, CVE-2026-29039)

- **Repo:** dgtlmoon/changedetection.io
- **File path:** `changedetectionio/forms.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\bcompile\s*\(`
- **Sink match position:** line 557
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  549   
  550   
  551   class ValidateSinglePythonRegexString(object):
  552       def __init__(self, message=None):
  553           self.message = message
  554   
  555       def __call__(self, form, field):
  556           try:
  557 →             re.compile(field.data)
  558           except re.error:
  559               message = field.gettext('RegEx \'%s\' is not a valid regular expression.')
  560               raise ValidationError(message % (field.data))
  561   
  562   
  563   class ValidateListRegex(object):
  564       """
  565       Validates that anything that looks like a regex passes as a regex
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #9 — `ghsa_db_code_injection_e7580923410221ca` (ghsa_db, CVE-2022-0845)

- **Repo:** pytorchlightning/pytorch-lightning
- **File path:** `pytorch_lightning/utilities/argparse.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 124
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
  116       env_args = {}
  117       for arg_name, _, _ in cls_arg_defaults:
  118           env = template % {"cls_name": cls.__name__.upper(), "cls_argument": arg_name.upper()}
  119           val = os.environ.get(env)
  120           if not (val is None or val == ""):
  121               # todo: specify the possible exception
  122               with suppress(Exception):
  123                   # converting to native types like int/float/bool
  124 →                 val = eval(val)
  125               env_args[arg_name] = val
  126       return Namespace(**env_args)
  127   
  128   
  129   def get_init_arguments_and_types(cls: Any) -> List[Tuple[str, Tuple, Any]]:
  130       r"""Scans the class signature and returns argument names, types and default values.
  131   
  132       Returns:
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---

### #10 — `ghsa_db_code_injection_0dbc5089a9ebdf35` (ghsa_db, CVE-2023-39662)

- **Repo:** run-llama/llama_index
- **File path:** `llama_index/query_engine/pandas_query_engine.py`
- **Framework:** unknown
- **Sink pattern recorded:** `\beval\s*\(`
- **Sink match position:** line 32
- **label_source / confidence:** github_advisory_db / high

**Code excerpt:**

```python
   24   from llama_index.utils import print_text
   25   
   26   logger = logging.getLogger(__name__)
   27   
   28   
   29   DEFAULT_INSTRUCTION_STR = (
   30       "We wish to convert this query to executable Python code using Pandas.\n"
   31       "The final line of code should be a Python expression that can be called "
   32 →     "with the `eval()` function. This expression should represent a solution "
   33       "to the query. This expression should not have leading or trailing "
   34       "quotes.\n"
   35   )
   36   
   37   
   38   def default_output_processor(
   39       output: str, df: pd.DataFrame, **output_kwargs: Any
   40   ) -> str:
```

**Verdict:** [ PASS / FAIL ]

**If FAIL, the actual CWE (or reason):**

---
