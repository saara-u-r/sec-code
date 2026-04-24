# VULN_QUERIES — Detailed Explanation
## File: `src/generator/scraper/github_scraper.py`

Every query has two mandatory parts:
- `"app.route"` — ensures the file is a real Flask endpoint (not a test, migration script, or utility)
- A vulnerability-specific pattern — a dangerous function appearing near user-controlled input

The combination of a web entry point + dangerous function + user-controlled data is what makes a vulnerability **exploitable by a real attacker**.

---

## SQL Injection (CWE-89) — 7 Queries

The core idea: SQL injection happens when **user input is embedded directly into a SQL string** instead of being passed as a parameter.

---

**Query 1:** `language:python "app.route" "execute(f" SELECT`
```python
cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
```
The `execute(f"` string means the SQL query is an **f-string being passed directly into execute()**. F-strings substitute variables inline at runtime — there's no escaping. If `user_id` comes from `request.args`, an attacker can inject `1 OR 1=1` and dump the whole table. This is the most obvious and direct form of SQLi.

---

**Query 2:** `language:python "app.route" "execute(" request.args SELECT`
```python
user_id = request.args.get("id")
cursor.execute("SELECT * FROM users WHERE id=" + user_id)
```
This catches the **multi-line** version where the bad string isn't built inside `execute()` — the user input (`request.args`) is somewhere nearby and `execute(` + `SELECT` are both in the file. GitHub finds files containing all three terms anywhere in the file.

---

**Query 3:** `language:python "app.route" "% request.args" execute`
```python
cursor.execute("SELECT * FROM users WHERE name='%s'" % request.args.get("name"))
```
The `%` operator is Python's old string formatting. `"some string %s" % variable` substitutes the variable in. This catches the pattern where `%` formatting with `request.args` flows into `execute()`. Same result as f-strings — no escaping, user controls the SQL.

---

**Query 4:** `language:python "app.route" ".format(" SELECT request`
```python
cursor.execute("SELECT * FROM users WHERE id={}".format(request.args.get("id")))
```
`.format()` is Python's other string formatting method. It slots variables into `{}` placeholders. Again, no SQL escaping — the user's input lands directly in the query. This catches it by looking for `.format(` + `SELECT` + `request` all in the same file.

---

**Query 5:** `language:python "app.route" "execute(" "+" request`
```python
cursor.execute("SELECT * FROM users WHERE id=" + request.args.get("id"))
```
Plain **string concatenation** with `+`. The `+` operator joins two strings — here it joins a hard-coded SQL prefix with user input. This is the oldest and most readable form of SQLi. Catches it with `execute(` + `+` + `request` in the same file.

---

**Query 6:** `language:python "app.route" "request.args.get" "SELECT"`
```python
user_id = request.args.get("id")
query = "SELECT * FROM users WHERE id=" + user_id
cursor.execute(query)
```
This is the broadest query — it just needs `request.args.get` AND `SELECT` anywhere in the file. It catches **even more indirect multi-line taint flows** where the dangerous concatenation might happen several lines away from the `execute()`. The tradeoff: more false positives, but catches patterns the other queries miss. The `detect_vuln_type()` verification step filters those out afterwards.

---

**Query 7:** `language:python "app.route" "request.form" "INSERT INTO"`
```python
username = request.form.get("username")
cursor.execute("INSERT INTO users VALUES ('" + username + "')")
```
This specifically targets **write operations** (INSERT) using **form data** (POST requests). The previous 6 queries were mostly SELECT-focused. This catches login forms, registration pages, etc. where form input goes straight into an INSERT without sanitization. `request.form` is what Flask uses to read POST body data.

---

## Command Injection (CWE-78) — 7 Queries

The core idea: command injection happens when **user input is passed to a shell/system call** that executes it as an OS command.

---

**Query 1:** `language:python "app.route" "os.system(" request`
```python
os.system("ping " + request.args.get("host"))
```
`os.system()` runs a shell command directly. If `host` is `google.com; rm -rf /`, the shell runs both commands. This is the simplest and most dangerous form — one line, full shell access.

---

**Query 2:** `language:python "app.route" "os.popen(" request`
```python
output = os.popen("nslookup " + request.args.get("domain")).read()
```
`os.popen()` is like `os.system()` but captures the output. Often used when the app shows command results to the user (e.g., a "ping tool" or "DNS lookup" feature). Same injection risk, slightly different usage pattern.

---

**Query 3:** `language:python "app.route" "subprocess" "shell=True" request`
```python
subprocess.run("ls " + request.args.get("path"), shell=True)
```
`subprocess` is the modern way to run shell commands. **The key here is `shell=True`** — that flag tells Python to pass the entire string to the shell interpreter, which means shell metacharacters (`;`, `|`, `&&`, etc.) are interpreted. `shell=False` (passing a list) is safe; `shell=True` with user input is not.

---

**Query 4:** `language:python "app.route" "subprocess.run" request.args`
```python
subprocess.run(request.args.get("cmd"), shell=True)
```
A more targeted version of Query 3 — specifically looking for `subprocess.run` with `request.args` data flowing into it. Catches cases where the entire command comes from user input, not just an argument appended to a hard-coded command prefix.

---

**Query 5:** `language:python "app.route" "eval(request"`
```python
result = eval(request.args.get("expression"))
```
`eval()` executes arbitrary Python code. If an attacker passes `__import__('os').system('whoami')` as the expression, it runs on the server. This is effectively Remote Code Execution (RCE) in one function call. The query looks for `eval(request` — they start right next to each other, meaning user input goes straight in.

---

**Query 6:** `language:python "app.route" "exec(request"`
```python
exec(request.data.decode())
```
Same as `eval()` but `exec()` can handle full statements (not just expressions). Even more dangerous in some ways. Again looks for `exec(request` directly — no intermediate variable, raw user data straight into code execution.

---

**Query 7:** `language:python "app.route" "os.system" "request.args.get"`
```python
cmd = request.args.get("command")
os.system(cmd)
```
The multi-line version of Query 1. Here `os.system` and `request.args.get` are both in the file but not on the same line. Catches the pattern where the developer assigned the user input to a variable first before passing it to `os.system`.

---

## Path Traversal (CWE-22) — 7 Queries

The core idea: path traversal happens when **user input controls a file path**, letting attackers use `../` sequences to escape the intended directory and read arbitrary files.

---

**Query 1:** `language:python "app.route" "open(" request.args`
```python
filename = request.args.get("file")
with open(filename) as f:
    return f.read()
```
`open()` reads a file from disk. If `filename` is `../../etc/passwd`, the server reads and returns the system password file. This catches the pattern where a GET parameter directly controls what file gets opened.

---

**Query 2:** `language:python "app.route" "open(" request.form`
```python
filepath = request.form.get("path")
data = open(filepath).read()
```
Same as Query 1 but for POST form data. A file upload or download form where the server-side path comes from the form body instead of a URL query parameter.

---

**Query 3:** `language:python "app.route" "send_file(" request.args`
```python
return send_file(request.args.get("filename"))
```
`send_file()` is Flask's function for serving files to the browser (downloads, attachments, etc.). If the filename comes from user input with no validation, an attacker requests `?filename=../../etc/shadow` and the server sends it as a file download.

---

**Query 4:** `language:python "app.route" "send_file(" request.form`
```python
return send_file(request.form["path"])
```
Same as Query 3 but sourced from POST form data. A form submission where the user specifies what file to download.

---

**Query 5:** `language:python "app.route" "os.path.join" request.args`
```python
filepath = os.path.join("/var/uploads/", request.args.get("name"))
open(filepath)
```
`os.path.join()` is commonly used to build file paths "safely" — but it's not safe if the user input starts with `/` (it ignores the base directory entirely) or contains `../`. Developers often think `os.path.join` protects them. It doesn't.

---

**Query 6:** `language:python "app.route" "request.args.get" "open("`
```python
name = request.args.get("doc")
path = BASE_DIR + name
content = open(path).read()
```
Broader multi-line version — just needs `request.args.get` and `open(` anywhere in the file. The string concatenation building the path might be on a completely different line. Catches more indirect taint flows than Query 1.

---

**Query 7:** `language:python "app.route" "send_from_directory" request`
```python
return send_from_directory("/var/www/files", request.args.get("filename"))
```
`send_from_directory()` is Flask's "safer" file serving function — it's supposed to restrict serving to a specific folder. But if the `filename` argument contains `../`, some versions can still escape the base directory. This query catches all uses of it where `request` data is involved.

---

## Insecure Deserialization (CWE-502) — 7 Queries

The core idea: deserialization converts bytes back into a Python object. **Pickle and similar formats can embed executable code** in the serialized data — so deserializing attacker-controlled bytes = Remote Code Execution.

---

**Query 1:** `language:python "app.route" "pickle.loads(request"`
```python
data = pickle.loads(request.data)
```
The most direct form — user's raw request body (`request.data`) fed straight into `pickle.loads()`. One line = full RCE. An attacker sends a crafted pickle payload and the server executes whatever Python objects are embedded in it.

---

**Query 2:** `language:python "app.route" "pickle.loads(" request.data`
```python
raw = request.data
obj = pickle.loads(raw)
```
Same danger, but with a space between `pickle.loads(` and the argument — meaning the data might be in a variable. Still `request.data` (the raw POST body) going into pickle. The space version catches slightly different code styles.

---

**Query 3:** `language:python "app.route" "pickle.load(" request`
```python
import io
obj = pickle.load(io.BytesIO(request.data))
```
`pickle.load()` (without the `s`) reads from a **file-like object** instead of bytes directly. Developers sometimes wrap `request.data` in `io.BytesIO()` first. Same RCE risk, different API call. This catches both `request.data`, `request.files`, etc.

---

**Query 4:** `language:python "app.route" "yaml.load(request"`
```python
config = yaml.load(request.data)
```
`yaml.load()` without a `Loader` argument (or with `Loader=yaml.Loader`) can deserialize arbitrary Python objects — just like pickle. An attacker sends a crafted YAML payload containing `!!python/object/apply:os.system ['whoami']` and it executes. The safe version is `yaml.safe_load()`.

---

**Query 5:** `language:python "app.route" "yaml.load(" request`
```python
body = request.get_data()
parsed = yaml.load(body, Loader=yaml.FullLoader)
```
Same as Query 4 but with a space, catching cases where the request data is in a variable rather than passed directly. Also catches different `Loader` arguments — `yaml.FullLoader` is still unsafe for untrusted input.

---

**Query 6:** `language:python "app.route" "marshal.loads(" request`
```python
obj = marshal.loads(request.data)
```
`marshal` is Python's low-level serialization module (used internally for `.pyc` files). Like pickle, it can embed code objects. It's rarely used in web apps, but when it is with user input, it's RCE. This query catches that niche but real pattern.

---

**Query 7:** `language:python "app.route" "pickle.loads" "request.cookies"`
```python
session_data = pickle.loads(base64.b64decode(request.cookies.get("session")))
```
This is a **specific real-world attack vector** — session cookies stored as pickled objects. Flask itself uses a different (signed) cookie format, but some apps roll their own session handling using pickle + base64 in cookies. An attacker crafts a malicious cookie, the server deserializes it, RCE happens. This exact pattern has caused real CVEs.
