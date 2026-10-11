"""Isolated regression cases for the priority HydraScan issues.

Run:
    set HYDRASCAN_SCRIPTS=<path to skills/hydrascan/scripts>
    set HYDRASCAN_JS_PARSER_ROOT=<folder containing node_modules/@babel/parser>   (optional)
    python -m unittest discover -s tests -p test_priority_regressions.py -v

Each test asserts the DESIRED behaviour, so a failing test means the defect is
present in the HydraScan revision under test. Tests whose name starts with
test_control_ describe behaviour that already works and should keep passing;
they show the harness can see a positive result.

Everything is synthetic: source snippets are written to a temporary folder,
secrets are fake strings injected only into child-process environments, and
nothing is scanned outside the temporary folder. HydraScan itself is imported
or executed, never modified.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = pathlib.Path(os.environ.get("HYDRASCAN_SCRIPTS") or pathlib.Path(__file__).resolve().parents[1] / "skills/hydrascan/scripts").resolve()
CLI = SCRIPTS / "hydrascan.py"
sys.path.insert(0, str(SCRIPTS))
import hydrascan  # noqa: E402

FLASK = "import os, requests\nfrom flask import Flask, request, send_file, render_template_string, session, g, jsonify, abort\nfrom pathlib import Path\napp = Flask(__name__)\n"
FAKE_SECRET = "FAKE-SECRET-VALUE-0123456789"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="hs-regr-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def analyze(self, files):
        root = self.tmp / "src"
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text, encoding="utf-8")
        return hydrascan.analyze(root, [{"path": name} for name in files])

    def rules(self, files):
        candidates, _gaps, _tasks = self.analyze(files)
        return sorted({item["rule"] for item in candidates})

    def cli(self, *args, env=None):
        environment = {k: v for k, v in os.environ.items() if k.upper() in {"PATH", "SYSTEMROOT", "TEMP", "TMP", "PATHEXT", "COMSPEC", "USERPROFILE", "HOME", "APPDATA", "LOCALAPPDATA", "HYDRASCAN_JS_PARSER_ROOT"}}
        environment.update(env or {})
        return subprocess.run([sys.executable, str(CLI), *args], capture_output=True, env=environment, cwd=self.tmp, timeout=180)

    def source_dir(self, files):
        root = self.tmp / "app"
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text, encoding="utf-8")
        return root


# ---------------------------------------------------------------- A. request input forms
REQUEST_FORMS = {
    "control_args_get_variable": ("u = request.args.get('u')", "u"),
    "args_subscript_variable": ("u = request.args['u']", "u"),
    "args_subscript_inline": ("", "request.args['u']"),
    "args_get_inline": ("", "request.args.get('u')"),
    "form_subscript": ("u = request.form['u']", "u"),
    "form_get": ("u = request.form.get('u')", "u"),
    "values_get": ("u = request.values.get('u')", "u"),
    "json_subscript": ("u = request.json['u']", "u"),
    "get_json_subscript": ("u = request.get_json()['u']", "u"),
    "cookies_get": ("u = request.cookies.get('u')", "u"),
    "headers_get": ("u = request.headers.get('X-Target')", "u"),
    "data_decode": ("u = request.data.decode()", "u"),
    "view_args_subscript": ("u = request.view_args['u']", "u"),
}


class RequestInputForms(Base):
    """D1: every way of reading request data must count as input for the outbound-URL rule."""


def _request_form_test(setup, expression):
    def test(self):
        body = FLASK + "@app.route('/x')\ndef x():\n" + ("    %s\n" % setup if setup else "") + "    return requests.get(%s).text\n" % expression
        self.assertIn("python-outbound-input", self.rules({"m.py": body}))
    return test


for _name, (_setup, _expr) in REQUEST_FORMS.items():
    prefix = "test_" if _name.startswith("control_") else "test_d1_"
    setattr(RequestInputForms, prefix + _name, _request_form_test(_setup, _expr))


class RequestInputOtherFrameworks(Base):
    def test_control_route_parameter(self):
        self.assertIn("python-outbound-input", self.rules({"m.py": FLASK + "@app.route('/x/<path:u>')\ndef x(u):\n    return requests.get(u).text\n"}))

    def test_d1_django_get_subscript(self):
        self.assertIn("python-outbound-input", self.rules({"m.py": "import requests\ndef view(request):\n    return requests.get(request.GET['u']).text\n"}))

    def test_d1_django_post_subscript(self):
        self.assertIn("python-outbound-input", self.rules({"m.py": "import requests\ndef view(request):\n    u = request.POST['u']\n    return requests.get(u).text\n"}))

    def test_d5_host_allowlist_guard_not_flagged(self):
        body = FLASK + "from urllib.parse import urlparse\nALLOWED = {'api.example.com'}\n@app.route('/x')\ndef x():\n    u = request.args.get('u')\n    p = urlparse(u)\n    if p.scheme != 'https' or p.hostname not in ALLOWED:\n        abort(400)\n    return requests.get(u, allow_redirects=False).text\n"
        self.assertNotIn("python-outbound-input", self.rules({"m.py": body}))

    def test_d5_requests_put_is_an_outbound_call(self):
        self.assertIn("python-outbound-input", self.rules({"m.py": "import requests\ndef f(u):\n    return requests.put(u, data='x')\n"}))


# ---------------------------------------------------------------- B. path traversal
PATH_FORMS = {
    "control_join_parameter": "def f(name):\n    return open(os.path.join('/srv/files', name)).read()\n",
    "control_pathlib_parameter": "def f(name):\n    return (Path('/srv/files') / name).read_text()\n",
    "d1_join_request_subscript": "@app.route('/f')\ndef f():\n    return open(os.path.join('/srv/files', request.args['name'])).read()\n",
    "d2_fstring_parameter": "def f(name):\n    return open(f'/srv/files/{name}').read()\n",
    "d2_concat_parameter": "def f(name):\n    return open('/srv/files/' + name).read()\n",
    "d2_bare_route_parameter": "@app.route('/f/<path:name>')\ndef f(name):\n    return open(name).read()\n",
    "d2_send_file": "@app.route('/f')\ndef f():\n    return send_file(os.path.join('/srv/files', request.args.get('name')))\n",
    "d2_os_remove": "def f(name):\n    os.remove(os.path.join('/srv/files', name))\n",
    "d2_upload_filename": "@app.route('/u', methods=['POST'])\ndef u():\n    item = request.files['file']\n    item.save(os.path.join('/srv/uploads', item.filename))\n    return 'ok'\n",
}
PATH_SAFE = {
    "control_int_route_parameter": "@app.route('/r/<int:n>')\ndef r(n):\n    return open('/srv/reports/%d.txt' % n).read()\n",
    "d2_resolved_containment_guard": "BASE = Path('/srv/files').resolve()\n@app.route('/f')\ndef f():\n    target = (BASE / request.args.get('name')).resolve()\n    if not target.is_relative_to(BASE):\n        abort(403)\n    return target.read_text()\n",
    "d2_secure_filename": "from werkzeug.utils import secure_filename\ndef f(name):\n    return open(os.path.join('/srv/files', secure_filename(name))).read()\n",
    "d2_int_coerced_segment": "def f(order_id):\n    return open(os.path.join('/srv/invoices', '%d.pdf' % int(order_id)), 'rb').read()\n",
}


class PathTraversal(Base):
    """D2: path rule coverage (vulnerable forms must be flagged, contained forms must not)."""


def _path_test(body, expect):
    def test(self):
        found = "python-path-input" in self.rules({"m.py": FLASK + body})
        self.assertEqual(found, expect)
    return test


for _name, _body in PATH_FORMS.items():
    setattr(PathTraversal, "test_" + _name + "_is_flagged", _path_test(_body, True))
for _name, _body in PATH_SAFE.items():
    setattr(PathTraversal, "test_" + _name + "_is_not_flagged", _path_test(_body, False))


# ---------------------------------------------------------------- C. template injection
class TemplateInjection(Base):
    """D3: user data concatenated into a template source must produce a candidate on that line."""

    def lines(self, body):
        candidates, _gaps, _tasks = self.analyze({"m.py": FLASK + body})
        return {item["line"] for item in candidates}

    def test_d3_render_template_string_concat(self):
        self.assertIn(7, self.lines("@app.route('/h')\ndef h():\n    return render_template_string('<h1>' + request.args.get('n', '') + '</h1>')\n"))

    def test_d3_jinja_template_from_request(self):
        self.assertIn(8, self.lines("from jinja2 import Template\n@app.route('/h')\ndef h():\n    return Template(request.args.get('t')).render()\n"))

    def test_control_constant_template_not_flagged(self):
        self.assertEqual(set(), self.lines("@app.route('/h')\ndef h():\n    return render_template_string('<h1>{{ n }}</h1>', n=request.args.get('n', ''))\n"))


# ---------------------------------------------------------------- D. safe authorization controls
SQLITE = "import sqlite3\nfrom functools import wraps\nfrom flask import Flask, session, g, jsonify, abort\napp = Flask(__name__)\ndb = sqlite3.connect('a.db')\ndb.row_factory = sqlite3.Row\ndb.execute('CREATE TABLE IF NOT EXISTS invoices (id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL)')\ndb.execute('CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL)')\n"
AUTHZ_SAFE = {
    "owner_predicate_session": "@app.route('/i/<int:i>')\ndef v(i):\n    return jsonify(db.execute('SELECT id, amount FROM invoices WHERE id = ? AND user_id = ?', (i, session['user_id'])).fetchone())\n",
    "owner_predicate_g_user": "@app.route('/i/<int:i>', methods=['POST'])\ndef v(i):\n    db.execute('UPDATE invoices SET amount = 0 WHERE id = ? AND user_id = ?', (i, g.user['id']))\n    return 'ok'\n",
    "owner_check_after_fetch": "@app.route('/i/<int:i>')\ndef v(i):\n    row = db.execute('SELECT id, user_id, amount FROM invoices WHERE id = ?', (i,)).fetchone()\n    if row is None or row['user_id'] != session.get('user_id'):\n        abort(404)\n    return jsonify(dict(row))\n",
    "local_admin_decorator": "def admin_required(view):\n    @wraps(view)\n    def wrapper(*a, **k):\n        if session.get('role') != 'admin':\n            abort(403)\n        return view(*a, **k)\n    return wrapper\n@app.route('/admin/i/<int:i>', methods=['POST'])\n@admin_required\ndef v(i):\n    db.execute('DELETE FROM invoices WHERE id = ?', (i,))\n    return 'ok'\n",
    "public_table_without_owner_column": "@app.route('/p/<int:i>')\ndef v(i):\n    return jsonify(db.execute('SELECT id, name, price FROM products WHERE id = ?', (i,)).fetchone())\n",
}


class SafeAuthorizationControls(Base):
    """D7: correctly controlled object access must not produce an object-authorization candidate."""

    def test_control_unchecked_lookup_is_flagged(self):
        body = SQLITE + "@app.route('/i/<int:i>')\ndef v(i):\n    if 'user_id' not in session:\n        abort(401)\n    return jsonify(db.execute('SELECT id, amount FROM invoices WHERE id = ?', (i,)).fetchone())\n"
        self.assertTrue([r for r in self.rules({"m.py": body}) if "object-authorization" in r])


def _authz_test(body):
    def test(self):
        self.assertEqual([], [r for r in self.rules({"m.py": SQLITE + body}) if "authorization" in r])
    return test


for _name, _body in AUTHZ_SAFE.items():
    setattr(SafeAuthorizationControls, "test_d7_" + _name + "_not_flagged", _authz_test(_body))


# ---------------------------------------------------------------- E. secret files and redaction
SECRET_FILES = [".env", ".env.production", "id_rsa", "server.pem", "credentials",  # already excluded (controls)
                ".netrc", ".git-credentials", ".pgpass", ".htpasswd", "id_ecdsa", "id_dsa", "keystore.jks", "app.keystore",
                "terraform.tfstate", "service-account.json", "secrets.yaml", "secrets.json", ".docker/config.json", "wp-config.php"]
CONTROL_SECRET_FILES = {".env", ".env.production", "id_rsa", "server.pem", "credentials"}


class SecretFileExclusion(Base):
    """R3: credential-bearing files must not be copied into the snapshot."""


def _secret_file_test(name):
    def test(self):
        source = self.source_dir({name: "fake = '%s'\n" % FAKE_SECRET, "main.py": "x = 1\n"})
        inventory = hydrascan.snapshot(source, self.tmp / "snap")
        self.assertNotIn(name, [item["path"] for item in inventory["files"]])
    return test


for _name in SECRET_FILES:
    label = "".join(ch if ch.isalnum() else "_" for ch in _name).strip("_")
    setattr(SecretFileExclusion, ("test_control_" if _name in CONTROL_SECRET_FILES else "test_r3_") + label + "_excluded", _secret_file_test(_name))


class LogRedaction(Base):
    """R4: redaction of check output. Secrets exist only in the child environment."""

    def run_check(self, script, extra_env, name="check", argv_tail=()):
        source = self.source_dir({"t.py": script})
        checks = self.tmp / "checks.json"
        checks.write_text(json.dumps([{"name": name, "argv": [sys.executable, "t.py", *argv_tail], "timeout": 60}]), encoding="utf-8")
        result = self.cli("scan", str(source), "--output", str(self.tmp / "run"), "--checks", str(checks), env=extra_env)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        return (self.tmp / "run" / "logs" / "check-1.log").read_text(encoding="utf-8")

    def test_control_named_secret_in_output_is_redacted(self):
        log = self.run_check("import os\nprint('value', os.environ['HS_FAKE_API_KEY'])\n", {"HS_FAKE_API_KEY": FAKE_SECRET})
        self.assertNotIn(FAKE_SECRET, log)

    def test_r4_database_url_password_is_redacted(self):
        log = self.run_check("import os\nprint(os.environ['DATABASE_URL'])\n", {"DATABASE_URL": "postgres://app:%s@db.invalid/app" % FAKE_SECRET})
        self.assertNotIn(FAKE_SECRET, log)

    def test_r4_private_key_variable_is_redacted(self):
        log = self.run_check("import os\nprint(os.environ['HS_FAKE_PRIVATE_KEY'])\n", {"HS_FAKE_PRIVATE_KEY": FAKE_SECRET})
        self.assertNotIn(FAKE_SECRET, log)

    def test_r4_short_common_value_does_not_corrupt_log(self):
        log = self.run_check("print('feature enabled: true; items: 1234')\n", {"HS_FAKE_FLAG_TOKEN": "true", "HS_FAKE_PASSWORD": "1234"})
        self.assertIn("feature enabled: true; items: 1234", log)

    def test_r4_secret_straddling_the_log_limit_is_not_partly_written(self):
        script = "import os, sys\nsys.stdout.write('A' * (1024 * 1024 - 12) + os.environ['HS_FAKE_API_KEY'])\n"
        log = self.run_check(script, {"HS_FAKE_API_KEY": FAKE_SECRET})
        self.assertNotIn(FAKE_SECRET[:10], log)

    def test_r4_check_name_is_redacted_in_saved_artifacts(self):
        self.run_check("print('ok')\n", {"HS_FAKE_API_KEY": FAKE_SECRET}, name="deploy with " + FAKE_SECRET)
        saved = (self.tmp / "run" / "checks.json").read_text(encoding="utf-8") + (self.tmp / "run" / "report.md").read_text(encoding="utf-8")
        self.assertNotIn(FAKE_SECRET, saved)

    def test_control_secret_in_argv_is_redacted_in_checks_json(self):
        self.run_check("print('ok')\n", {"HS_FAKE_API_KEY": FAKE_SECRET}, argv_tail=("--key", FAKE_SECRET))
        self.assertNotIn(FAKE_SECRET, (self.tmp / "run" / "checks.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------- F. non-ASCII paths, cp1252 stdout
class NonAsciiPaths(Base):
    """R1: a successful scan must exit 0 whatever the console encoding."""

    def scan(self, output_name, encoding):
        source = self.source_dir({"main.py": "x = 1\n"})
        return self.cli("scan", str(source), "--output", str(self.tmp / output_name), env={"PYTHONIOENCODING": encoding})

    def test_control_ascii_output_path_cp1252(self):
        self.assertEqual(self.scan("run-ascii", "cp1252").returncode, 0)

    def test_control_hebrew_output_path_utf8_stdout(self):
        self.assertEqual(self.scan("ריצה-run", "utf-8").returncode, 0)

    def test_r1_hebrew_output_path_cp1252_stdout(self):
        result = self.scan("ריצה-run", "cp1252")
        status = json.loads((self.tmp / "ריצה-run" / "run.json").read_text(encoding="utf-8"))["status"]
        self.assertEqual((result.returncode, status), (0, "completed"), result.stderr.decode("cp1252", "replace"))

    def test_r1_hebrew_source_file_name_cp1252_stdout(self):
        source = self.source_dir({"שלום.py": "import os\ndef f(c):\n    os.system('ls ' + c)\n"})
        result = self.cli("scan", str(source), "--output", str(self.tmp / "run"), env={"PYTHONIOENCODING": "cp1252"})
        self.assertEqual(result.returncode, 0, result.stderr.decode("cp1252", "replace"))


# ---------------------------------------------------------------- G. failed checks and diagnostics
class Diagnostics(Base):
    """R2 / R5: failures must say what failed."""

    def scan_with_checks(self, checks):
        source = self.source_dir({"main.py": "x = 1\n"})
        path = self.tmp / "checks.json"
        path.write_text(json.dumps(checks), encoding="utf-8")
        result = self.cli("scan", str(source), "--output", str(self.tmp / "run"), "--checks", str(path))
        saved = self.tmp / "run" / "checks.json"
        return result, (json.loads(saved.read_text(encoding="utf-8")) if saved.exists() else None)

    def test_control_failing_command_records_exit_code(self):
        _result, checks = self.scan_with_checks([{"name": "fails", "argv": [sys.executable, "-c", "import sys; sys.exit(3)"]}])
        self.assertEqual((checks[0]["status"], checks[0]["exit_code"]), ("failed", 3))

    def test_control_timeout_is_recorded(self):
        _result, checks = self.scan_with_checks([{"name": "slow", "argv": [sys.executable, "-c", "import time; time.sleep(30)"], "timeout": 1}])
        self.assertEqual(checks[0]["status"], "timeout")

    def test_r5_missing_executable_names_the_command(self):
        _result, checks = self.scan_with_checks([{"name": "missing", "argv": ["hs-no-such-command-xyz", "--version"]}])
        self.assertIn("hs-no-such-command-xyz", json.dumps(checks[0].get("error", "")))

    @unittest.skipUnless(os.name == "nt" and shutil.which("npm"), "needs Windows with npm on PATH")
    def test_r5_bare_npm_runs_on_windows(self):
        _result, checks = self.scan_with_checks([{"name": "npm", "argv": ["npm", "--version"], "timeout": 60}])
        self.assertEqual(checks[0]["status"], "passed")

    def test_r2_existing_output_directory_is_explained(self):
        source = self.source_dir({"main.py": "x = 1\n"})
        (self.tmp / "run").mkdir()
        result = self.cli("scan", str(source), "--output", str(self.tmp / "run"))
        self.assertRegex(result.stderr.decode("utf-8", "replace").lower(), "exist")

    def test_r2_output_inside_source_is_explained(self):
        source = self.source_dir({"main.py": "x = 1\n"})
        result = self.cli("scan", str(source), "--output", str(source / "out"))
        self.assertRegex(result.stderr.decode("utf-8", "replace").lower(), "outside|inside|separate")

    def test_r2_missing_source_is_explained(self):
        result = self.cli("scan", str(self.tmp / "nope"), "--output", str(self.tmp / "run"))
        self.assertRegex(result.stderr.decode("utf-8", "replace").lower(), "source|directory|not found|exist")

    def test_r2_malformed_checks_file_is_explained(self):
        result, _checks = self.scan_with_checks({"not": "a list"})
        self.assertRegex(result.stderr.decode("utf-8", "replace").lower(), "check|list")


# ---------------------------------------------------------------- H. coverage gaps
class CoverageGaps(Base):
    """R6 / J1 / P2: anything the analyzers cannot read must leave an explicit gap."""

    def gaps(self, files, **kwargs):
        root = self.tmp / "src"
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text, encoding="utf-8")
        _candidates, gaps, _tasks = hydrascan.analyze(root, [{"path": name} for name in files], **kwargs)
        return gaps

    def test_r6_php_file_leaves_a_gap(self):
        gaps = self.gaps({"app.php": "<?php mysqli_query($c, 'SELECT * FROM t WHERE id=' . $_GET['id']); ?>\n"})
        self.assertTrue([g for g in gaps if g.get("path") == "app.php" or "php" in json.dumps(g).lower()])

    def test_r6_go_file_leaves_a_gap(self):
        gaps = self.gaps({"main.go": "package main\nfunc h() { db.Query(\"SELECT 1 WHERE id=\" + id) }\n"})
        self.assertTrue([g for g in gaps if g.get("path") == "main.go" or ".go" in json.dumps(g).lower()])

    def test_r6_java_file_leaves_a_gap(self):
        gaps = self.gaps({"A.java": "class A { void f(String id) throws Exception { Runtime.getRuntime().exec(id); } }\n"})
        self.assertTrue([g for g in gaps if g.get("path") == "A.java" or "java" in json.dumps(g).lower().replace("javascript", "")])

    def test_control_missing_js_parser_leaves_a_gap_per_file(self):
        empty = self.tmp / "no-parser"
        empty.mkdir()
        gaps = self.gaps({"a.js": "eval(location.hash)\n", "b.ts": "export const x: number = 1;\n"}, js_parser_root=empty)
        self.assertEqual({"a.js", "b.ts"}, {g["path"] for g in gaps if g.get("rule") == "js-ast-unavailable"})

    def test_control_unparseable_js_leaves_a_parse_gap(self):
        gaps = self.gaps({"broken.js": "function ( { \n"})
        self.assertTrue([g for g in gaps if g.get("path") == "broken.js" and g.get("rule") in {"js-parse-error", "js-ast-unavailable"}])

    @unittest.skipUnless(hydrascan.javascript_doctor()["available"], "optional Babel parser unavailable")
    def test_j1_typescript_decorators_parse(self):
        source = "import { exec } from 'child_process';\nfunction Get(p: string): any { return () => {}; }\nexport class C {\n  @Get('ping')\n  ping(host: string) { exec('ping ' + host); }\n}\n"
        gaps = self.gaps({"c.ts": source})
        self.assertEqual([], [g for g in gaps if g.get("rule") in {"js-parse-error", "js-ast-unavailable"}])

    def test_p2_python_parse_gap_has_rule_and_title(self):
        gaps = [g for g in self.gaps({"broken.py": "def broken(:\n    pass\n"}) if g.get("path") == "broken.py"]
        self.assertTrue(gaps)
        self.assertEqual([], [g for g in gaps if "rule" not in g or "title" not in g])

    def test_d6_credential_after_syntax_error_is_still_reported(self):
        candidates, _gaps, _tasks = self.analyze({"broken.py": "def broken(:\n    pass\nAPI_KEY = '%s'\n" % FAKE_SECRET})
        self.assertIn("embedded-credential", {c["rule"] for c in candidates})

    def test_d6_prefixed_secret_names_are_reported(self):
        candidates, _gaps, _tasks = self.analyze({"settings.py": "STRIPE_API_KEY = '%s'\nDB_PASSWORD = '%s'\n" % (FAKE_SECRET, FAKE_SECRET)})
        self.assertEqual({1, 2}, {c["line"] for c in candidates if c["rule"] == "embedded-credential"})


class ControlChallenges(Base):
    def test_containment_needs_an_unchanged_trusted_root(self):
        template = FLASK + "@app.route('/f')\ndef f():\n    base = ROOT\n    target = (base / request.args['name']).resolve()\nREASSIGN    if not target.is_relative_to(base):\n        abort(403)\n    return target.read_text()\n"
        variants = [
            ("Path('/srv/public').resolve()", '', False),
            ("Path(request.args['root']).resolve()", '', True),
            ("Path('/srv/public').resolve()", "    base = Path('/').resolve()\n", True),
            ("Path('/srv/public').resolve()", "    target = (base / request.args['other']).resolve()\n", False),
        ]
        for root, reassignment, expected in variants:
            with self.subTest(root=root, reassignment=reassignment):
                source = template.replace('ROOT', root).replace('REASSIGN', reassignment)
                self.assertEqual('python-path-input' in self.rules({'m.py': source}), expected)

    def test_url_control_must_reject_and_disable_redirects_on_the_exact_url(self):
        source = FLASK + "from urllib.parse import urlparse\nALLOWED = {'api.example.test'}\n@app.route('/x')\ndef f():\n    url = request.args['url']\n    parsed = urlparse(url)\n    if parsed.scheme != 'https' or parsed.hostname not in ALLOWED:\n        abort(400)\n    return requests.get(url, allow_redirects=False)\n"
        variants = [source, source.replace('abort(400)', "print('bad')"),
                    source.replace('allow_redirects=False', 'allow_redirects=True'),
                    source.replace("return requests.get(url", "return requests.get(request.args['other']"),
                    source.replace("return requests.get(url", "url = request.args['other']\n    return requests.get(url"),
                    source.replace("ALLOWED = {'api.example.test'}", "ALLOWED = request.args['allowed']")]
        for index, body in enumerate(variants):
            with self.subTest(index=index):
                self.assertEqual('python-outbound-input' in self.rules({'m.py': body}), index != 0)

    def test_owner_binding_does_not_accept_a_request_fallback_or_shadowed_session(self):
        route = "@app.route('/i/<int:i>')\ndef f(i):\nSETUP    return jsonify(db.execute('SELECT id, amount FROM invoices WHERE id = ? AND user_id = ?', (i, PRINCIPAL)).fetchone())\n"
        for principal, setup, expected in [
            ("session['user_id']", '', False),
            ("session.get('user_id', request.args['owner'])", '', True),
            ("session['user_id']", "    session = request.json\n", True),
        ]:
            with self.subTest(principal=principal, setup=setup):
                body = SQLITE.replace('from flask import Flask,', 'from flask import request, Flask,') + route.replace('SETUP', setup).replace('PRINCIPAL', principal)
                self.assertEqual(any('object-authorization' in rule for rule in self.rules({'m.py': body})), expected)

    def test_a_supplied_decorator_keeps_object_policy_open(self):
        body = SQLITE + "def access(view):\n    def wrapped(*a, **k):\n        if session.get('role') != 'admin':\n            abort(403)\n        return view(*a, **k)\n    return wrapped\n@app.route('/i/<int:i>')\n@access\ndef f(i):\n    return jsonify(db.execute('SELECT id, amount FROM invoices WHERE id = ?', (i,)).fetchone())\n"
        _candidates, _gaps, tasks = self.analyze({'m.py': body})
        policy = [t for t in tasks if t['rule'] == 'python-project-object-policy']
        self.assertTrue(policy)
        self.assertTrue(policy[0]['trace'])
        self.assertEqual(policy[0]['family'], 'Authorization and tenant isolation')

    def test_a_noop_decorator_does_not_hide_an_unowned_record(self):
        body = SQLITE + "def access(view):\n    return view\n@app.route('/i/<int:i>')\n@access\ndef f(i):\n    return jsonify(db.execute('SELECT id, amount FROM invoices WHERE id = ?', (i,)).fetchone())\n"
        self.assertTrue(any('object-authorization' in rule for rule in self.rules({'m.py': body})))

    def test_template_escaping_is_not_a_template_source_control(self):
        source = FLASK + "from markupsafe import escape\n@app.route('/t')\ndef f():\n    return render_template_string(escape(request.args['template']))\n"
        self.assertIn('python-template-input', self.rules({'m.py': source}))


class RunnerChallenges(Base):
    run_check = LogRedaction.run_check

    def test_hardlinked_sources_are_excluded(self):
        source = self.source_dir({'original.py': 'x = 1\n'})
        try:
            os.link(source / 'original.py', source / 'linked.py')
        except OSError:
            self.skipTest('hard links unavailable')
        inventory = hydrascan.snapshot(source, self.tmp / 'snap')
        self.assertEqual(inventory['files'], [])
        self.assertTrue(all(item['reason'] == 'hard-linked file' for item in inventory['excluded']))

    @unittest.skipUnless(os.name == 'nt', 'Windows batch execution boundary')
    def test_batch_arguments_cannot_become_shell_operators(self):
        source = self.source_dir({'echo.cmd': '@echo off\necho %1\n'})
        checks = self.tmp / 'checks.json'
        checks.write_text(json.dumps([{'name': 'literal batch argument', 'argv': [str(source / 'echo.cmd'), 'ok & echo injected']}]), encoding='utf-8')
        result = self.cli('scan', str(source), '--output', str(self.tmp / 'run'), '--checks', str(checks))
        self.assertEqual(result.returncode, 0)
        outcome = json.loads((self.tmp / 'run/checks.json').read_text(encoding='utf-8'))[0]
        self.assertEqual(outcome['status'], 'error')
        self.assertIn('Batch check arguments', outcome['error'])
        self.assertNotIn('injected', (self.tmp / 'run/logs/check-1.log').read_text(encoding='utf-8'))
    def test_earlier_redactions_cannot_expose_a_partial_secret_at_capture_end(self):
        script = "import os, sys\ns = os.environ['HS_FAKE_API_KEY']\nsys.stdout.write((s + '\\n') * 10000 + 'A' * (1024 * 1024 + 4096 - 10000 * (len(s) + 1) - 10) + s)\n"
        log = self.run_check(script, {'HS_FAKE_API_KEY': FAKE_SECRET})
        self.assertNotIn(FAKE_SECRET[:10], log)
        self.assertLessEqual(len(log.encode('utf-8')), hydrascan.MAX_LOG_BYTES)

    def test_literal_credential_flags_are_hidden_in_check_metadata(self):
        value = 'FAKE-ONLY-IN-ARGV-0123456789'
        self.run_check("print('ok')\n", {}, argv_tail=('--password', value, '--api-key=' + value))
        self.assertNotIn(value, (self.tmp / 'run/checks.json').read_text(encoding='utf-8'))

    def test_database_password_and_encoded_form_are_redacted(self):
        environment = {'DATABASE_URL': 'postgres://app:FAKE%2FENCODED%2FPASSWORD@db.invalid/app'}
        log = self.run_check("print('FAKE/ENCODED/PASSWORD FAKE%2FENCODED%2FPASSWORD')\n", environment)
        self.assertNotIn('FAKE/ENCODED/PASSWORD', log)
        self.assertNotIn('FAKE%2FENCODED%2FPASSWORD', log)


if __name__ == "__main__":
    unittest.main(verbosity=2)
