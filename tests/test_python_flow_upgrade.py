"""Inert AST fixtures: these application snippets are never executed."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hydrascan_python_flow_upgrade', ROOT / 'skills/hydrascan/scripts/hydrascan_python_flow.py')
engine = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = engine
spec.loader.exec_module(engine)


class PythonFlowUpgradeTests(unittest.TestCase):
    def inspect(self, body, imports='import subprocess\nfrom flask import request\n'):
        controls = []
        source = imports + "@app.get('/run')\ndef run():\n" + body
        signals, gaps, tasks = engine.inspect_project({'app.py': source}, controls_out=controls)
        return signals, gaps, tasks, controls

    def test_asyncio_shell_alias_has_exact_command_trace(self):
        signals, _, _, _ = self.inspect("    host = request.args['host']\n    return launch('ping ' + host)\n", 'from asyncio import create_subprocess_shell as launch\nfrom flask import request\n')
        found = next(s for s in signals if s['rule'] == 'python-project-interpreter-input')
        self.assertEqual(found['line'], 6)
        self.assertTrue(any(t['line'] == 5 for t in found['trace']))

    def test_awaited_request_parameter_shell(self):
        source = "import asyncio\n@app.get('/run')\nasync def run(request):\n    await asyncio.create_subprocess_shell('echo ' + request.query_params['value'])\n"
        signals, _, _ = engine.inspect_project({'app.py': source})
        self.assertEqual([(s['rule'], s['line']) for s in signals], [('python-project-interpreter-input', 4)])

    def test_shell_argv_command_flag_and_aliases(self):
        for program, options in [('sh', "'-c'"), ('/bin/bash', "'-lc'"), ('dash', "'-e', '-c'")]:
            for process in ['subprocess.run', 'subprocess.check_output', 'subprocess.Popen']:
                with self.subTest(program=program, process=process):
                    signals, _, tasks, _ = self.inspect(f"    {process}(['{program}', {options}, 'echo ' + request.args['value']], shell=False)\n")
                    self.assertTrue(any(s['rule'] == 'python-project-interpreter-input' for s in signals))
                    self.assertFalse(any(t['rule'] == 'python-project-interpreter-options' for t in tasks))

    def test_asyncio_exec_can_explicitly_launch_shell(self):
        signals, _, _, _ = self.inspect("    return asyncio.create_subprocess_exec('/bin/sh', '-c', request.args['script'])\n", 'import asyncio\nfrom flask import request\n')
        self.assertTrue(any(s['rule'] == 'python-project-interpreter-input' for s in signals))

    def test_argv_data_and_unknown_executable_stay_review_tasks(self):
        for expression in ["subprocess.run(['echo', request.args['value']])",
                           "subprocess.run(['git', 'clone', request.args['url']])",
                           "subprocess.run(['sh', '-c', 'printf %s \"$1\"', 'name', request.args['value']])",
                           "subprocess.run(['sh', '--', '-c', request.args['value']])",
                           "subprocess.run(['sh', '-c', request.args['value']], executable='echo')",
                           "subprocess.run(['sh', '-c', request.args['value']], executable=request.args['exe'])"]:
            with self.subTest(expression=expression):
                signals, _, tasks, _ = self.inspect('    ' + expression + '\n')
                self.assertFalse(any(s['rule'] == 'python-project-interpreter-input' for s in signals))
                self.assertTrue(any(t['rule'] == 'python-project-interpreter-options' for t in tasks))

    def test_keyword_process_args_and_shell_true(self):
        for expression in ["subprocess.run(args=['sh', '-c', request.args['script']])",
                           "subprocess.run(args=request.args['script'], shell=True)"]:
            with self.subTest(expression=expression):
                signals, _, _, _ = self.inspect('    ' + expression + '\n')
                self.assertTrue(any(s['rule'] == 'python-project-interpreter-input' for s in signals))

    def test_shlex_quote_is_not_a_global_control(self):
        for expression in ["os.system('echo ' + shlex.quote(request.args['value']))",
                           "os.system('echo \"' + shlex.quote(request.args['value']) + '\"')"]:
            with self.subTest(expression=expression):
                signals, _, _, controls = self.inspect('    ' + expression + '\n', 'import os\nimport shlex\nfrom flask import request\n')
                self.assertTrue(any(s['rule'] == 'python-project-interpreter-input' for s in signals))
                self.assertFalse(any('python-shell' in c['rules'] for c in controls))

    def test_integer_sql_control_is_at_the_exact_sink(self):
        for conversion, imports in [('int', ''), ('builtins.int', 'import builtins\n'), ('convert', 'from builtins import int as convert\n')]:
            with self.subTest(conversion=conversion):
                signals, gaps, _, controls = self.inspect(f"    count = {conversion}(request.args['count'])\n    db.execute(f'SELECT id FROM items LIMIT {{count}}')\n", imports + 'from flask import request\n')
                self.assertEqual(signals, [])
                self.assertEqual(gaps, [])
                self.assertEqual([(c['line'], c['column'], c['rules']) for c in controls], [(6 if imports else 5, 5, ['python-sql-composition'])])

    def test_numeric_conversion_does_not_trust_other_interpreter_inputs(self):
        signals, _, _, _ = self.inspect("    count = int(request.args['count'])\n    os.system(f'echo {count}')\n", 'import os\nfrom flask import request\n')
        self.assertTrue(any(s['rule'] == 'python-project-interpreter-input' for s in signals))

    def test_numeric_conversion_keeps_object_selection_provenance(self):
        body = "    db.execute('CREATE TABLE items (id INTEGER, user_id INTEGER)')\n    row = db.execute('SELECT * FROM items WHERE id = ?', (int(request.args['id']),)).fetchone()\n    return row\n"
        signals, _, _, _ = self.inspect(body)
        self.assertTrue(any(s['rule'] == 'python-project-object-authorization' for s in signals))

    def test_shadowed_conversion_and_mixed_text_do_not_control_sql(self):
        for body in ["    int = lambda x: x\n    count = int(request.args['count'])\n    db.execute(f'SELECT id LIMIT {count}')\n",
                     "    from external import int\n    count = int(request.args['count'])\n    db.execute(f'SELECT id LIMIT {count}')\n",
                     "    class int:\n        pass\n    count = int(request.args['count'])\n    db.execute(f'SELECT id LIMIT {count}')\n",
                     "    count = float(request.args['count'])\n    db.execute(f'SELECT id LIMIT {count}')\n",
                     "    count = int(request.args['count'])\n    db.execute(f'SELECT {request.args[\"column\"]} LIMIT {count}')\n",
                     "    count = int(request.args['count'])\n    db.execute(f'SELECT 1 -{count}')\n",
                     "    count = int(request.args['count'])\n    db.execute(f'SELECT id LIMIT {count:{request.args[\"format\"]}}')\n"]:
            with self.subTest(body=body):
                signals, _, _, controls = self.inspect(body)
                self.assertTrue(any(s['rule'] == 'python-project-sql-injection' for s in signals))
                self.assertFalse(any('python-sql-composition' in c['rules'] for c in controls))

    def test_supplied_builtin_rebinding_withholds_numeric_control(self):
        for mutation in ["    builtins.int = replacement\n", "    setattr(builtins, 'int', replacement)\n"]:
            with self.subTest(mutation=mutation):
                signals, gaps, _, controls = self.inspect(mutation + "    count = builtins.int(request.args['count'])\n    db.execute(f'SELECT id LIMIT {count}')\n", 'import builtins\nfrom flask import request\n')
                self.assertTrue(any(g['rule'] == 'python-project-builtins-gap' for g in gaps))
                self.assertEqual(controls, [])
                self.assertTrue(any(s['rule'] == 'python-project-sql-injection' for s in signals))

    def test_other_request_handler_builtin_mutation_cannot_hide_sql_candidate(self):
        source = "import builtins as b\nfrom flask import request\n@app.get('/query')\ndef query():\n    count = b.int(request.args['count'])\n    db.execute(f'SELECT id LIMIT {count}')\n@app.post('/replace')\ndef replace():\n    b.int = replacement\n"
        controls = []
        signals, gaps, _ = engine.inspect_project({'app.py':source}, controls_out=controls)
        self.assertTrue(any(s['rule'] == 'python-project-sql-injection' and s['line'] == 6 for s in signals))
        self.assertTrue(any(g['rule'] == 'python-project-builtins-gap' for g in gaps))
        self.assertEqual(controls, [])

    def test_format_spec_request_origin_is_preserved(self):
        signals, _, _, _ = self.inspect("    db.execute(f'SELECT id LIMIT {42:{request.args[\"format\"]}}')\n")
        self.assertTrue(any(s['rule'] == 'python-project-sql-injection' for s in signals))

    def test_local_builtin_alias_and_cross_file_numeric_return(self):
        signals, gaps, _, controls = self.inspect("    from builtins import int as number\n    count = number(request.args['count'])\n    db.execute(f'SELECT id LIMIT {count}')\n")
        self.assertEqual(signals, [])
        self.assertEqual(gaps, [])
        self.assertTrue(any(c['rules'] == ['python-sql-composition'] for c in controls))
        controls = []
        files = {'app.py': "from flask import request\nfrom helpers import number\n@app.get('/x')\ndef x():\n    count = number(request.args['count'])\n    db.execute(f'SELECT id LIMIT {count}')\n",
                 'helpers.py': "import builtins\ndef number(value):\n    return builtins.int(value)\n"}
        self.assertEqual(engine.inspect_project(files, controls_out=controls)[0], [])
        self.assertTrue(any(c['path'] == 'app.py' and c['line'] == 6 and c['rules'] == ['python-sql-composition'] for c in controls))

    def test_shared_numeric_query_sink_requires_all_call_contexts(self):
        files = {'app.py': "from flask import request\nfrom helpers import query\n@app.get('/x')\ndef x():\n    query(int(request.args['count']))\n    query(request.args['count'])\n",
                 'helpers.py': "def query(value):\n    db.execute(f'SELECT id LIMIT {value}')\n"}
        controls = []
        signals, _, _ = engine.inspect_project(files, controls_out=controls)
        self.assertTrue(any(s['rule'] == 'python-project-sql-injection' and s['path'] == 'helpers.py' for s in signals))
        self.assertFalse(any(c['path'] == 'helpers.py' for c in controls))

    def test_runner_suppresses_only_exact_numeric_sink(self):
        sys.path.insert(0, str(ROOT / 'skills/hydrascan/scripts'))
        import hydrascan
        source = "from flask import request\ndef number(value):\n    return int(value)\n@app.get('/x')\ndef x():\n    count = number(request.args['count'])\n    db.execute(f'SELECT id LIMIT {count}'); db.execute(f'SELECT id LIMIT {request.args[\"count\"]}')\n"
        self.assertTrue(any(s['rule'] == 'python-sql-composition' and s['column'] == 5 for s in hydrascan.inspect_python(source)[0]))
        with tempfile.TemporaryDirectory(prefix='hs-flow-upgrade-') as folder:
            root = Path(folder)
            (root / 'app.py').write_text(source, encoding='utf-8')
            signals, _, _ = hydrascan.analyze(root, [{'path': 'app.py'}])
        sql = [s for s in signals if s['family'] == engine.SQL]
        self.assertEqual([(s['rule'], s['line']) for s in sql], [('python-project-sql-injection', 7)])
        self.assertNotEqual(sql[0]['column'], 5)

    def test_declared_request_owner_predicate_selects_a_collection(self):
        body = "    db.execute('CREATE TABLE orders (id INTEGER, user_id INTEGER, total REAL)')\n    rows = db.execute('SELECT total FROM orders WHERE user_id = ?', (request.args['user_id'],)).fetchall()\n    return rows\n"
        signals, _, _, _ = self.inspect(body)
        found = next(s for s in signals if s['rule'] == 'python-project-object-authorization')
        self.assertEqual(found['missing_fields'], ['user_id'])
        self.assertTrue(found['ownership_schema_observed'])
        self.assertFalse(any(s['rule'] == 'python-project-object-authorization' for s in self.inspect(body.replace("request.args['user_id']", "session['user_id']"), 'from flask import request, session\n')[0]))
        self.assertEqual(self.inspect(body.replace('user_id = ?', 'total = ?'))[0], [])


if __name__ == '__main__':
    unittest.main()
