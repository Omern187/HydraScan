import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'skills/hydrascan/scripts/hydrascan.py'
spec = importlib.util.spec_from_file_location('hydrascan_project_runner', SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ProjectIntegrationTests(unittest.TestCase):
    def analyze(self, sources, **options):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in sources.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding='utf-8')
            options.setdefault('node', 'missing-hydrascan-node')
            return runner.analyze(root, [{'path': name} for name in sources], **options)

    def test_python_source_preserves_javascript_runtime_options(self):
        sources = {
            'config.py': 'password: str = "synthetic_fixture_value_123"\nsettings = {"api_key": "synthetic_setting_value_123"}\n',
            'route.js': 'eval(req.query.code);',
        }
        parser = Path('isolated-parser-runtime')
        for node in (None, 'configured-node', Path('node-runtime')):
            with self.subTest(node=node), patch.object(runner, 'inspect_javascript_project', return_value=([], [], [])) as inspect:
                self.analyze(sources, node=node, js_parser_root=parser)
                inspect.assert_called_once_with({'route.js': sources['route.js']}, node=node, parser_root=parser)

    def test_cross_file_interpreter_candidate_has_source_trace(self):
        candidates, gaps, tasks = self.analyze({
            'route.py': 'from flask import request\nfrom worker import calculate\n@app.get("/calculate")\ndef route():\n    return calculate(request.args.get("expression"))\n',
            'worker.py': 'def calculate(expression):\n    return eval(expression)\n',
        })
        traced = [item for item in candidates if item['rule'] == 'python-project-interpreter-input']
        self.assertTrue(traced)
        self.assertEqual(traced[0]['path'], 'worker.py')
        self.assertTrue(any(location['path'] == 'route.py' for location in traced[0]['trace']))
        self.assertTrue(all(item['proof_state'] == 'candidate' for item in candidates))
        self.assertEqual(len({item['id'] for item in candidates}), len(candidates))
        self.assertEqual(len([item for item in candidates if item['path'] == 'worker.py' and item['line'] == 2]), 1)

    def test_unavailable_javascript_ast_retains_signal_and_coverage_gap(self):
        candidates, gaps, tasks = self.analyze({'route.js': 'app.get("/", (req,res) => { view.innerHTML = req.query.message; });'})
        self.assertTrue(candidates)
        self.assertTrue(any(item.get('rule', '').startswith('js-') for item in gaps))
        self.assertFalse(any(item.get('proof_state') == 'source-confirmed' for item in candidates))

    def test_project_source_is_never_imported(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'must-not-exist'
            source = f'from pathlib import Path\nPath({str(marker)!r}).write_text("executed")\n'
            self.analyze({'target.py': source})
            self.assertFalse(marker.exists())

    def test_unexpanded_registered_callback_cannot_clear_shared_helper(self):
        candidates, gaps, tasks = self.analyze({'app.py': '''from flask import request
def calculate(value):
    return eval(value)
@app.get('/safe')
def safe():
    return calculate('2')
def other_handler():
    return calculate(request.args['expression'])
app.add_url_rule('/other', view_func=other_handler)
'''})
        self.assertTrue(any(item['rule'] in {'python-dynamic-code', 'python-project-interpreter-input'} and item['line'] == 3 for item in candidates))
        self.assertTrue(any(item.get('rule') in {'python-project-callback-gap', 'python-project-unexpanded-caller-gap'} for item in gaps))


class MixedLanguageAstIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = os.environ.get('HYDRASCAN_JS_PARSER_ROOT')
        cls.info = runner.javascript_doctor(parser_root=cls.runtime)
        if not cls.info['available']:
            raise unittest.SkipTest('Optional pinned Babel parser unavailable; runtime option regression still runs')

    def test_mixed_scan_keeps_javascript_ast_and_safe_control(self):
        javascript = '''const express = require('express');
const {exec} = require('node:child_process');
const app = express();
app.get('/run', (req, res) => { exec(req.query.command); res.send('ok'); });
app.get('/hello', (req, res) => { res.send('<b>' + req.query.name + '</b>'); });
app.get('/other', (req, res) => { res.send(`<p>${req.query.message}</p>`); });
app.get('/safe', (req, res) => { res.send('<b>fixed text</b>'); });
'''
        python = '''from flask import request
import subprocess
@app.get('/run')
def run():
    subprocess.run(request.args['command'], shell=True)
    return 'ok'
'''
        for explicit_node in (False, True):
            with self.subTest(explicit_node=explicit_node), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, output = root / 'app', root / 'review'
                source.mkdir()
                (source / 'app.py').write_text(python, encoding='utf-8')
                (source / 'routes.js').write_text(javascript, encoding='utf-8')
                runner.scan(source, output,
                            node=Path(self.info['node']) if explicit_node else None,
                            js_parser_root=Path(self.info['parser_root']))
                candidates = json.loads((output / 'candidates.json').read_text(encoding='utf-8'))
                gaps = json.loads((output / 'analysis-gaps.json').read_text(encoding='utf-8'))
                metadata = json.loads((output / 'run.json').read_text(encoding='utf-8'))
                self.assertTrue(metadata['javascript_backend']['available'])
                self.assertFalse(any(gap.get('rule') == 'js-ast-unavailable' for gap in gaps), gaps)
                signals = [item for item in candidates if item['path'] == 'routes.js']
                self.assertEqual([(item['line'], item['rule']) for item in signals],
                                 [(4, 'js-shell'), (5, 'js-response-rendering'), (6, 'js-response-rendering')])
                self.assertTrue(all(item['backend'] == 'babel-ast' for item in signals))
                self.assertTrue(any(item['path'] == 'app.py' for item in candidates))
                self.assertTrue(all(item['proof_state'] == 'candidate' for item in candidates))


if __name__ == '__main__':
    unittest.main()
