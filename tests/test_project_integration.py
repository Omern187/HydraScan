import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'skills/hydrascan/scripts/hydrascan.py'
spec = importlib.util.spec_from_file_location('hydrascan_project_runner', SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ProjectIntegrationTests(unittest.TestCase):
    def analyze(self, sources):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in sources.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding='utf-8')
            return runner.analyze(root, [{'path': name} for name in sources], node='missing-hydrascan-node')

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


if __name__ == '__main__':
    unittest.main()
