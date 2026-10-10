"""Regression expectations for generic parser behavior. No snippets execute."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'skills/hydrascan/scripts/hydrascan_source.py'
spec = importlib.util.spec_from_file_location('helper_under_review', PATH)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

class ParserRegressionTests(unittest.TestCase):
    def py_rules(self, text):
        return {(x['line'], x['rule']) for x in helper.inspect_python(text)[0]}

    def js_rules(self, text, html=False):
        return {(x['line'], x['rule']) for x in helper.inspect_javascript(text, html)}

    def test_builtin_shadowed_by_function_definition(self):
        self.assertEqual(self.py_rules('def eval(value):\n    return value\neval(input_value)\n'), set())

    def test_lambda_parameter_scope(self):
        self.assertEqual(self.py_rules('handler = lambda eval: eval(value)\n'), set())

    def test_with_assignment_persists_in_same_scope(self):
        self.assertIn((4, 'python-dynamic-code'), self.py_rules('from contextlib import nullcontext\nwith nullcontext():\n    evaluate = eval\nevaluate(value)\n'))

    def test_augmented_assignment_query_flow(self):
        self.assertIn((4, 'python-sql-composition'), self.py_rules('def search(db, value):\n    sql = "SELECT "\n    sql += value\n    return db.execute(sql)\n'))

    def test_definition_time_calls_scanned(self):
        self.assertEqual(self.py_rules('@decorate(eval(data))\ndef route(value=eval(data)):\n    return value\n'), {(1, 'python-dynamic-code'), (2, 'python-dynamic-code')})

    def test_assignment_target_calls_scanned(self):
        self.assertIn((1, 'python-dynamic-code'), self.py_rules('items[eval(key)] = value\n'))

    def test_request_uses_url_not_method_argument(self):
        self.assertIn((3, 'python-outbound-input'), self.py_rules('import requests\ndef load(url):\n    return requests.request("GET", url)\n'))

    def test_format_retains_dynamic_receiver(self):
        self.assertIn((4, 'python-sql-composition'), self.py_rules('def search(db, value):\n    template = "SELECT " + value\n    sql = template.format()\n    return db.execute(sql)\n'))

    def test_auth_decorator_creates_review_question(self):
        signals, tasks = helper.inspect_python('@login_required\ndef records(db, identifier):\n    return db.execute("SELECT * FROM records WHERE id = ?", (identifier,))\n')
        self.assertEqual(signals, [])
        self.assertEqual([(x['line'], x['rule']) for x in tasks], [(3, 'object-ownership-review')])

    def test_literal_prefix_is_not_constant_url(self):
        self.assertIn((1, 'js-outbound-input'), self.js_rules('fetch("https://" + host);'))

    def test_comment_is_not_redirect_configuration(self):
        self.assertIn((2, 'js-outbound-input'), self.js_rules("if (target.origin !== allowed) return reply(403);\nfetch(target, {/*redirect: 'error'*/ redirect: 'follow'});"))

    def test_conditional_guard_does_not_dominate(self):
        self.assertIn((2, 'js-outbound-input'), self.js_rules("if (flag && target.origin !== allowed) return reply(403);\nfetch(target, {redirect: 'error'});"))

    def test_url_mutation_invalidates_guard(self):
        self.assertIn((3, 'js-outbound-input'), self.js_rules("if (target.origin !== allowed) return reply(403);\ntarget.href = other;\nfetch(target, {redirect: 'error'});"))

    def test_html_comments_excluded(self):
        self.assertEqual(self.js_rules('<!-- <script>eval(value)</script> -->', True), set())

    def test_jsx_text_does_not_swallow_following_code(self):
        self.assertIn((2, 'js-dynamic-code'), self.js_rules("const view = <p>Don't show scripts</p>;\neval(value);"))

    def test_multiline_embedded_script_positions(self):
        self.assertEqual(self.js_rules('const page = `\n<div>hi</div>\n<script>\n  eval(value)\n</script>`;'), {(4, 'js-dynamic-code')})

    def test_comment_and_escaped_string_masking(self):
        self.assertEqual(self.js_rules('// eval(value)\nconst example = "text\\\" eval(value)";\n/* fetch(value) */\neval(value);'), {(4, 'js-dynamic-code')})

    def test_class_namespaces_and_relative_imports(self):
        for source in ['class eval:\n    pass\neval(value)\n',
                       'class Service:\n    evaluate = eval\n    def run(self, value):\n        return evaluate(value)\n',
                       'from .os import system\nsystem(value)\n',
                       'from os import system as execute\ndef f():\n    execute: object\n    execute(value)\n']:
            with self.subTest(source=source):
                self.assertEqual(self.py_rules(source), set())

    def test_dynamic_base_and_builtin_open_guard(self):
        self.assertIn((3, 'python-path-input'), self.py_rules('from pathlib import Path\ndef read(requested):\n    return (Path(requested) / "data.txt").read_text()\n'))
        guarded = 'def read(root, requested):\n    path = (root / requested).resolve()\n    if root not in path.parents:\n        raise ValueError("outside root")\n    return open(path).read()\n'
        self.assertEqual(self.py_rules(guarded), set())
        self.assertIn((5, 'python-path-input'), self.py_rules(guarded.replace('if root not', 'if wrong_root not')))

    def test_keyword_query_and_branch_composition(self):
        self.assertIn((2, 'python-sql-composition'), self.py_rules('def search(db, value):\n    db.execute(query="SELECT " + value)\n'))
        self.assertIn((5, 'python-sql-composition'), self.py_rules('def search(db, value, choose):\n    sql = "SELECT fixed"\n    if choose:\n        sql += value\n    db.execute(sql)\n'))

    def test_unicode_and_carriage_return_line_endings(self):
        for ending in ['\r', '\n', '\r\n', '\u2028', '\u2029']:
            with self.subTest(ending=repr(ending)):
                self.assertEqual(self.js_rules('// example' + ending + 'eval(value);'), {(2, 'js-dynamic-code')})

    def test_inert_html_script_contexts(self):
        for source in ['<script type="text/plain">eval(value)</script>',
                       '<script type="application/json">eval(value)</script>',
                       '<template><script>eval(value)</script></template>',
                       '<div data-example="<script>eval(value)</script>">Example</div>']:
            with self.subTest(source=source):
                self.assertEqual(self.js_rules(source, True), set())
        self.assertEqual(self.js_rules('<script type="module">eval(value)</script>', True), {(1, 'js-dynamic-code')})

if __name__ == '__main__':
    unittest.main()
