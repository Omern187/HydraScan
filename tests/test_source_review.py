"""New source cases, including controls, aliases and guard placement.

These test candidate triage, not exploitation or whole-application security.
"""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'skills/hydrascan/scripts/hydrascan_source.py'
spec = importlib.util.spec_from_file_location('source_review_tests', PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SourceReviewTests(unittest.TestCase):
    def rules(self, source):
        return {item['rule'] for item in module.inspect_python(source)[0]}

    def js_rules(self, source, html=False):
        return {item['rule'] for item in module.inspect_javascript(source, html)}

    def test_query_flow_and_bound_control(self):
        for build in ['sql = f"SELECT * FROM items WHERE label = {value}"',
                      'sql = "SELECT * FROM items WHERE label = " + value',
                      'sql = "SELECT * FROM items WHERE label = %s" % value',
                      'template = "SELECT * FROM items WHERE label = {}"\n    sql = template.format(value)']:
            source = 'def search(db, value):\n    ' + build + '\n    return db.execute(sql)\n'
            self.assertIn('python-sql-composition', self.rules(source))
        self.assertNotIn('python-sql-composition', self.rules('def search(db, value):\n    return db.execute("SELECT * FROM items WHERE label = ?", (value,))\n'))

    def test_static_query_not_promoted_by_other_functions(self):
        source = '''def compose(db, value):
    sql = "SELECT * FROM items WHERE label = " + value
    return db.execute(sql)
def fixed(db):
    sql = "SELECT * FROM items"
    return db.execute(sql)
'''
        signals, _ = module.inspect_python(source)
        self.assertEqual([x['line'] for x in signals if x['rule'] == 'python-sql-composition'], [3])

    def test_local_alias_and_shadowed_name(self):
        source = '''def compute(value):
    render = eval
    alias = render
    return alias(value)
def shadow(eval, value):
    return eval(value)
def overwrite(value):
    render = eval
    render = str
    return render(value)
'''
        signals, _ = module.inspect_python(source)
        self.assertEqual([x['line'] for x in signals if x['rule'] == 'python-dynamic-code'], [4])

    def test_archive_receiver_and_explicit_filter(self):
        source = '''import tarfile as archives
def import_bundle(data, destination):
    with archives.open(fileobj=data) as bundle:
        bundle.extractall(destination, filter="fully_trusted")
def import_package(data, destination):
    with archives.open(fileobj=data) as package:
        package.extractall(destination, filter="data")
'''
        signals, _ = module.inspect_python(source)
        self.assertEqual([x['line'] for x in signals if x['rule'] == 'python-archive-extraction'], [4])

    def test_file_input_and_dominating_containment_guard(self):
        source = '''def read(root, requested):
    path = (root / requested).resolve()
    if root not in path.parents:
        raise ValueError("outside root")
    return path.read_text()
'''
        self.assertNotIn('python-path-input', self.rules(source))
        self.assertIn('python-path-input', self.rules(source.replace('if root not', 'if wrong_root not')))
        self.assertIn('python-path-input', self.rules(source.replace('return path.read_text()', 'path = root / requested\n    return path.read_text()')))
        self.assertIn('python-path-input', self.rules(source.replace('.resolve()', '')))
        self.assertNotIn('python-path-input', self.rules('def setup(root):\n    return (root / "readme.txt").write_text("fixture")\n'))

    def test_authentication_context_creates_a_question_not_a_finding(self):
        source = '''def records(request, db, identifier):
    user = request.user
    return db.execute("SELECT * FROM records WHERE id = ?", (identifier,))
def owned(request, db, identifier):
    user = request.user
    return db.execute("SELECT * FROM records WHERE id = ? AND owner = ?", (identifier, user))
'''
        signals, tasks = module.inspect_python(source)
        self.assertEqual(signals, [])
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]['line'], 3)
        self.assertIn('middleware', tasks[0]['question'])

    def test_outbound_alias_and_literal_control(self):
        source = '''from urllib.request import urlopen as load
def fetch(target):
    return load(target)
def known():
    return load("https://fixture.invalid/public")
'''
        signals, _ = module.inspect_python(source)
        self.assertEqual([x['line'] for x in signals if x['rule'] == 'python-outbound-input'], [3])

    def test_js_comments_and_plain_literals_are_not_executed(self):
        source = '''// eval(user)
/* child_process.exec(user) */
const explanation = "eval(input)";
element.innerHTML = "<strong>constant</strong>";
element.textContent = value;
'''
        self.assertEqual(self.js_rules(source), set())
        self.assertIn('html-rendering', self.js_rules('element.innerHTML = "<b>" + value;'))

    def test_script_embedded_in_response_string(self):
        source = '''reply('<div id="view"></div><script>view.innerHTML = userValue;</script>');'''
        signals = module.inspect_javascript(source)
        self.assertEqual([x['rule'] for x in signals], ['html-rendering'])
        self.assertEqual(signals[0]['line'], 1)
        self.assertEqual(self.js_rules('<script>view.innerHTML = "constant";</script>', html=True), set())

    def test_fetch_requires_guard_and_redirect_control_before_call(self):
        safe = '''const target = new URL(input);
if (target.origin !== allowed) return reply(403);
fetch(target, {redirect: 'error'});
'''
        self.assertNotIn('js-outbound-input', self.js_rules(safe))
        self.assertIn('js-outbound-input', self.js_rules(safe.replace("redirect: 'error'", "redirect: 'follow'")))
        self.assertIn('js-outbound-input', self.js_rules(safe.replace("fetch(target", "target = new URL(other);\nfetch(target")))
        self.assertIn('js-outbound-input', self.js_rules('fetch(target);\nif (target.origin !== allowed) return reply(403);'))
        self.assertIn('js-outbound-input', self.js_rules("if (a) {" + safe + "}\nif (b) {fetch(target, {redirect: 'error'});}"))
        self.assertNotIn('js-outbound-input', self.js_rules("fetch('https://fixture.invalid/public');"))


if __name__ == '__main__':
    unittest.main()
