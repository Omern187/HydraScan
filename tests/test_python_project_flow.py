"""Project analyzer fixtures are inert strings; analyzed applications never run."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hydrascan_python_flow_tests', ROOT / 'skills/hydrascan/scripts/hydrascan_python_flow.py')
engine = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = engine
spec.loader.exec_module(engine)

SQL_PREFIX = '''from flask import request, abort
db.execute("CREATE TABLE notes (id INTEGER, owner_id INTEGER, tenant_id INTEGER, body TEXT)")
@app.get('/notes')
def note():
    note_id = request.args.get('id')
'''
LOOKUP = "    row = db.execute('SELECT * FROM notes WHERE id = :id', {'id': note_id}).fetchone()\n"
GUARD = "    if row['owner_id'] != current_user.id or row['tenant_id'] != current_user.tenant_id:\n        abort(403)\n"
DJANGO = '''from django.db import models
from flask import request, abort
class Note(models.Model):
    owner_id = models.IntegerField()
    tenant_id = models.IntegerField()
@app.post('/notes')
def note():
    key = request.args.get('id')
'''


class PythonProjectFlowTests(unittest.TestCase):
    def analyze(self, source, **kwargs):
        files = {'app.py': source} if isinstance(source, str) else source
        return engine.inspect_project(files, **kwargs)

    def auth(self, source):
        return [s for s in self.analyze(source)[0] if s['rule'] == 'python-project-object-authorization']

    def test_cross_file_input_and_evidence(self):
        files = {'app.py': "from flask import request\nfrom util import compute as run\n@app.get('/x')\ndef x():\n    return run(request.args.get('x'))\n",
                 'util.py': 'def compute(value):\n    return eval(value)\n'}
        signals, _, _ = self.analyze(files)
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0]['path'], 'util.py')
        self.assertEqual({t['path'] for t in signals[0]['trace']}, {'app.py', 'util.py'})
        self.assertEqual(signals[0]['proof_state'], 'candidate')

    def test_relative_package_import(self):
        files = {'pkg/app.py': "from flask import request\nfrom .util import compute\n@app.get('/x')\ndef x():\n    return compute(request.args.get('x'))\n",
                 'pkg/util.py': 'def compute(value):\n    return eval(value)\n'}
        self.assertTrue(self.analyze(files)[0])

    def test_helper_literal_control_and_unsafe_caller_override(self):
        base = {'app.py': "from flask import request\nfrom util import compute\n@app.get('/x')\ndef x():\n    return compute('2 + 2')\n",
                'util.py': 'def compute(value):\n    return eval(value)\n'}
        controls = []
        self.assertEqual(self.analyze(base, controls_out=controls)[0], [])
        self.assertTrue(any(c['path'] == 'util.py' and c['rules'] == ['python-dynamic-code'] for c in controls))
        base['app.py'] += "@app.get('/y')\ndef y():\n    return compute(request.args.get('x'))\n"
        controls = []
        self.assertTrue(self.analyze(base, controls_out=controls)[0])
        self.assertFalse(any(c['path'] == 'util.py' for c in controls))

    def test_shadowed_evaluator_is_not_builtin(self):
        text = "from flask import request\ndef eval(value):\n    return value\n@app.get('/x')\ndef x():\n    return eval(request.args.get('x'))\n"
        self.assertEqual(self.analyze(text)[0], [])

    def test_recursive_cycle_is_gap(self):
        text = "from flask import request\ndef helper(x):\n    return helper(x)\n@app.get('/x')\ndef x():\n    return helper(request.args.get('x'))\n"
        self.assertTrue(any(g['rule'] == 'python-project-cycle-gap' for g in self.analyze(text)[1]))

    def test_keyword_default_and_constant_argument(self):
        text = "from flask import request\ndef helper(value='2 + 2'):\n    return eval(value)\n@app.get('/x')\ndef x():\n    return helper(value=request.args.get('x'))\n"
        self.assertTrue(self.analyze(text)[0])
        self.assertEqual(self.analyze(text.replace("helper(value=request.args.get('x'))", 'helper()'))[0], [])

    def test_expanded_arguments_are_explicit_gap(self):
        text = "from flask import request\ndef helper(value):\n    return eval(value)\n@app.get('/x')\ndef x():\n    return helper(**request.json)\n"
        self.assertTrue(any(g['rule'] == 'python-project-argument-gap' for g in self.analyze(text)[1]))

    def test_named_sql_read_missing_owner_and_tenant(self):
        found = self.auth(SQL_PREFIX + LOOKUP + '    return dict(row)\n')
        self.assertEqual(found[0]['missing_fields'], ['owner_id', 'tenant_id'])
        self.assertEqual(found[0]['boundary_kind'], 'disclosure')

    def test_exact_guards_and_control_location(self):
        controls = []
        self.assertEqual(self.analyze(SQL_PREFIX + LOOKUP + GUARD + '    return dict(row)\n', controls_out=controls)[0], [])
        self.assertTrue(any(c['line'] == 6 and c['rules'] == ['python-object-authorization'] for c in controls))

    def test_owner_alone_does_not_prove_tenant(self):
        found = self.auth(SQL_PREFIX + LOOKUP + "    if row['owner_id'] != current_user.id:\n        abort(403)\n    return row\n")
        self.assertEqual(found[0]['missing_fields'], ['tenant_id'])

    def test_mapping_guard_and_untrusted_default(self):
        text = SQL_PREFIX + LOOKUP + GUARD.replace("row['owner_id']", "row.get('owner_id')").replace("row['tenant_id']", "row.get('tenant_id')") + '    return row\n'
        self.assertEqual(self.auth(text), [])
        self.assertTrue(self.auth(text.replace("row.get('owner_id')", "row.get('owner_id', request.args.get('owner'))")))

    def test_later_guard_does_not_cover_earlier_send(self):
        self.assertTrue(self.auth(SQL_PREFIX + LOOKUP + '    self.send_json(row)\n' + GUARD + '    return None\n'))

    def test_unknown_mutation_cannot_preserve_guard(self):
        self.assertTrue(self.auth(SQL_PREFIX + LOOKUP + GUARD + '    unknown_mutator(row)\n    return row\n'))

    def test_ownership_assignment_invalidates_guard(self):
        self.assertTrue(self.auth(SQL_PREFIX + LOOKUP + GUARD + "    row['owner_id'] = request.args.get('owner')\n    return row\n"))

    def test_assert_and_or_positive_guards_not_trusted(self):
        for guard in ["    assert row['owner_id'] == current_user.id\n", "    if row['owner_id'] == current_user.id or row['tenant_id'] == current_user.tenant_id:\n        return row\n"]:
            with self.subTest(guard=guard):
                self.assertTrue(self.auth(SQL_PREFIX + LOOKUP + guard + '    return row\n'))

    def test_unknown_schema_requires_policy_task(self):
        signals, _, tasks = self.analyze(SQL_PREFIX.replace(SQL_PREFIX.splitlines()[1] + '\n', '') + LOOKUP + '    return row\n')
        self.assertTrue(signals)
        self.assertTrue(any(t['rule'] == 'python-project-authorization-policy' for t in tasks))

    def test_named_parameters_scoped_query(self):
        lookup = "    row = db.execute('SELECT * FROM notes WHERE id = :id AND owner_id = :owner AND tenant_id = :tenant', {'id': note_id, 'owner': current_user.id, 'tenant': current_user.tenant_id}).fetchone()\n"
        self.assertEqual(self.auth(SQL_PREFIX + lookup + '    return row\n'), [])

    def test_percent_named_parameters_scoped_query(self):
        lookup = "    row = db.execute('SELECT * FROM notes WHERE id = %(id)s AND owner_id = %(owner)s AND tenant_id = %(tenant)s', {'id': note_id, 'owner': current_user.id, 'tenant': current_user.tenant_id}).fetchone()\n"
        self.assertEqual(self.auth(SQL_PREFIX + lookup + '    return row\n'), [])

    def test_join_bounds_are_alias_specific(self):
        lookup = "    row = db.execute('SELECT n.* FROM notes AS n JOIN other AS o ON o.id = n.id WHERE n.id = :id AND o.owner_id = :owner AND o.tenant_id = :tenant', {'id': note_id, 'owner': current_user.id, 'tenant': current_user.tenant_id}).fetchone()\n"
        self.assertTrue(self.auth(SQL_PREFIX + lookup + '    return row\n'))
        self.assertEqual(self.auth(SQL_PREFIX + lookup.replace('o.owner_id', 'n.owner_id').replace('o.tenant_id', 'n.tenant_id') + '    return row\n'), [])

    def test_sql_write_and_delete_before_return(self):
        for operation in ["UPDATE notes SET body = :body WHERE id = :id", "DELETE FROM notes WHERE id = :id"]:
            found = self.auth(SQL_PREFIX + f"    db.execute({operation!r}, {{'id': note_id, 'body': 'new'}})\n    return 'ok'\n")
            self.assertTrue(found)
            self.assertIn(found[0]['boundary_kind'], {'update', 'delete'})

    def test_update_positional_set_parameter_does_not_shift_identity(self):
        text = SQL_PREFIX + "    db.execute('UPDATE notes SET body = ? WHERE id = ? AND owner_id = ? AND tenant_id = ?', ('new', note_id, current_user.id, current_user.tenant_id))\n    return 'ok'\n"
        self.assertEqual(self.auth(text), [])

    def test_composed_sql_cross_function(self):
        files = {'app.py': "from flask import request\nfrom util import load\n@app.get('/x')\ndef x():\n    return load(request.args.get('id'))\n", 'util.py': "import sqlite3\ndb = sqlite3.connect(':memory:')\ndef load(key):\n    return db.execute('SELECT * FROM notes WHERE id = ' + key)\n"}
        self.assertTrue(any(s['rule'] == 'python-project-sql-injection' for s in self.analyze(files)[0]))

    def test_complex_sql_predicate_is_gap_not_safe(self):
        lookup = "    row = db.execute('SELECT * FROM notes WHERE id = :id AND (owner_id = :owner OR tenant_id = :tenant)', {'id': note_id, 'owner': current_user.id, 'tenant': current_user.tenant_id}).fetchone()\n"
        signals, gaps, _ = self.analyze(SQL_PREFIX + lookup + '    return row\n')
        self.assertTrue(signals)
        self.assertTrue(any(g['rule'] == 'python-project-sql-gap' for g in gaps))

    def test_django_object_write_delete_and_safe_bounds(self):
        for action in ['save', 'delete']:
            text = DJANGO + f"    row = Note.objects.get(pk=key)\n    row.{action}()\n    return 'ok'\n"
            self.assertTrue(self.auth(text))
            safe = text.replace('get(pk=key)', 'get(pk=key, owner_id=current_user.id, tenant_id=current_user.tenant_id)')
            self.assertEqual(self.auth(safe), [])

    def test_django_queryset_update_requires_scoping(self):
        text = DJANGO + "    Note.objects.filter(pk=key).update(body='new')\n    return 'ok'\n"
        self.assertTrue(self.auth(text))
        self.assertEqual(self.auth(text.replace('filter(pk=key)', 'filter(pk=key, owner_id=current_user.id, tenant_id=current_user.tenant_id)')), [])

    def test_sqlalchemy_explicit_model_session_and_filters(self):
        prefix = '''from sqlalchemy.orm import declarative_base, Session
from flask import request
Base = declarative_base()
class Note(Base):
    owner_id = Column(Integer)
session = Session()
@app.get('/notes')
def note():
    key = request.args.get('id')
'''
        text = prefix + '    return session.query(Note).filter_by(id=key).first()\n'
        self.assertTrue(self.auth(text))
        self.assertEqual(self.auth(text.replace('filter_by(id=key)', 'filter_by(id=key, owner_id=current_user.id)')), [])
        self.assertEqual(self.auth(text.replace('filter_by(id=key)', 'filter(Note.id == key, Note.owner_id == current_user.id)')), [])

    def test_admin_route_name_stays_policy_question(self):
        text = "from flask import request, abort\n@app.post('/admin/users')\ndef admin():\n    if not current_user.is_admin:\n        abort(403)\n    return 'ok'\n"
        signals, _, tasks = self.analyze(text)
        self.assertEqual(signals, [])
        self.assertTrue(any(t['rule'] == 'python-project-admin-boundary' for t in tasks))
        task = next(t for t in tasks if t['rule'] == 'python-project-admin-boundary')
        self.assertTrue(task['admin_guard_observed'])
        unguarded = text.replace("    if not current_user.is_admin:\n        abort(403)\n", '')
        task = next(t for t in self.analyze(unguarded)[2] if t['rule'] == 'python-project-admin-boundary')
        self.assertFalse(task['admin_guard_observed'])

    def test_admin_guard_does_not_override_object_policy(self):
        text = SQL_PREFIX + LOOKUP + "    if not current_user.is_admin:\n        abort(403)\n    return row\n"
        self.assertTrue(self.auth(text))
        self.assertTrue(self.auth(text)[0]['admin_guard_observed'])

    def test_cross_file_guard_helper_dominates_only_later_boundary(self):
        files = {'app.py': SQL_PREFIX + LOOKUP + '    guard(row, current_user)\n    return row\n',
                 'policy.py': "from flask import abort\ndef guard(row, user):\n    if row['owner_id'] != user.id or row['tenant_id'] != user.tenant_id:\n        abort(403)\n"}
        files['app.py'] = 'from policy import guard\n' + files['app.py']
        self.assertEqual(self.auth(files), [])
        files['app.py'] = files['app.py'].replace('    guard(row, current_user)\n', '    self.send_json(row)\n    guard(row, current_user)\n')
        self.assertTrue(self.auth(files))

    def test_unknown_guard_helper_does_not_prove_authorization(self):
        text = SQL_PREFIX + LOOKUP + '    verify_policy(row)\n    return row\n'
        self.assertTrue(self.auth(text))

    def test_file_total_bytes_and_ast_budgets_are_explicit(self):
        for limit, value, sources in [('MAX_FILES', 1, {'a.py': 'pass', 'b.py': 'pass'}),
                                      ('MAX_TOTAL_BYTES', 4, {'a.py': 'pass\n'}),
                                      ('MAX_AST_NODES', 2, {'a.py': 'a = [1,2,3]'})]:
            with self.subTest(limit=limit), patch.object(engine, limit, value):
                self.assertTrue(any(g['rule'] == 'python-project-resource-gap' for g in self.analyze(sources)[1]))

    def test_unknown_cursor_helper_keeps_query_candidate_and_provenance(self):
        text = "from flask import request\ndef lookup(cursor, name):\n    cursor.execute('SELECT * FROM notes WHERE body = ' + name)\n@app.get('/x')\ndef x():\n    lookup(db.cursor(), request.args['name'])\n"
        signals, _, tasks = self.analyze(text)
        found = next(s for s in signals if s['rule'] == 'python-project-sql-injection')
        self.assertTrue(found['trace'])
        self.assertEqual(found['line'], 3)
        self.assertTrue(any(t['rule'] == 'python-project-sql-provenance' for t in tasks))

    def test_imported_current_user_and_request_user_are_trusted_exact_principals(self):
        lookup = "    row = db.cursor().execute('SELECT * FROM notes WHERE id=:id AND owner_id=:owner', {'id': note_id, 'owner': PRINCIPAL}).fetchone()\n"
        for principal in ['current_user.id', 'request.user.id']:
            with self.subTest(principal=principal):
                source = "from flask import request\nfrom flask_login import current_user\n@app.get('/notes')\ndef note(note_id):\n" + lookup.replace('PRINCIPAL', principal) + '    return row\n'
                self.assertEqual(self.auth(source), [])
                self.assertTrue(self.auth(source.replace(principal, "request.args['owner']")))

    def test_flask_sqlalchemy_declared_model_mutation_requires_owner_and_tenant(self):
        prefix = "from flask import request, abort\nfrom flask_sqlalchemy import SQLAlchemy\nfrom flask_login import current_user\ndb = SQLAlchemy()\nclass Invoice(db.Model):\n    owner_id = db.Column(db.Integer)\n    tenant_id = db.Column(db.Integer)\n@app.patch('/invoices')\ndef edit(invoice_id):\n    row = Invoice.query.get_or_404(invoice_id)\n"
        guard = "    if row.owner_id != current_user.id OR row.tenant_id != current_user.tenant_id:\n        abort(403)\n    row.amount = 100\n    db.session.commit()\n    return 'ok'\n"
        self.assertEqual(self.auth(prefix + guard.replace('OR', 'or')), [])
        found = self.auth(prefix + guard.replace('OR', 'and'))
        self.assertTrue(found)
        self.assertIn('tenant_id', found[0]['missing_fields'])

    def test_unverified_model_query_scope_is_conditional_and_exact(self):
        prefix = "from flask import request\nfrom flask_login import current_user\n@app.patch('/notes')\ndef edit(note_id):\n"
        source = prefix + "    Note.query.filter_by(id=note_id).update({'title': request.json['title']})\n    return 'ok'\n"
        self.assertTrue(self.auth(source))
        safe = source.replace('filter_by(id=note_id)', 'filter_by(id=note_id, owner_id=current_user.id, tenant_id=current_user.tenant_id)')
        self.assertEqual(self.auth(safe), [])
        self.assertTrue(any(t['rule'] == 'python-project-orm-provenance' for t in self.analyze(safe)[2]))

    def test_query_rebinding_does_not_reuse_discarded_owner_scope(self):
        source = "from flask_login import current_user\n@app.get('/notes')\ndef note(note_id):\n    query = Note.query.filter_by(owner_id=current_user.id)\n    query = Note.query\n    row = query.filter_by(id=note_id).first_or_404()\n    return row.body\n"
        self.assertTrue(self.auth(source))

    def test_other_object_guard_does_not_cover_query_delete(self):
        source = "from flask import request, abort\nfrom flask_login import current_user\n@app.delete('/notes')\ndef note(note_id):\n    owned = Note.query.filter_by(id=request.json['check_id'], owner_id=current_user.id).first_or_404()\n    if owned.owner_id != current_user.id:\n        abort(403)\n    Note.query.filter_by(id=note_id).delete()\n    return 'ok'\n"
        self.assertTrue(self.auth(source))

    def test_inverted_explicit_admin_guard_has_write_evidence_and_policy_gap(self):
        source = "from flask import abort\nfrom flask_login import current_user\n@app.delete('/accounts')\ndef delete(account_id):\n    if current_user.is_admin:\n        abort(403)\n    db.cursor().execute('DELETE FROM accounts WHERE id=%s', (account_id,))\n    return 'ok'\n"
        signals = self.analyze(source)[0]
        found = next(s for s in signals if s['rule'] == 'python-project-admin-authorization')
        self.assertFalse(found['admin_policy_verified'])
        self.assertTrue(found['trace'])
        self.assertFalse(any(s['rule'] == 'python-project-admin-authorization' for s in self.analyze(source.replace('if current_user.is_admin:', 'if not current_user.is_admin:'))[0]))

    def test_fixed_mapping_identifiers_control_only_all_literal_choices(self):
        prefix = "from flask import request\n@app.get('/products')\ndef products():\n    columns = {'name':'name', 'price':'price'}\n    sort = columns.get(request.args['sort'], 'name')\n    db.cursor().execute('SELECT * FROM products ORDER BY ' + sort + ' LIMIT :count', {'count':10})\n    return 'ok'\n"
        controls = []
        self.assertEqual(self.analyze(prefix, controls_out=controls)[0], [])
        self.assertTrue(any(c['rules'] == ['python-sql-composition'] for c in controls))
        for bad in [prefix.replace("request.args['sort'], 'name'", "request.args['sort'], request.args['fallback']"),
                    prefix.replace("'price':'price'", "'price':request.args['column']")]:
            with self.subTest(source=bad):
                self.assertTrue(any(s['rule'] == 'python-project-sql-injection' for s in self.analyze(bad)[0]))

    def test_safe_caller_does_not_hide_unsupported_handler_registration(self):
        text = "from flask import request\ndef calc(value):\n    return eval(value)\n@app.get('/safe')\ndef safe():\n    return calc('2')\ndef other_handler():\n    return calc(request.args['expression'])\napp.add_url_rule('/unsafe', view_func=other_handler)\n"
        controls = []
        signals, gaps, _ = self.analyze(text, controls_out=controls)
        self.assertEqual(controls, [])
        self.assertTrue(any(g['rule'] == 'python-project-callback-gap' for g in gaps))
        self.assertTrue(any(s['rule'] == 'python-project-interpreter-input' for s in signals))

    def test_unexpanded_imported_alias_and_local_alias_withhold_control(self):
        for invocation in ["    return calculate(value)\n", "    runner = calculate\n    return runner(value)\n"]:
            with self.subTest(invocation=invocation):
                files = {'calc.py': 'def calc(value):\n    return eval(value)\n',
                         'app.py': "from flask import request\nfrom calc import calc as calculate\n@app.get('/safe')\ndef safe():\n    return calculate('2')\ndef unsupported(value):\n" + invocation}
                controls = []
                _, gaps, _ = self.analyze(files, controls_out=controls)
                self.assertEqual(controls, [])
                self.assertTrue(any(g['rule'] == 'python-project-unexpanded-caller-gap' for g in gaps))

    def test_unknown_registration_positional_function_argument_is_gap(self):
        source = "def callback(value):\n    return eval(value)\nunknown_library.register(callback)\n"
        _, gaps, _ = self.analyze(source)
        self.assertTrue(any(g['rule'] == 'python-project-callback-gap' for g in gaps))

    def test_undecorated_explicit_flask_source_keeps_fstring_query_trace(self):
        text = "from flask import request\ndef report(cursor):\n    year = request.args['year']\n    return cursor.execute(f'SELECT total FROM reports WHERE year = {year}')\n"
        signals, _, tasks = self.analyze(text)
        found = next(s for s in signals if s['rule'] == 'python-project-sql-injection')
        self.assertTrue(any(t['line'] == 3 for t in found['trace']))
        self.assertEqual(found['line'], 4)
        self.assertTrue(any(t['rule'] == 'python-project-entrypoint-policy' for t in tasks))
        self.assertEqual(self.analyze(text.replace("f'SELECT total FROM reports WHERE year = {year}'", "'SELECT total FROM reports WHERE year = 2025'"))[0], [])

    def test_sqlalchemy_text_is_query_construction_not_a_sanitizer(self):
        prefix = "from flask import request\nfrom sqlalchemy import text as statement\nfrom app import db\ndef search():\n    state = request.args['state']\n"
        text = prefix + "    sql = statement('SELECT * FROM tasks WHERE state = ' + state)\n    return db.session.execute(sql).all()\n"
        found = next(s for s in self.analyze(text)[0] if s['rule'] == 'python-project-sql-injection')
        self.assertEqual(found['line'], 7)
        self.assertTrue(found['trace'])
        safe = prefix + "    sql = statement('SELECT * FROM tasks WHERE state = :state')\n    return db.session.execute(sql, {'state':state}).all()\n"
        self.assertEqual(self.analyze(safe)[0], [])

    def test_external_session_get_uses_exact_tenant_guard(self):
        prefix = "from flask import jsonify, abort\nfrom flask_login import current_user\nfrom app import db, Invoice\n@app.get('/invoices')\ndef show(invoice_id):\n    invoice = db.session.get(Invoice, invoice_id)\n"
        disclose = "    return jsonify({'amount':invoice.amount})\n"
        self.assertTrue(self.auth(prefix + disclose))
        guard = "    if invoice is None or invoice.tenant_id != current_user.tenant_id:\n        abort(404)\n"
        self.assertEqual(self.auth(prefix + guard + disclose), [])
        self.assertTrue(self.auth(prefix + guard.replace('current_user.tenant_id', 'invoice_id') + disclose))

    def test_external_session_delete_requires_actual_selected_object_guard(self):
        prefix = "from flask import request, abort\nfrom flask_login import current_user\nfrom app import db, Note\n@app.delete('/notes')\ndef delete(note_id):\n    note = Note.query.get_or_404(note_id)\n"
        write = "    db.session.delete(note)\n    return '',204\n"
        self.assertTrue(self.auth(prefix + write))
        guard = "    if note.owner_id != current_user.id:\n        abort(403)\n"
        self.assertEqual(self.auth(prefix + guard + write), [])
        self.assertTrue(self.auth(prefix + guard.replace('current_user.id', "int(request.args['owner'])") + write))

    def test_with_cursor_binding_and_query_fstring_has_bounded_evidence(self):
        text = "from flask import request\n@app.get('/x')\ndef report():\n    with connection.cursor() as cursor:\n        year = request.args['year']\n        cursor.execute(f'SELECT total FROM reports WHERE year = {year}')\n    return 'ok'\n"
        signals, gaps, _ = self.analyze(text)
        self.assertTrue(any(s['rule'] == 'python-project-sql-injection' and s['line'] == 6 for s in signals))
        self.assertTrue(any(g['rule'] == 'python-project-with-gap' for g in gaps))
        self.assertEqual(self.analyze(text.replace("f'SELECT total FROM reports WHERE year = {year}'", "'SELECT total FROM reports WHERE year = :year', {'year':year}"))[0], [])

    def test_subprocess_check_output_cross_file_shell_and_argv_pair(self):
        files = {'app.py': "from flask import request\nfrom runner import run\ndef handler():\n    return run(request.args['value'])\n", 'runner.py': "import subprocess\ndef run(value):\n    return subprocess.check_output('echo ' + value, shell=True)\n"}
        found = next(s for s in self.analyze(files)[0] if s['rule'] == 'python-project-interpreter-input')
        self.assertEqual(found['path'], 'runner.py')
        self.assertTrue(any(t['path'] == 'app.py' for t in found['trace']))
        files['runner.py'] = "import subprocess\ndef run(value):\n    return subprocess.check_output(['echo', value], shell=False)\n"
        self.assertEqual(self.analyze(files)[0], [])

    def test_parse_resource_and_unknown_calls_withhold_suppression(self):
        controls = []
        signals, gaps, _ = self.analyze({'app.py': "@app.get('/x')\ndef x():\n    return eval('2 + 2')\n", 'bad.py': 'def broken('}, controls_out=controls)
        self.assertTrue(gaps)
        self.assertEqual(controls, [])
        self.assertEqual(signals, [])
        _, gaps, _ = self.analyze('x=' + repr('x' * engine.MAX_SOURCE_BYTES))
        self.assertTrue(any(g['rule'] == 'python-project-resource-gap' for g in gaps))


if __name__ == '__main__':
    unittest.main()
