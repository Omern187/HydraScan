"""Inert source data: never execute the analyzed application snippets."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('authorization_flow_tests', ROOT / 'skills/hydrascan/scripts/hydrascan_source.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

SCHEMA = 'db.execute("CREATE TABLE records (id INTEGER, owner_id INTEGER, title TEXT)")\n'
LOOKUP = "    row = db.execute('SELECT * FROM records WHERE id = ?', (record_id,)).fetchone()\n"
PREFIX = "from flask import request, abort\n@app.get('/records')\ndef record():\n    record_id = request.args.get('id')\n"


class AuthorizationFlowTests(unittest.TestCase):
    def candidates(self, text):
        return [item for item in helper.inspect_python(text)[0] if item['rule'] == 'python-object-authorization']

    def test_frozen_independent_cases(self):
        cases = []
        for name in ('authorization_cases.json', 'authorization_challenges.json'):
            cases.extend(json.loads((ROOT / 'tests/fixtures' / name).read_text(encoding='utf-8'))['cases'])
        for case in cases:
            with self.subTest(case=case['id']):
                signals, tasks = helper.inspect_python(case['source'])
                candidates = [item for item in signals if item['rule'] == 'python-object-authorization']
                expected = case['expectation']['candidate_expected']
                if expected is not None:
                    self.assertEqual(bool(candidates), expected)
                else:
                    self.assertTrue(candidates or tasks, 'Unknown publication policy remains open')
                self.assertTrue(all('evidence_lines' in item for item in candidates))
                self.assertFalse(any('confirmed' in item.get('proof_state', '') for item in signals))

    def test_declared_schema_trace_and_bound_principal(self):
        candidate = self.candidates(SCHEMA + PREFIX + LOOKUP + '    return dict(row)\n')
        self.assertEqual(len(candidate), 1)
        self.assertTrue(candidate[0]['ownership_schema_observed'])
        self.assertEqual(candidate[0]['evidence_lines'], {'input': 5, 'lookup': 6, 'disclosure': 7})
        scoped = LOOKUP.replace('WHERE id = ?', 'WHERE id = ? AND owner_id = ?').replace('(record_id,)', '(record_id, current_user.id)')
        self.assertEqual(self.candidates(SCHEMA + PREFIX + scoped + '    return dict(row)\n'), [])

    def test_untrusted_or_branch_dependent_owner_is_not_a_principal(self):
        scoped = LOOKUP.replace('WHERE id = ?', 'WHERE id = ? AND owner_id = ?').replace('(record_id,)', '(record_id, owner)')
        for assign in ["    owner = request.args.get('owner')\n",
                       "    owner = current_user.id\n    if request.args.get('override'):\n        owner = request.args.get('owner')\n"]:
            with self.subTest(assign=assign):
                self.assertTrue(self.candidates(PREFIX + assign + scoped + '    return dict(row)\n'))

    def test_sending_precedes_later_guard_but_constructing_does_not(self):
        guard = "    if row['owner_id'] != current_user.id:\n        abort(403)\n"
        self.assertTrue(self.candidates(PREFIX + LOOKUP + '    self.reply(200, dict(row))\n' + guard + '    return None\n'))
        self.assertEqual(self.candidates(PREFIX + LOOKUP + '    response = dict(row)\n' + guard + '    return response\n'), [])

    def test_alias_guard_and_replaced_object(self):
        guard = "    alias = row\n    if alias['owner_id'] != current_user.id:\n        abort(403)\n"
        self.assertEqual(self.candidates(PREFIX + LOOKUP + guard + '    return dict(row)\n'), [])
        replacement = "    row = db.execute('SELECT * FROM records WHERE id = ?', (record_id,)).fetchone()\n"
        self.assertTrue(self.candidates(PREFIX + LOOKUP + guard + replacement + '    return dict(row)\n'))

    def test_missing_query_arguments_do_not_crash(self):
        helper.inspect_python('db.execute()\ndb.execute("SELECT * FROM records WHERE id = ?")\n')

    def test_mapping_guard_checks_exact_row_without_untrusted_default(self):
        guard = "    if row.get('owner_id') != current_user.id:\n        abort(403)\n"
        self.assertEqual(self.candidates(PREFIX + LOOKUP + guard + '    return dict(row)\n'), [])
        unsafe_default = guard.replace("row.get('owner_id')", "row.get('owner_id', request.args.get('owner'))")
        self.assertTrue(self.candidates(PREFIX + LOOKUP + unsafe_default + '    return dict(row)\n'))


if __name__ == '__main__':
    unittest.main()
