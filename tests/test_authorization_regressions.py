"""Expected-behavior static checks; no fixture execution or server calls."""
import unittest
import importlib.util
import json
from pathlib import Path
import tempfile

REPO = Path(__file__).resolve().parents[1]
CASES = json.loads((REPO / 'tests/fixtures/authorization_regressions.json').read_text(encoding='utf-8'))

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

helper = load('authorization_regression_helper', REPO / 'skills/hydrascan/scripts/hydrascan_source.py')
runner = load('authorization_regression_runner', REPO / 'skills/hydrascan/scripts/hydrascan.py')

class AuthorizationRegressionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def signals(self, name):
        return helper.inspect_python(CASES[name])[0]

    def assert_candidate(self, name):
        self.assertTrue(any(x['rule'] == 'python-object-authorization' for x in self.signals(name)), name)

    def assert_no_candidate(self, name):
        self.assertFalse(any(x['rule'] == 'python-object-authorization' for x in self.signals(name)), name)

    def test_positive_and_genuine_controls(self):
        self.assert_candidate('positive_unscoped')
        self.assert_no_candidate('control_scoped_principal')
        self.assert_no_candidate('control_inequality_exit')
        self.assert_no_candidate('control_positive_owner_branch')

    def test_conditional_controls_do_not_suppress(self):
        for name in ('conditional_guard_does_not_dominate', 'conditional_guard_boolean_test', 'unsafe_sql_or', 'query_subquery_scope_not_outer_owner', 'different_owned_object_checked'):
            with self.subTest(name=name):
                self.assert_candidate(name)

    def test_request_selected_principal_does_not_suppress(self):
        for name in ('caller_principal_default','caller_principal_boolean_fallback','caller_principal_conditional','caller_owner_guard_default','principal_branch_untrusted_control'):
            with self.subTest(name=name):
                self.assert_candidate(name)

    def test_sql_comment_owner_clause_does_not_suppress(self):
        self.assert_candidate('commented_owner_placeholder')

    def test_sql_string_owner_clause_does_not_suppress(self):
        self.assert_candidate('owner_comparison_in_sql_string')

    def test_derived_owner_guard_does_not_suppress(self):
        self.assert_candidate('owner_guard_derived_arithmetic')

    def test_derived_principal_does_not_suppress(self):
        self.assert_candidate('principal_derived_arithmetic')

    def test_conditional_nonprincipal_does_not_suppress(self):
        self.assert_candidate('principal_conditional_nonprincipal')

    def test_owner_sql_expression_is_not_exact_principal_equality(self):
        self.assert_candidate('sql_owner_rhs_arithmetic')

    def test_lookup_identity_distinguishes_same_line_nodes(self):
        self.assert_candidate('same_line_unsafe_then_safe')

    def test_lookup_identity_does_not_promote_safe_result(self):
        self.assert_no_candidate('same_line_safe_then_unsafe')

    def test_guard_on_second_same_line_object_does_not_clear_first(self):
        self.assert_candidate('two_objects_same_line_one_guard')

    def test_wrapper_owner_does_not_clear_inner_object(self):
        self.assert_candidate('wrapper_owner_is_not_record_owner')

    def test_mutating_owner_does_not_establish_provenance(self):
        self.assert_candidate('rewritten_owner_is_not_verified_owner')

    def test_return_namedexpr_evaluation_order(self):
        self.assert_candidate('return_namedexpr_binding_order')

    def test_augassign_preserves_request_input(self):
        self.assert_candidate('augassign_request_input_lost')

    def test_tuple_assignment_preserves_input_elements(self):
        self.assert_candidate('tuple_unpacking_input_lost')

    def test_simple_execute_alias_preserves_lookup(self):
        self.assert_candidate('sql_alias_lookup')

    def test_call_target_captured_before_argument_namedexpr(self):
        self.assertTrue(any(x['rule'] == 'python-dynamic-code' for x in self.signals('captured_call_target_before_namedexpr')))

    def test_safe_captured_call_does_not_promote_alias(self):
        self.assertFalse(any(x['rule'] == 'python-dynamic-code' for x in self.signals('captured_safe_call_target_before_namedexpr')))

    def test_future_local_binding_hides_outer_alias(self):
        self.assertFalse(any(x['rule'] == 'python-dynamic-code' for x in self.signals('local_future_binding_not_outer_eval')))

    def test_comprehension_target_does_not_shadow_function_builtin(self):
        self.assertTrue(any(x['rule'] == 'python-dynamic-code' and x['line'] == 2 for x in self.signals('comprehension_target_does_not_bind_function_local')))

    def test_evidence_and_candidate_semantics(self):
        root = self.root / 'inert_regression_integration'
        root.mkdir(exist_ok=True)
        (root / 'example.py').write_text(CASES['positive_unscoped'],encoding='utf-8')
        candidates,gaps,tasks = runner.analyze(root,[{'path':'example.py'}])
        finding = next(x for x in candidates if x['rule'] == 'python-object-authorization')
        self.assertEqual(finding['evidence_lines'], {'input':4,'lookup':6,'disclosure':7})
        self.assertEqual(finding['proof_state'],'candidate')
        self.assertEqual(finding['kind'],'security')
        self.assertTrue(finding['id'].startswith('HS-'))
        self.assertNotIn('confirmed',finding['proof_state'])
        self.assertTrue(all(x['kind']=='review-task' and 'proof_state' not in x for x in tasks))

    def test_review_task_ids_are_unique(self):
        root = self.root / 'inert_regression_integration'
        root.mkdir(exist_ok=True)
        (root / 'same_line.py').write_text(CASES['duplicate_tasks_no_disclosure'],encoding='utf-8')
        _,_,tasks = runner.analyze(root,[{'path':'same_line.py'}])
        self.assertEqual(len({x['id'] for x in tasks}),len(tasks))

if __name__ == '__main__':
    unittest.main()
