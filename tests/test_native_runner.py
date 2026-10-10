"""Behavioral checks for isolation, triage honesty, command execution and continuation."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "skills/hydrascan/scripts/hydrascan.py"
spec = importlib.util.spec_from_file_location("hydrascan", SCRIPT)
hydra = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hydra)


class NativeReviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "app"
        self.source.mkdir()
        self.run = self.root / "assessment"

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, relative, content):
        path = self.source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def checks(self, commands):
        path = self.root / "checks.json"
        path.write_text(json.dumps(commands), encoding="utf-8")
        return path

    def read(self, name):
        return json.loads((self.run / name).read_text(encoding="utf-8"))

    def test_end_to_end_with_real_bug_trigger_and_control(self):
        # Application test exposes a Unicode byte-count defect, independent of source signals.
        self.write("app.py", "def size(text):\n    return len(text)\n")
        self.write("probe.py", "from app import size\nassert size('abc') == 3\nassert size('שלום') == len('שלום'.encode('utf-8'))\n")
        self.write("render.js", "export function render(target, data) { target.innerHTML = data; }\n")
        result = hydra.scan(self.source, self.run, self.checks([
            {"name": "ASCII control", "argv": [sys.executable, "-c", "from app import size; assert size('abc') == 3"]},
            {"name": "Unicode invariant", "argv": [sys.executable, "probe.py"]},
        ]))
        self.assertEqual([x['status'] for x in self.read('checks.json')], ['passed', 'failed'])
        self.assertEqual(result['status'], 'completed')
        self.assertTrue(all(x['proof_state'] == 'candidate' for x in self.read('candidates.json')))
        self.assertEqual(len(self.read('coverage.json')), 32)
        self.assertFalse(any(x['status'] == 'checked-no-issue-observed' for x in self.read('coverage.json')))
        self.assertIn('Confirmed vulnerabilities: not determined', (self.run / 'report.md').read_text(encoding='utf-8'))

    def test_snapshot_keeps_original_untouched_and_records_exclusions(self):
        self.write('app.py', 'original = True\n')
        self.write('.env', 'TOKEN=private-token\n')
        self.write('.env.example', 'TOKEN=example\n')
        self.write('node_modules/package/index.js', 'privateDependency()\n')
        (self.source / 'binary.bin').write_bytes(b'\0\xff')
        outside = self.root / 'outside.txt'
        outside.write_text('outside-only-content', encoding='utf-8')
        try:
            (self.source / 'linked.txt').symlink_to(outside)
            symlink_created = True
        except OSError:
            symlink_created = False
        hydra.scan(self.source, self.run, self.checks([{'name': 'write test', 'argv': [sys.executable, '-c', "from pathlib import Path; Path('app.py').write_text('changed')"]}]))
        self.assertEqual((self.source / 'app.py').read_text(encoding='utf-8'), 'original = True\n')
        self.assertEqual((self.run / 'snapshot/app.py').read_text(encoding='utf-8'), 'changed')
        self.assertEqual(self.read('snapshot-changes.json'), [{'path': 'app.py', 'state': 'modified'}])
        excluded = {x['path']: x['reason'] for x in self.read('inventory.json')['excluded']}
        self.assertIn('.env', excluded)
        self.assertIn('node_modules', excluded)
        self.assertIn('binary.bin', excluded)
        self.assertTrue((self.run / 'snapshot/.env.example').exists())
        if symlink_created:
            self.assertIn('linked.txt', excluded)
            self.assertFalse((self.run / 'snapshot/linked.txt').exists())

    def test_safe_controls_and_aliases(self):
        self.write('safe.py', "import subprocess\nimport yaml\nimport requests\nsubprocess.run(['echo', 'ok'], shell=False)\nyaml.safe_load('{}')\nyaml.load('{}', Loader=yaml.SafeLoader)\nrequests.get('https://example.test', verify=True)\n")
        self.write('review.py', "from pickle import loads as deserialize\nimport subprocess as sp\nfrom requests import get as request\ndeserialize(data)\nsp.run(command, shell=True)\nrequest(url, verify=False)\n")
        hydra.scan(self.source, self.run)
        candidates = self.read('candidates.json')
        self.assertEqual({x['path'] for x in candidates}, {'review.py'})
        self.assertEqual({x['line'] for x in candidates}, {4, 5, 6})
        self.assertEqual({x['rule'] for x in candidates}, {'python-deserialization', 'python-shell', 'python-tls-verification', 'python-outbound-input'})

    def test_invalid_source_is_a_gap_and_values_are_withheld(self):
        secret = 'real-looking-fixture-value-123'
        self.write('config.json', json.dumps({'api_key': secret}))
        self.write('broken.py', 'def broken(:\n')
        hydra.scan(self.source, self.run)
        self.assertTrue(self.read('analysis-gaps.json'))
        self.assertTrue(self.read('candidates.json'))
        for name in ['candidates.json', 'report.md', 'review-state.md']:
            self.assertNotIn(secret, (self.run / name).read_text(encoding='utf-8'))

    def test_no_shell_interpolation_and_bounded_logs(self):
        argv_value = 'marker; echo unintended & echo nope'
        hydra.scan(self.source, self.run, self.checks([{'name': 'literal argv', 'argv': [sys.executable, '-c', 'import sys; print(sys.argv[1]); print("x" * 1200000)', argv_value]}]))
        check = self.read('checks.json')[0]
        log = (self.run / check['log']).read_text(encoding='utf-8')
        self.assertIn(argv_value, log)
        self.assertTrue(check['log_truncated'])
        self.assertLessEqual(len(log.encode()), hydra.MAX_LOG_BYTES)

    def test_timeout_and_missing_executable_are_explicit_results(self):
        started = time.monotonic()
        hydra.scan(self.source, self.run, self.checks([
            {'name': 'bounded wait', 'argv': [sys.executable, '-c', 'import time; time.sleep(20)'], 'timeout': .15},
            {'name': 'unavailable tool', 'argv': [str(self.root / 'not-a-real-executable')]},
        ]))
        self.assertLess(time.monotonic() - started, 8)
        self.assertEqual([x['status'] for x in self.read('checks.json')], ['timeout', 'error'])

    def test_collect_preserves_notes_and_original_inventory(self):
        self.write('app.js', 'eval(input);\n')
        hydra.scan(self.source, self.run)
        fingerprint = self.read('inventory.json')['fingerprint']
        for filename in ['report.md', 'review-state.md']:
            path = self.run / filename
            with path.open('a', encoding='utf-8') as stream:
                stream.write('\nIndependent validator: candidate invalidated by runtime guard.\n')
        (self.run / 'snapshot/app.js').write_text('modified after initial scan', encoding='utf-8')
        hydra.collect(self.run)
        self.assertEqual(self.read('inventory.json')['fingerprint'], fingerprint)
        for filename in ['report.md', 'review-state.md']:
            self.assertIn('candidate invalidated', (self.run / filename).read_text(encoding='utf-8'))

    def test_finished_check_removes_children_and_keeps_logs_separate(self):
        child = "import time; from pathlib import Path; time.sleep(1); Path('late.txt').write_text('orphan'); print('ORPHAN_FIRST_OUTPUT', flush=True)"
        parent = "import subprocess, sys; subprocess.Popen([sys.executable, '-c', " + repr(child) + "]); print('PARENT_OUTPUT', flush=True)"
        hydra.scan(self.source, self.run, self.checks([
            {'name': 'parent returns', 'argv': [sys.executable, '-c', parent]},
            {'name': 'next check', 'argv': [sys.executable, '-c', "import time; time.sleep(1.5); print('SECOND_OUTPUT')"]},
        ]))
        checks = self.read('checks.json')
        self.assertEqual([x['status'] for x in checks], ['passed', 'passed'])
        self.assertFalse((self.run / 'snapshot/late.txt').exists())
        first = (self.run / checks[0]['log']).read_text(encoding='utf-8')
        second = (self.run / checks[1]['log']).read_text(encoding='utf-8')
        self.assertIn('PARENT_OUTPUT', first)
        self.assertIn('SECOND_OUTPUT', second)
        self.assertNotIn('ORPHAN_FIRST_OUTPUT', second)
        self.assertNotIn('PARENT_OUTPUT', second)

    def test_collect_rejects_reversed_markers_without_touching_notes(self):
        hydra.scan(self.source, self.run)
        report = self.run / 'report.md'
        malformed = hydra.MARK_END + '\nManual findings must survive\n' + hydra.MARK_START
        report.write_text(malformed, encoding='utf-8')
        with self.assertRaises(ValueError):
            hydra.collect(self.run)
        self.assertEqual(report.read_text(encoding='utf-8'), malformed)

    def test_never_overwrite_or_recurse_into_source(self):
        self.write('app.py', 'pass\n')
        with self.assertRaises(ValueError):
            hydra.scan(self.source, self.source / 'run')
        self.assertFalse((self.source / 'run').exists())
        hydra.scan(self.source, self.run)
        (self.run / 'keep.txt').write_text('preserve', encoding='utf-8')
        with self.assertRaises(FileExistsError):
            hydra.scan(self.source, self.run)
        self.assertEqual((self.run / 'keep.txt').read_text(encoding='utf-8'), 'preserve')

    def test_invalid_command_config_is_rejected_before_creating_run(self):
        for config in [{'argv': 'echo unsafe'}, [{'name': 'bad timeout', 'argv': ['echo'], 'timeout': -1}], [{'name': 'bad argv', 'argv': ['']}]]:
            path = self.root / 'bad.json'
            path.write_text(json.dumps(config), encoding='utf-8')
            with self.assertRaises(ValueError):
                hydra.scan(self.source, self.run, path)
            self.assertFalse(self.run.exists())

    def test_known_environment_secrets_are_redacted_from_logs(self):
        value = 'synthetic-provider-secret-123'
        with patch.dict(os.environ, {'HYDRASCAN_TEST_API_KEY': value}):
            hydra.scan(self.source, self.run, self.checks([{'name': 'provider output', 'argv': [sys.executable, '-c', 'import os; print(os.environ["HYDRASCAN_TEST_API_KEY"])']}]))
        log = (self.run / 'logs/check-1.log').read_text(encoding='utf-8')
        self.assertNotIn(value, log)
        self.assertIn('[REDACTED]', log)

    def test_doctor_cli_has_no_engine_dependency(self):
        result = subprocess.run([sys.executable, str(SCRIPT), 'doctor'], capture_output=True, text=True, check=True)
        metadata = json.loads(result.stdout)
        self.assertFalse(metadata['external_engine_required'])
        self.assertEqual(metadata['extra_packages_required'], [])


if __name__ == '__main__':
    unittest.main()
