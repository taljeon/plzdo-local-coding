from engine_types import no_start_cleanup
"""Offline pack checks and mock process/browser boundary tests; no model calls."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from workflow_core import ContractError
import workflow_validation as validation


class ValidationPackTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.candidate = self.root / 'candidate'
        self.candidate.mkdir()

    def write(self, relative, content):
        path = self.candidate / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
        return path

    def packet(self, paths, packs=None, checks=None):
        return {'allowed_paths': paths, 'validation_packs': packs or [],
                'checks': checks or [], 'timeout_seconds': 30}

    def browser_pack(self):
        return {'type': 'html-browser', 'path': 'index.html',
                'expected_text': ['Example'], 'clicks': [{'selector': '#show', 'expect_text': 'Changed'}],
                'widths': [390, 1280]}

    def fake_run(self, argv, cwd, evidence, timeout, **kwargs):
        self.assertTrue(kwargs['pipe_output'])
        self.assertGreater(timeout, 0)
        state = json.loads(argv[argv.index('--sandbox-state-json') + 1])
        self.assertEqual(state['permissionProfile']['network'], 'restricted')
        entries = state['permissionProfile']['file_system']['entries']
        writes = [entry['path']['path'] for entry in entries if entry['access'] == 'write']
        self.assertEqual(len(writes), 1)
        self.assertFalse(Path(writes[0]).is_relative_to(self.candidate))
        self.assertNotIn(str(validation.DIRECTORY), [entry['path'].get('path') for entry in entries])
        self.assertIn('/usr/bin/env', argv)
        self.assertIn('-i', argv)
        evidence = Path(evidence)
        evidence.mkdir()
        spec_path = evidence.parent / ('spec-' + evidence.name.split('-')[-1] + '.json')
        spec = json.loads(spec_path.read_text())
        pack = spec['pack']
        if pack is None:
            report = {'command': 'completed'}
        elif pack['type'] == 'html-browser':
            report = self.browser_report(pack, Path(spec['scratch']))
        else:
            try:
                report = validation._run_builtin(pack, self.candidate)
            except Exception as exc:
                report = {'passed': False, 'executed': True, 'error': type(exc).__name__}
        (evidence / 'events.jsonl').write_text(json.dumps(report) + '\n')
        code = 0 if report.get('passed', True) else 1
        summary = {'return_code': code, 'child_exit_code': code, 'duration_seconds': 0.01,
                   'timed_out': False, 'supervisor_stop': False,
                   'stop_reason': 'process-exited', 'error': None, 'cleanup': no_start_cleanup()}
        (evidence / 'summary.json').write_text(json.dumps(summary))
        (evidence / 'stderr.log').write_text('')
        return summary

    def browser_report(self, pack, scratch):
        screenshots = scratch / 'screenshots'
        screenshots.mkdir(exist_ok=True)
        viewports = []
        for width in pack['widths']:
            image = screenshots / ('viewport-' + str(width) + '.png')
            image.write_bytes(b'\x89PNG\r\n\x1a\nmocked screenshot, not live browser proof')
            viewports.append({'width': width, 'passed': True,
                              'layout': {'body_present': True, 'horizontal_overflow': False},
                              'screenshot': str(image),
                              'expected_text': [{'text': text, 'visible': True} for text in pack['expected_text']],
                              'clicks': [{**click, 'before_visible': False, 'after_visible': True, 'passed': True}
                                         for click in pack['clicks']]})
        return {'type': 'html-browser', 'passed': True, 'executed': True, 'viewports': viewports,
                'external_resources': [], 'console_errors': [], 'page_errors': []}

    def test_normalization_preserves_host_pack_without_mutating_it(self):
        original = [{'type': 'text', 'path': 'notes.md', 'required': ['42']}]
        normalized = validation.validate_packs(original, ['notes.md'])
        self.assertEqual(normalized[0]['forbidden'], [])
        self.assertNotIn('forbidden', original[0])
        normalized[0]['required'].append('43')
        self.assertEqual(original[0]['required'], ['42'])

    def test_pack_count_and_unknown_fields_are_rejected(self):
        pack = {'type': 'text', 'path': 'notes.md', 'required': ['x']}
        for packs in ([pack] * 9, [{**pack, 'command': ['touch', 'other']}], [{'type': 'arbitrary-code'}]):
            with self.subTest(packs=packs), self.assertRaises(ContractError):
                validation.validate_packs(packs, ['notes.md'])

    def test_exact_paths_and_file_types_are_enforced(self):
        for pack in ({'type': 'python-syntax', 'paths': ['../escape.py']},
                     {'type': 'python-syntax', 'paths': ['unlisted.py']},
                     {'type': 'python-syntax', 'paths': ['notes.md']},
                     {'type': 'text', 'path': '.env', 'required': ['x']}):
            with self.subTest(pack=pack), self.assertRaises(ContractError):
                validation.validate_packs([pack], ['notes.md'])

    def test_json_schema_rejects_remote_refs_ids_and_dynamic_refs(self):
        for schema in ({'$ref': 'https://example.invalid/schema.json'},
                       {'$defs': {'nested': {'$ref': 'file:///private/data'}}},
                       {'$dynamicRef': '#node'}, {'$id': 'https://example.invalid/id'},
                       {'type': 'unknown-type'}):
            with self.subTest(schema=schema), self.assertRaises(ContractError):
                validation.validate_packs([{'type': 'json-schema', 'path': 'data.json', 'schema': schema}], ['data.json'])

    def test_json_const_detects_changed_frozen_value(self):
        schema = {'type': 'object', 'additionalProperties': False, 'required': ['value', 'unit'],
                  'properties': {'value': {'const': 42}, 'unit': {'const': 'ms'}}}
        pack = validation.validate_packs([{'type': 'json-schema', 'path': 'data.json', 'schema': schema}], ['data.json'])[0]
        self.write('data.json', '{"value":42,"unit":"ms"}\n')
        self.assertTrue(validation._run_builtin(pack, self.candidate)['passed'])
        self.write('data.json', '{"value":43,"unit":"ms"}\n')
        self.assertFalse(validation._run_builtin(pack, self.candidate)['passed'])

    def test_local_schema_reference_works_without_fetch(self):
        schema = {'$defs': {'answer': {'const': 42}}, 'type': 'object',
                  'required': ['value'], 'properties': {'value': {'$ref': '#/$defs/answer'}}}
        pack = validation.validate_packs([{'type': 'json-schema', 'path': 'data.json', 'schema': schema}], ['data.json'])[0]
        self.write('data.json', '{"value":42}\n')
        self.assertTrue(validation._run_builtin(pack, self.candidate)['passed'])

    def test_json_duplicate_keys_and_nonfinite_numbers_fail(self):
        for text in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                validation.strict_json(text)

    def test_python_syntax_never_executes_candidate(self):
        marker = self.root / 'should-not-exist'
        self.write('code.py', 'from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("executed")\n')
        result = validation._run_builtin({'type': 'python-syntax', 'paths': ['code.py']}, self.candidate)
        self.assertTrue(result['passed'])
        self.assertFalse(marker.exists())
        self.write('code.py', 'def broken(:\n')
        self.assertFalse(validation._run_builtin({'type': 'python-syntax', 'paths': ['code.py']}, self.candidate)['passed'])

    def test_text_assertions_detect_missing_and_forbidden_values(self):
        pack = {'type': 'text', 'path': 'notes.md', 'required': ['42 ms'], 'forbidden': ['43 ms']}
        self.write('notes.md', 'The fixed delay is 42 ms.\n')
        self.assertTrue(validation._run_builtin(pack, self.candidate)['passed'])
        self.write('notes.md', 'The fixed delay is 43 ms.\n')
        self.assertEqual(len(validation._run_builtin(pack, self.candidate)['failures']), 2)

    def test_browser_normalization_and_click_semantics_are_bounded(self):
        result = validation.validate_packs([{'type': 'html-browser', 'path': 'index.html'}], ['index.html'])
        self.assertEqual(result[0]['widths'], [390, 1280])
        for pack in ({**self.browser_pack(), 'widths': [1]},
                     {**self.browser_pack(), 'widths': [390, 390]},
                     {**self.browser_pack(), 'expected_text': ['Changed']},
                     {**self.browser_pack(), 'clicks': [{'selector': '#a', 'expect_text': 'x', 'evaluate': 'evil()'}]}):
            with self.subTest(pack=pack), self.assertRaises(ContractError):
                validation.validate_packs([pack], ['index.html'])

    def test_browser_legacy_normalization_hash_is_unchanged(self):
        original = self.browser_pack()
        self.assertEqual(validation.validate_packs([original], ['index.html']), [original])
        self.assertNotIn('driver', validation.validate_packs([original], ['index.html'])[0])
        for driver in ('managed', 'native'):
            declared = {**original, 'driver': driver}
            self.assertEqual(validation.validate_packs([declared], ['index.html']), [declared])
        with self.assertRaises(ContractError):
            validation.validate_packs([{**original, 'driver': 'unrestricted'}], ['index.html'])

    def test_managed_browser_handoff_runs_all_other_packs_and_never_launches_browser(self):
        self.write('index.html', '<!doctype html><h1>Example</h1>\n')
        self.write('notes.md', '42 ms\n')
        managed = {**self.browser_pack(), 'driver': 'managed'}
        text = {'type': 'text', 'path': 'notes.md', 'required': ['42 ms']}
        packet = self.packet(['index.html', 'notes.md'], [managed, text], [['python3', '-B', '-c', 'pass']])
        before = validation._tree_snapshot(self.candidate)
        with patch.object(validation, 'run', side_effect=self.fake_run) as process:
            result = validation.run_artifact_checks(packet, self.candidate, self.root / 'managed')
        self.assertEqual(process.call_count, 2)
        self.assertFalse(result['passed'])
        self.assertEqual(result['status'], 'awaiting_browser_validation')
        self.assertEqual(result['pending_browser'], [{'pack_index': 0, 'pack': managed}])
        self.assertEqual([row['kind'] for row in result['checks']], ['command', 'html-browser', 'text'])
        self.assertFalse(result['checks'][1]['executed'])
        self.assertIsNone(result['checks'][1]['return_code'])
        self.assertIsNone(result['checks'][1]['duration_seconds'])
        self.assertTrue(result['checks'][2]['executed'])
        self.assertEqual(before, validation._tree_snapshot(self.candidate))
        self.assertFalse(list((self.root / 'managed').rglob('profile-*')))

    def test_managed_only_pack_is_pending_not_passed_or_executed(self):
        self.write('index.html', '<!doctype html><h1>Example</h1>\n')
        packet = self.packet(['index.html'], [{**self.browser_pack(), 'driver': 'managed'}])
        with patch.object(validation, 'run') as process:
            result = validation.run_artifact_checks(packet, self.candidate, self.root / 'managed')
        process.assert_not_called()
        self.assertFalse(result['passed'])
        self.assertEqual(len(result['pending_browser']), 1)

    def test_nonbrowser_semantic_failure_is_not_masked_as_pending_browser(self):
        self.write('index.html', '<!doctype html><h1>Example</h1>\n')
        self.write('notes.md', 'wrong value\n')
        packet = self.packet(['index.html', 'notes.md'], [
            {**self.browser_pack(), 'driver': 'managed'},
            {'type': 'text', 'path': 'notes.md', 'required': ['42 ms']},
        ])
        with patch.object(validation, 'run', side_effect=self.fake_run):
            result = validation.run_artifact_checks(packet, self.candidate, self.root / 'managed')
        self.assertFalse(result['passed'])
        self.assertEqual(result['pending_browser'], [])
        self.assertNotIn('status', result)
        self.assertNotEqual(result['checks'][-1]['return_code'], 0)

    def test_managed_browser_does_not_mask_source_mutation(self):
        source = self.write('index.html', '<!doctype html><h1>Example</h1>\n')
        self.write('notes.md', '42 ms\n')
        packet = self.packet(['index.html', 'notes.md'], [
            {**self.browser_pack(), 'driver': 'managed'},
            {'type': 'text', 'path': 'notes.md', 'required': ['42 ms']},
        ])

        def mutate(*args, **kwargs):
            summary = self.fake_run(*args, **kwargs)
            source.write_text('<!doctype html><h1>changed</h1>\n')
            return summary

        with patch.object(validation, 'run', side_effect=mutate):
            result = validation.run_artifact_checks(packet, self.candidate, self.root / 'managed')
        self.assertFalse(result['passed'])
        self.assertFalse(result['scope']['passed'])
        self.assertEqual(result['pending_browser'], [])

    def test_managed_browser_does_not_mask_file_format_failure(self):
        self.write('index.html', '<h1>Example</h1> \n')
        packet = self.packet(['index.html'], [{**self.browser_pack(), 'driver': 'managed'}])
        with patch.object(validation, 'run') as process:
            result = validation.run_artifact_checks(packet, self.candidate, self.root / 'managed')
        process.assert_not_called()
        self.assertFalse(result['passed'])
        self.assertFalse(result['diff_check']['passed'])
        self.assertEqual(result['pending_browser'], [])

    def test_artifact_checks_require_no_git_and_preserve_source(self):
        self.write('code.py', 'value = 42\n')
        self.write('notes.md', '42 ms\n')
        packet = self.packet(['code.py', 'notes.md'], [{'type': 'python-syntax', 'paths': ['code.py']},
                                                    {'type': 'text', 'path': 'notes.md', 'required': ['42 ms']}],
                             [['python3', '-B', '-c', 'assert 1 + 1 == 2']])
        before = validation._tree_snapshot(self.candidate)
        with patch.object(validation, 'run', side_effect=self.fake_run):
            result = validation.run_artifact_checks(packet, self.candidate, self.root / 'evidence')
        self.assertTrue(result['passed'])
        self.assertEqual(len(result['checks']), 3)
        self.assertEqual(before, validation._tree_snapshot(self.candidate))
        self.assertFalse((self.candidate / '.git').exists())
        self.assertEqual(result['diff_check']['kind'], 'artifact-text-format')

    def test_unexpected_artifact_or_missing_output_blocks_before_execution(self):
        self.write('notes.md', 'expected\n')
        self.write('extra.txt', 'unexpected\n')
        packet = self.packet(['notes.md', 'missing.md'], [{'type': 'text', 'path': 'notes.md', 'required': ['expected']}])
        with patch.object(validation, 'run') as process:
            result = validation.run_artifact_checks(packet, self.candidate, self.root / 'evidence')
        process.assert_not_called()
        self.assertFalse(result['passed'])
        self.assertEqual(result['scope']['violations'], ['extra.txt'])
        self.assertEqual(result['missing_required_changed_paths'], ['missing.md'])

    def test_check_that_mutates_source_cannot_pass(self):
        source = self.write('notes.md', 'expected\n')
        packet = self.packet(['notes.md'], checks=[['python3', '-B', '-c', 'pass']])

        def mutate(*args, **kwargs):
            summary = self.fake_run(*args, **kwargs)
            source.write_text('mutated\n')
            return summary

        with patch.object(validation, 'run', side_effect=mutate):
            result = validation.run_artifact_checks(packet, self.candidate, self.root / 'evidence')
        self.assertFalse(result['passed'])
        self.assertEqual(result['scope']['violations'], ['notes.md'])

    def test_missing_check_report_is_not_a_pass(self):
        self.write('code.py', 'value = 42\n')
        packet = self.packet(['code.py'], [{'type': 'python-syntax', 'paths': ['code.py']}])
        with patch.object(validation, 'run', return_value={'return_code': 0, 'duration_seconds': 0.1}):
            result = validation.run_artifact_checks(packet, self.candidate, self.root / 'evidence')
        self.assertFalse(result['passed'])
        self.assertNotEqual(result['checks'][0]['return_code'], 0)

    def test_browser_reports_all_requested_evidence(self):
        self.write('index.html', '<!doctype html><h1>Example</h1>\n')
        packet = self.packet(['index.html'], [self.browser_pack()])
        trusted = self.root / 'trusted-runtime'
        trusted.mkdir(mode=0o700)
        bindings = []
        for name in ('node', 'playwright', 'chrome'):
            path = trusted / name
            path.write_bytes(('synthetic runtime fixture ' + name).encode())
            path.chmod(0o700)
            bindings.append({'command': name, 'path': str(path),
                             'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        policy = self.root / 'runtime-policy.json'
        policy.write_text(json.dumps({'schema': 'local-coding-runtime.v1',
                                     'executables': bindings, 'read_files': []}))
        policy.chmod(0o600)
        with patch.dict(os.environ, {'LOCAL_CODING_RUNTIME_POLICY': str(policy),
                'LOCAL_CODING_RUNTIME_POLICY_SHA256': hashlib.sha256(policy.read_bytes()).hexdigest()}), \
                patch.object(validation, 'run', side_effect=self.fake_run):
            result = validation.run_artifact_checks(packet, self.candidate, self.root / 'browser-evidence')
        self.assertTrue(result['passed'])
        self.assertEqual(len(result['checks'][0]['report']['viewports']), 2)
        command = result['checks'][0]['argv']
        self.assertEqual(command[0], str(trusted / 'node'))
        self.assertEqual(command[1], str(self.root / 'browser-evidence/runtime/browser_check.cjs'))
        specification = json.loads((self.root / 'browser-evidence/spec-1.json').read_text())
        self.assertEqual(specification['runtime'], {'playwright': str(trusted / 'playwright'),
                                                  'chrome': str(trusted / 'chrome')})

    def test_browser_missing_evidence_errors_and_noop_clicks_fail(self):
        pack = self.browser_pack()
        scratch = self.root / 'scratch'
        scratch.mkdir()
        original = self.browser_report(pack, scratch)
        cases = [
            {**original, 'viewports': []},
            {**original, 'external_resources': ['https://example.invalid']},
            {**original, 'console_errors': ['bad JavaScript']},
            {**original, 'page_errors': ['uncaught exception']},
        ]
        for field, value in (('screenshot', str(self.root / 'missing.png')),
                             ('clicks', [{**pack['clicks'][0], 'before_visible': True, 'after_visible': True, 'passed': True}]),
                             ('expected_text', []), ('layout', {'body_present': True, 'horizontal_overflow': True})):
            report = copy.deepcopy(original)
            report['viewports'][0][field] = value
            cases.append(report)
        for report in cases:
            with self.subTest(report=report), self.assertRaises(ContractError):
                validation._validate_browser_report(report, pack, scratch)

    def test_screenshot_outside_scratch_is_rejected(self):
        pack, scratch = self.browser_pack(), self.root / 'scratch'
        scratch.mkdir()
        report = self.browser_report(pack, scratch)
        outside = self.root / 'outside.png'
        outside.write_bytes(b'\x89PNG\r\n\x1a\n')
        report['viewports'][0]['screenshot'] = str(outside)
        with self.assertRaises(ContractError):
            validation._validate_browser_report(report, pack, scratch)

    def test_artifact_with_no_checks_is_not_passed(self):
        self.write('notes.md', 'content\n')
        result = validation.run_artifact_checks(self.packet(['notes.md']), self.candidate, self.root / 'evidence')
        self.assertFalse(result['passed'])

    def test_trailing_whitespace_fails_artifact_format_gate(self):
        self.write('notes.md', 'content \n')
        packet = self.packet(['notes.md'], [{'type': 'text', 'path': 'notes.md', 'required': ['content']}])
        with patch.object(validation, 'run', side_effect=self.fake_run):
            result = validation.run_artifact_checks(packet, self.candidate, self.root / 'evidence')
        self.assertFalse(result['passed'])
        self.assertEqual(result['diff_check']['issues'][0]['reason'], 'trailing-whitespace')

    def test_symlink_candidate_file_is_rejected(self):
        outside = self.root / 'outside'
        outside.write_text('data')
        (self.candidate / 'linked.md').symlink_to(outside)
        with self.assertRaises(ContractError):
            validation._tree_snapshot(self.candidate)

    def test_empty_or_timed_out_pack_cannot_silently_skip(self):
        self.write('notes.md', 'content\n')
        packet = self.packet(['notes.md'], [{'type': 'text', 'path': 'notes.md', 'required': ['content']}])
        with patch.object(validation.time, 'monotonic', side_effect=[0, 31]), patch.object(validation, 'run') as process:
            result = validation.run_artifact_checks(packet, self.candidate, self.root / 'evidence')
        process.assert_not_called()
        self.assertFalse(result['passed'])

    def test_evidence_cannot_be_written_inside_candidate(self):
        self.write('notes.md', 'content\n')
        with self.assertRaises(ContractError):
            validation.run_artifact_checks(self.packet(['notes.md']), self.candidate, self.candidate / 'evidence')

    def test_untrusted_shell_wrapper_checks_are_rejected(self):
        with self.assertRaises(ContractError):
            validation._validate_commands([['sh', '-c', 'touch unexpected']])

    def test_staged_runtime_is_exact_and_hash_verified(self):
        evidence = self.root / 'runtime-evidence'
        evidence.mkdir()
        runtime, receipt = validation._stage_runtime(evidence)
        self.assertEqual({path.name for path in runtime.iterdir()},
                         {'workflow_validation.py', 'workflow_core.py', 'run_bounded.py', 'host_paths.py', 'json_codec.py', 'engine_types.py', 'provider_common.py'})
        validation._verify_runtime(runtime, receipt)
        metadata = json.loads((evidence / 'runtime-receipt.json').read_text())
        self.assertEqual(metadata['files'], receipt)
        target = runtime / 'workflow_validation.py'
        target.chmod(0o600)
        target.write_text('tampered')
        with self.assertRaises(ContractError):
            validation._verify_runtime(runtime, receipt)


if __name__ == '__main__':
    unittest.main()
