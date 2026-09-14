import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import workflow_core as core


class WorkflowCoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)
        self.repository = self.root / 'repository'
        self.repository.mkdir()
        (self.repository / 'src').mkdir()
        (self.repository / 'tests').mkdir()
        (self.repository / 'src/code.py').write_text('value = 1\n')
        (self.repository / 'src/code.js').write_text('export const value = 1;\n')
        (self.repository / 'tests/test_code.py').write_text('def test_value():\n    assert True\n')
        self.git('init', '-q')
        self.git('add', '.')
        self.git('-c', 'user.name=Test', '-c', 'user.email=test@example.com', 'commit', '-qm', 'fixture')
        self.base = self.git('rev-parse', 'HEAD').strip()
        self.packet = dict(id='smoke-task', repository=str(self.repository), base_revision=self.base,
                           objective='Change value from one to two', allowed_paths=['src/code.py'],
                           context_files=['tests/test_code.py'], checks=[['python3', '-B', '-m', 'pytest', '-p', 'no:cacheprovider']],
                           authorityId='fixture-authority', generation_profile='huihui-qwen38-q6kl-v1')

    def git(self, *args):
        env = {**os.environ, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
        return subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', *args], cwd=self.repository,
                                       env=env, stderr=subprocess.DEVNULL).decode()

    def validated(self, **overrides):
        return core.validate_packet({**self.packet, **overrides})

    def test_packet_defaults_and_dirty_source_use_committed_identity(self):
        (self.repository / 'src/code.py').write_text('user modification\n')
        packet = self.validated()
        self.assertEqual(packet['local_attempts'], 2)
        self.assertNotIn('codex_attempts', packet)
        self.assertEqual(packet['base_revision'], self.base)

    def test_rejects_unknown_fields_bad_revision_and_boolean_budget(self):
        for overrides in ({'shell': True}, {'base_revision': 'HEAD'}, {'local_attempts': True},
                          {'local_attempts': 3}, {'codex_attempts': 2}, {'timeout_seconds': 0},
                          {'external_ai_allowed': 'yes'}):
            with self.subTest(overrides=overrides), self.assertRaises(core.ContractError):
                self.validated(**overrides)

    def test_regression_checks_and_authority_binding_are_explicit(self):
        packet = self.validated(authorityId='hn-integration-1', regression_checks=[['python3', '-c', 'assert False']])
        self.assertEqual(packet['authorityId'], 'hn-integration-1')
        self.assertEqual(packet['regression_checks'], [['python3', '-c', 'assert False']])
        with self.assertRaises(core.ContractError):
            self.validated(regression_checks='python3 -c anything')
        with self.assertRaises(core.ContractError):
            self.validated(authorityId='../elsewhere')

    def test_paths_cannot_traverse_or_select_credentials(self):
        for path in ('../code.py', '/tmp/code.py', './src/code.py', 'src//code.py', '.env.example',
                     '.git/config', 'src/id_rsa', '.aws/config', 'src/x.pem', 'src\\code.py'):
            with self.subTest(path=path), self.assertRaises(core.ContractError):
                self.validated(allowed_paths=[path])

    def test_context_is_read_only_and_file_creation_unsupported(self):
        with self.assertRaises(core.ContractError):
            self.validated(context_files=['src/code.py'])
        with self.assertRaises(core.ContractError):
            self.validated(allowed_paths=['new.py'])
        with self.assertRaises(core.ContractError):
            self.validated(required_changed_paths=['tests/test_code.py'])

    def test_bad_checks_are_not_accepted_as_shell_strings(self):
        for checks in ('pytest', ['pytest'], [['bash', '-c', 'pytest']], [['env', 'pytest']], [[]],
                       [['pytest', 'tests\nsecret']], [[None]]):
            with self.subTest(checks=checks), self.assertRaises(core.ContractError):
                self.validated(checks=checks)

    def test_bundle_only_contains_selected_paths_and_has_no_external_switch(self):
        packet = self.validated()
        bundle = core.build_bundle(packet, self.repository)
        self.assertEqual(set(bundle['files']), {'src/code.py'})
        self.assertEqual(set(bundle['read_only_context']), {'tests/test_code.py'})
        self.assertNotIn(str(self.repository), json.dumps(bundle))
        with self.assertRaises(TypeError):
            core.build_bundle(packet, self.repository, external=True)

    def test_bundle_rejects_secret_content_and_symlinked_parent(self):
        packet = self.validated()
        (self.repository / 'src/code.py').write_text('key = "sk-' + 'a' * 30 + '"\n')
        with self.assertRaises(core.ContractError):
            core.build_bundle(packet, self.repository)
        (self.repository / 'src/code.py').unlink()
        (self.repository / 'src/code.py').symlink_to(self.repository / 'tests/test_code.py')
        with self.assertRaises(core.ContractError):
            core.build_bundle(packet, self.repository)

    def test_python_and_javascript_exact_anchor_edits(self):
        originals = {'src/code.py': 'value = 1\n', 'src/code.js': 'export const value = 1;\n'}
        changed, diff = core.validate_edits(originals, {'edits': [
            {'path': path, 'old_text': '1', 'new_text': '2'} for path in originals]})
        self.assertEqual(changed['src/code.js'], 'export const value = 2;\n')
        self.assertIn('--- a/src/code.py', diff)
        self.assertEqual(originals['src/code.py'], 'value = 1\n')

    def test_edit_validation_rejects_ambiguous_extra_fields_and_invalid_python(self):
        original = {'src/code.py': 'value = 1\n'}
        valid = {'path': 'src/code.py', 'old_text': '1', 'new_text': '2'}
        for payload in ({'edits': [valid], 'command': 'run me'}, {'edits': [{**valid, 'extra': True}]},
                        {'edits': [valid, valid]}, {'edits': [{**valid, 'new_text': '('}]},
                        {'edits': [{**valid, 'old_text': ''}]}, {'edits': [{**valid, 'path': 'new.py'}]}):
            with self.subTest(payload=payload), self.assertRaises(core.ContractError):
                core.validate_edits(original, payload)
        with self.assertRaises(core.ContractError):
            core.validate_edits({'src/code.py': 'value = 111\n'}, {'edits': [{**valid, 'old_text': '11'}]})

    def test_validates_whole_payload_before_any_write(self):
        packet = self.validated(allowed_paths=['src/code.py', 'src/code.js'])
        with patch.object(core, 'DIRECTORY', self.root):
            candidate = core.create_candidate(packet, self.root / 'validation-candidate')
        originals = core.snapshot(candidate)
        with self.assertRaises(core.ContractError):
            core.validate_and_apply(packet, candidate, {'edits': [
                {'path': 'src/code.js', 'old_text': '1', 'new_text': '2'},
                {'path': 'src/code.py', 'old_text': 'missing', 'new_text': '2'}]})
        self.assertEqual(core.snapshot(candidate), originals)

    def test_never_applies_even_valid_edits_to_original_repository(self):
        with self.assertRaises(core.ContractError):
            core.validate_and_apply(self.validated(), self.repository, {'edits': [
                {'path': 'src/code.py', 'old_text': '1', 'new_text': '2'}]})
        self.assertEqual((self.repository / 'src/code.py').read_text(), 'value = 1\n')

    def test_scope_detects_untracked_file_deletion_and_mode_change(self):
        before = core.snapshot(self.repository)
        (self.repository / 'new.txt').write_text('unexpected\n')
        (self.repository / 'src/code.py').unlink()
        (self.repository / 'src/code.js').chmod(0o755)
        result = core.inspect_scope(self.repository, before, ['src/code.py', 'src/code.js'])
        self.assertFalse(result['passed'])
        self.assertEqual(result['violations'], ['new.txt', 'src/code.js', 'src/code.py'])

    def test_sandbox_denies_network_git_and_outside_reads_and_candidate_writes(self):
        scratch = self.root / 'scratch'
        scratch.mkdir()
        state = core.build_permission_state(self.repository, ['src/code.py'], scratch)
        self.assertEqual(state['permissionProfile']['network'], 'restricted')
        entries = state['permissionProfile']['file_system']['entries']
        writes = [entry['path'].get('path') for entry in entries if entry['access'] == 'write']
        self.assertEqual(writes, [str(scratch)])
        self.assertIn({'path': {'type': 'path', 'path': str(self.repository / '.git')}, 'access': 'deny'}, entries)

    def test_checks_invoke_sandbox_with_clean_environment_and_short_circuit_failure(self):
        packet = self.validated(checks=[['python3', '-m', 'pytest'], ['ruff', 'check', '.']])
        with patch.object(core, 'run', return_value={'return_code': 1, 'duration_seconds': 0.2}) as execute:
            result = core.run_checks(packet, self.repository, self.root / 'evidence')
        self.assertFalse(result['passed'])
        self.assertEqual(execute.call_count, 1)
        self.assertTrue(execute.call_args.kwargs['pipe_output'])
        argv = execute.call_args.args[0]
        self.assertEqual(argv[:2], ['codex', 'sandbox'])
        self.assertIn('-i', argv)
        self.assertIn('PYTEST_DISABLE_PLUGIN_AUTOLOAD=1', argv)
        self.assertEqual(argv[-3:], ['python3', '-m', 'pytest'])

    def test_required_changed_path_and_whitespace_remain_gates_when_tests_pass(self):
        packet = self.validated(required_changed_paths=['src/code.py'])
        with patch.object(core, 'run', return_value={'return_code': 0, 'duration_seconds': 0.1}):
            first = core.run_checks(packet, self.repository, self.root / 'first-evidence')
        self.assertFalse(first['passed'])
        self.assertEqual(first['missing_required_changed_paths'], ['src/code.py'])
        (self.repository / 'src/code.py').write_text('value = 2  \n')
        with patch.object(core, 'run', return_value={'return_code': 0, 'duration_seconds': 0.1}):
            second = core.run_checks(packet, self.repository, self.root / 'second-evidence')
        self.assertFalse(second['passed'])
        self.assertFalse(second['diff_check']['passed'])

    def test_candidate_is_independent_and_preserves_dirty_original(self):
        packet = self.validated()
        (self.repository / 'src/code.py').write_text('user edits\n')
        before = self.git('status', '--porcelain')
        with patch.object(core, 'DIRECTORY', self.root):
            candidate = core.create_candidate(packet, self.root / 'attempt-1' / 'candidate')
        self.assertEqual((candidate / 'src/code.py').read_text(), 'value = 1\n')
        self.assertTrue((candidate / '.git').is_dir())
        self.assertFalse((candidate / '.git/objects/info/alternates').exists())
        core.validate_and_apply(packet, candidate, {'edits': [{'path': 'src/code.py', 'old_text': '1', 'new_text': '2'}]})
        self.assertEqual(self.git('status', '--porcelain'), before)
        self.assertEqual((self.repository / 'src/code.py').read_text(), 'user edits\n')

    def test_production_candidate_cannot_be_under_temp(self):
        with self.assertRaises(core.ContractError):
            core.create_candidate(self.validated(), self.root / 'candidate')


if __name__ == '__main__':
    unittest.main()
