from engine_types import no_start_cleanup
"""Synthetic runtime bindings and sandbox-policy tests; no real Node launched."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import node_runtime_policy as policy
import workflow_core as core
import workflow_validation as validation


class NodePolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.cellar, self.opt = self.root / 'Cellar', self.root / 'opt'
        self.node = self.cellar / 'node/24.10.0/bin/node'
        self.node.parent.mkdir(parents=True)
        self.node.write_bytes(b'synthetic Node identity fixture; never executable in tests')
        self.node.chmod(0o755)
        self.binary_alias = self.root / 'bin/node'
        self.binary_alias.parent.mkdir()
        self.binary_alias.symlink_to(self.node)
        self.aliases = ('node', str(self.binary_alias), str(self.node))
        libraries = []
        for index in range(16):
            target = self.cellar / ('lib' + str(index)) / '1.0/lib/file.dylib'
            target.parent.mkdir(parents=True)
            target.write_bytes(('synthetic library ' + str(index)).encode())
            alias = self.opt / ('lib' + str(index)) / 'lib/file.dylib'
            alias.parent.mkdir(parents=True)
            alias.symlink_to(target)
            libraries.append({'alias': str(alias), 'target': str(target), 'sha256': self.hash(target)})
        self.manifest = {
            'schema': 'hn-node-exact-library-reads.v1',
            'node': {'path': str(self.node), 'sha256': self.hash(self.node), 'version': '24.10.0',
                     'command_aliases': list(self.aliases)},
            'libraries': libraries,
            'policy': {'matching_node_only': True, 'exact_file_read_only': True, 'directory_read': False,
                       'network_change': False, 'write_change': False, 'auto_refresh': False},
        }
        self.manifest_path = self.root / 'policy.json'
        self.manifest_path.write_text(json.dumps(self.manifest))
        constants = patch.multiple(policy, MANIFEST_PATH=self.manifest_path, MANIFEST_SHA256=self.hash(self.manifest_path),
                                   PINNED_NODE=self.node, COMMAND_ALIASES=self.aliases, OPT_ROOT=self.opt,
                                   CELLAR_ROOT=self.cellar, CLEAN_CHECK_PATH=str(self.binary_alias.parent))
        constants.start()
        self.addCleanup(constants.stop)
        self.candidate, self.scratch = self.root / 'candidate', self.root / 'scratch'
        self.candidate.mkdir()
        self.scratch.mkdir()
        (self.candidate / 'code.py').write_text('value = 1\n')

    @staticmethod
    def hash(path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    @staticmethod
    def fake_success(argv, cwd, evidence, timeout, **kwargs):
        evidence = Path(evidence)
        evidence.mkdir()
        summary = {'return_code': 0, 'child_exit_code': 0, 'duration_seconds': 0.01,
                   'timed_out': False, 'supervisor_stop': False,
                   'stop_reason': 'process-exited', 'error': None, 'cleanup': no_start_cleanup()}
        (evidence / 'summary.json').write_text(json.dumps(summary))
        (evidence / 'stderr.log').write_text('')
        return summary

    def test_python_default_state_is_unchanged_and_does_not_load_manifest(self):
        original = core.build_permission_state(self.candidate, ['code.py'], self.scratch)
        with patch.object(policy, '_read_manifest', side_effect=AssertionError('unexpected Node admission')):
            explicit_python = core.build_permission_state(self.candidate, ['code.py'], self.scratch,
                                                           runtime_executable=sys.executable)
            self.assertEqual(core.prepare_check_command(['python3', '-B', '-c', 'pass']),
                             (['python3', '-B', '-c', 'pass'], None))
        self.assertEqual(explicit_python, original)

    def test_exact_sixteen_literal_alias_reads_are_the_only_delta(self):
        original = core.build_permission_state(self.candidate, ['code.py'], self.scratch)
        admitted = core.build_permission_state(self.candidate, ['code.py'], self.scratch, runtime_executable=str(self.node))
        before = original['permissionProfile']['file_system']['entries']
        after = admitted['permissionProfile']['file_system']['entries']
        self.assertEqual(after[:len(before)], before)
        self.assertEqual(after[len(before):], [{'path': {'type': 'path', 'path': item['alias']}, 'access': 'read'}
                                               for item in self.manifest['libraries']])
        self.assertTrue(all(item['access'] == 'read' for item in after[len(before):]))
        self.assertEqual(admitted['permissionProfile']['network'], 'restricted')
        self.assertEqual([item for item in after if item['access'] == 'write'],
                         [item for item in before if item['access'] == 'write'])
        self.assertNotIn(str(self.opt), [item['path'].get('path') for item in after])
        self.assertIn({'path': {'type': 'path', 'path': str(self.candidate / '.git')}, 'access': 'deny'}, after)

    def test_clean_check_path_not_host_path_selects_pinned_binary(self):
        with patch.dict(os.environ, {'PATH': '/untrusted/path'}):
            argv, runtime = core.prepare_check_command(['node', '-e', 'console.log(1)'])
        self.assertEqual(argv, [str(self.node), '-e', 'console.log(1)'])
        self.assertEqual(runtime, str(self.node))
        with self.assertRaises(core.ContractError):
            core.prepare_check_command(['/unapproved/node', '-e', 'pass'])

    def test_unmatched_runtime_gets_no_additional_reads(self):
        with patch.object(policy, '_read_manifest', side_effect=AssertionError('must not read policy')):
            self.assertEqual(policy.node_readonly_entries('/other/runtime/node'), [])
            self.assertEqual(policy.node_readonly_entries(None), [])

    def test_node_binary_hash_drift_fails_before_any_grant(self):
        self.node.write_bytes(b'changed')
        with self.assertRaises(core.ContractError):
            core.build_permission_state(self.candidate, ['code.py'], self.scratch, runtime_executable=str(self.node))

    def test_node_alias_target_drift_is_rejected(self):
        other = self.root / 'different-node'
        other.write_bytes(self.node.read_bytes())
        self.binary_alias.unlink()
        self.binary_alias.symlink_to(other)
        with self.assertRaises(core.ContractError):
            core.prepare_check_command([str(self.binary_alias), '-e', 'pass'])

    def test_library_alias_target_or_bytes_drift_is_rejected(self):
        alias = Path(self.manifest['libraries'][0]['alias'])
        target = Path(self.manifest['libraries'][0]['target'])
        replacement = target.with_name('same-bytes.dylib')
        replacement.write_bytes(target.read_bytes())
        alias.unlink()
        alias.symlink_to(replacement)
        with self.assertRaises(policy.NodeRuntimePolicyError):
            policy.node_readonly_entries(str(self.node))
        alias.unlink()
        alias.symlink_to(target)
        target.write_bytes(b'changed bytes')
        with self.assertRaises(policy.NodeRuntimePolicyError):
            policy.node_readonly_entries(str(self.node))

    def test_modified_manifest_cannot_redirect_reads_to_secret_paths(self):
        changed = copy.deepcopy(self.manifest)
        changed['libraries'][0]['target'] = '/synthetic/private/.env'
        self.manifest_path.write_text(json.dumps(changed))
        with patch.object(policy, '_verify_file') as verify, self.assertRaises(policy.NodeRuntimePolicyError):
            policy.node_readonly_entries(str(self.node))
        verify.assert_not_called()

    def test_even_rehashed_test_policy_cannot_add_directories_network_or_writes(self):
        for key in ('directory_read', 'network_change', 'write_change', 'auto_refresh'):
            changed = copy.deepcopy(self.manifest)
            changed['policy'][key] = True
            self.manifest_path.write_text(json.dumps(changed))
            with self.subTest(key=key), patch.object(policy, 'MANIFEST_SHA256', self.hash(self.manifest_path)), \
                 self.assertRaises(policy.NodeRuntimePolicyError):
                policy.node_readonly_entries(str(self.node))

    def test_core_builds_a_fresh_conditional_state_per_check(self):
        packet = {'allowed_paths': ['code.py'], 'checks': [['python3', '-c', 'pass'], ['node', '-e', 'console.log(1)']],
                  'regression_checks': [], 'base_revision': 'a' * 40, 'timeout_seconds': 10}
        with patch.object(core, 'run', side_effect=self.fake_success) as run, \
             patch.object(core, '_git', return_value=b''):
            result = core.run_checks(packet, self.candidate, self.root / 'checks')
        self.assertTrue(result['passed'])
        states = [json.loads(call.args[0][call.args[0].index('--sandbox-state-json') + 1]) for call in run.call_args_list]
        alias = self.manifest['libraries'][0]['alias']
        self.assertNotIn(alias, [item['path'].get('path') for item in states[0]['permissionProfile']['file_system']['entries']])
        self.assertIn(alias, [item['path'].get('path') for item in states[1]['permissionProfile']['file_system']['entries']])
        self.assertEqual(run.call_args_list[1].args[0][-3:], [str(self.node), '-e', 'console.log(1)'])

    def test_artifact_command_passes_resolved_runtime_to_state(self):
        packet = {'allowed_paths': ['code.py'], 'checks': [['node', '-e', 'console.log(1)']],
                  'validation_packs': [], 'timeout_seconds': 10}
        with patch.object(validation, 'run', side_effect=self.fake_success) as run:
            result = validation.run_artifact_checks(packet, self.candidate, self.root / 'artifact-checks')
        self.assertTrue(result['passed'])
        argv = run.call_args.args[0]
        state = json.loads(argv[argv.index('--sandbox-state-json') + 1])
        self.assertIn(self.manifest['libraries'][0]['alias'],
                      [item['path'].get('path') for item in state['permissionProfile']['file_system']['entries']])
        self.assertEqual(argv[-3:], [str(self.node), '-e', 'console.log(1)'])

    def test_three_file_staged_python_import_does_not_need_node_policy(self):
        evidence = self.root / 'staged'
        evidence.mkdir()
        runtime, receipt = validation._stage_runtime(evidence)
        try:
            self.assertEqual({item['name'] for item in receipt}, {'workflow_validation.py', 'workflow_core.py', 'run_bounded.py', 'host_paths.py', 'json_codec.py', 'engine_types.py', 'provider_common.py'})
            outcome = subprocess.run([sys.executable, '-B', '-c',
                'import workflow_validation,workflow_core; print("staged-python-ok")'], cwd=runtime,
                env={'PYTHONPATH': str(runtime), 'PYTHONDONTWRITEBYTECODE': '1'}, capture_output=True, timeout=10)
            self.assertEqual(outcome.returncode, 0, outcome.stderr.decode())
            self.assertEqual(outcome.stdout, b'staged-python-ok\n')
            self.assertFalse((runtime / 'node_runtime_policy.py').exists())
            validation._verify_runtime(runtime, receipt)
        finally:
            runtime.chmod(0o700)


if __name__ == '__main__':
    unittest.main()
