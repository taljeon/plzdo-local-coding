import json
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import workflow_artifacts as artifacts
from workflow_core import ContractError


class ArtifactContractTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.workspace = self.root / 'local-coding'
        self.workspace.mkdir(mode=0o700)
        directory_patch = patch.object(artifacts, 'DIRECTORY', self.workspace)
        directory_patch.start()
        self.addCleanup(directory_patch.stop)
        self.raw = {'kind': 'artifact-create', 'id': 'new-artifacts',
                    'objective': 'Create the supplied artifacts using the fixed facts.',
                    'allowed_paths': ['main.py', 'data/result.json', 'docs/README.md'],
                    'generation_profile': 'huihui-qwen38-q6kl-v1', 'authorityId': 'hn-artifacts-test',
                    'facts': {'count': 2}, 'design': 'Use a small pure function.',
                    'validation_packs': [{'kind': 'text'}]}
        self.payload = {'files': [
            {'path': 'main.py', 'content': 'def count():\n    return 2\n'},
            {'path': 'data/result.json', 'content': '{"count": 2}\n'},
            {'path': 'docs/README.md', 'content': '# 결과\n\n개수는 2입니다.\n'}]}

    def packet(self, **overrides):
        return artifacts.validate_artifact_packet({**self.raw, **overrides})

    def candidate(self, packet=None, name='run-1/candidate'):
        return artifacts.create_artifact_candidate(packet or self.packet(), self.workspace / name)

    def test_normalizes_defaults_without_mutating_input(self):
        result = self.packet()
        self.assertEqual((result['local_attempts'], result['timeout_seconds']), (2, 180))
        self.assertNotIn('codex_attempts', result)
        self.assertEqual(result['checks'], [])
        self.assertNotIn('checks', self.raw)
        result['facts']['count'] = 20
        self.assertEqual(self.raw['facts']['count'], 2)

    def test_requires_checks_or_packs_and_rejects_repository_fields(self):
        for overrides in ({'checks': [], 'validation_packs': []}, {'repository': '/tmp/project'},
                          {'base_revision': 'a' * 40}, {'kind': 'repo-edit'}, {'unlisted': True}):
            with self.subTest(overrides=overrides), self.assertRaises(ContractError):
                self.packet(**overrides)

    def test_limits_and_types_are_strict(self):
        for overrides in ({'local_attempts': 3}, {'local_attempts': True}, {'codex_attempts': 2},
                          {'timeout_seconds': 9}, {'timeout_seconds': 1801},
                          {'external_ai_allowed': 'yes'}, {'facts': []}, {'design': {}},
                          {'validation_packs': 'text'}, {'risk': 'anything'},
                          {'authorityId': '../contract'}):
            with self.subTest(overrides=overrides), self.assertRaises(ContractError):
                self.packet(**overrides)

    def test_path_contract_rejects_traversal_auth_and_collisions(self):
        bad = [['../out.py'], ['/tmp/out.py'], ['.git/config'], ['data/.env.example'], ['id_ed25519'],
               ['a.py', 'a.py'], ['Data/a.py', 'data/b.py'], ['a.py', 'A.py'],
               ['file', 'file/item.py'], ['caf\u00e9.md', 'cafe\u0301.md'], ['x//y.py']]
        for paths in bad:
            with self.subTest(paths=paths), self.assertRaises(ContractError):
                self.packet(allowed_paths=paths)

    def test_no_shell_string_checks(self):
        for checks in (['python3 -m pytest'], [['sh', '-c', 'anything']], [[]], [['python3', 'x\ny']]):
            with self.subTest(checks=checks), self.assertRaises(ContractError):
                self.packet(checks=checks)

    def test_facts_reject_non_json_nan_cycles_and_secrets(self):
        cycle = {}
        cycle['self'] = cycle
        for facts in ({'x': float('nan')}, {1: 'one'}, {'x': b'bytes'}, cycle,
                      {'api_key': 'sk-' + 'a' * 30}):
            with self.subTest(fact_type=type(facts)), self.assertRaises(ContractError):
                self.packet(facts=facts)

    def test_schema_and_bundle_are_scoped_data_only(self):
        packet = self.packet()
        schema = artifacts.artifact_schema(packet['allowed_paths'])
        self.assertEqual(schema['properties']['files']['minItems'], 3)
        self.assertEqual(schema['properties']['files']['maxItems'], 3)
        self.assertFalse(schema['additionalProperties'])
        bundle = artifacts.build_artifact_bundle(packet)
        self.assertEqual(bundle['facts'], {'count': 2})
        self.assertEqual(bundle['design'], self.raw['design'])
        self.assertEqual(bundle['checks'], [])
        self.assertEqual(bundle['validation_packs'], [{'kind': 'text'}])
        self.assertNotIn('repository', bundle)
        self.assertNotIn('authorityId', bundle)
        self.assertNotIn(str(self.workspace), json.dumps(bundle))

    def test_creates_empty_git_free_candidate_with_task_ownership(self):
        candidate = self.candidate()
        self.assertEqual(list(candidate.iterdir()), [])
        self.assertFalse((candidate / '.git').exists())
        self.assertTrue((candidate.parent / '.candidate.artifact-owner.json').is_file())
        with self.assertRaises(ContractError):
            self.candidate()

    def test_candidate_creation_rejects_outside_workspace_and_symlink_parents(self):
        outside = self.root / 'outside'
        outside.mkdir()
        with self.assertRaises(ContractError):
            artifacts.create_artifact_candidate(self.packet(), outside / 'candidate')
        (self.workspace / 'alias').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ContractError):
            self.candidate(name='alias/candidate')
        self.assertEqual(list(outside.iterdir()), [])

    def test_validate_new_files_returns_sorted_utf8_bytes(self):
        files = artifacts.validate_new_files(self.packet(), self.payload)
        self.assertEqual(list(files), ['data/result.json', 'docs/README.md', 'main.py'])
        self.assertEqual(files['docs/README.md'].decode(), '# 결과\n\n개수는 2입니다.\n')
        self.assertTrue(all(isinstance(value, bytes) for value in files.values()))

    def test_unicode_paths_and_text_survive_exact_creation(self):
        packet = self.packet(allowed_paths=['결과/요약.md'])
        candidate = self.candidate(packet)
        payload = {'files': [{'path': '결과/요약.md', 'content': '# 결과\n\n완료\n'}]}
        artifacts.apply_new_files(packet, candidate, payload)
        self.assertEqual((candidate / '결과/요약.md').read_bytes(), '# 결과\n\n완료\n'.encode('utf-8'))
        self.assertTrue(artifacts.inspect_artifact_scope(packet, candidate)['passed'])

    def test_korean_artifact_in_actual_workspace_has_exact_ownership_receipts(self):
        """Exercise the production boundary in owned private state, not installed source."""
        real_workspace = self.workspace
        packet = self.packet(allowed_paths=['자료/요약.md'])
        content = '# 자료 요약\n\n확정된 개수: 2\n'
        with tempfile.TemporaryDirectory(prefix='.artifact-unicode-check-', dir=real_workspace) as stage:
            with patch.object(artifacts, 'DIRECTORY', real_workspace):
                candidate = artifacts.create_artifact_candidate(packet, Path(stage) / 'candidate')
                owner = json.loads((candidate.parent / '.candidate.artifact-owner.json').read_text())
                info = candidate.stat()
                self.assertEqual((owner['device'], owner['inode']), (info.st_dev, info.st_ino))
                self.assertEqual(owner['candidate'], str(candidate))
                artifacts.apply_new_files(packet, candidate,
                    {'files': [{'path': '자료/요약.md', 'content': content}]})
                self.assertEqual((candidate / '자료/요약.md').read_bytes(), content.encode('utf-8'))
                scope = artifacts.inspect_artifact_scope(packet, candidate)
                expected = {'자료/요약.md': {'sha256': hashlib.sha256(content.encode('utf-8')).hexdigest(),
                                           'bytes': len(content.encode('utf-8'))}}
                manifest = json.loads((candidate.parent / '.candidate.artifact-output.json').read_text())
                self.assertTrue(scope['passed'])
                self.assertEqual(scope['snapshot'], expected)
                self.assertEqual(manifest, expected)
                self.assertEqual(scope['changed_paths'], ['자료/요약.md'])
                self.assertEqual(scope['violations'], [])
                self.assertFalse((candidate / '.git').exists())

    def test_payload_requires_every_exact_path_and_no_extra_fields(self):
        for payload in ({'files': self.payload['files'][:2]}, {'files': self.payload['files'] + self.payload['files'][:1]},
                        {'files': self.payload['files'], 'command': 'run something'},
                        {'files': [self.payload['files'][0]] * 3},
                        {'files': [{**self.payload['files'][0], 'mode': 'create'}, *self.payload['files'][1:]]},
                        {'files': [{**self.payload['files'][0], 'path': 'Main.py'}, *self.payload['files'][1:]]}):
            with self.subTest(payload=payload), self.assertRaises(ContractError):
                artifacts.validate_new_files(self.packet(), payload)

    def test_payload_rejects_invalid_python_strict_json_and_bad_text(self):
        invalid = [('main.py', 'def broken(:\n'), ('data/result.json', '{"x": 1, "x": 2}\n'),
                   ('data/result.json', '{"value": NaN}\n'), ('docs/README.md', 'no final newline'),
                   ('docs/README.md', 'bad\r\n'), ('docs/README.md', '\0\n'),
                   ('docs/README.md', '\ud800\n'), ('docs/README.md', 'sk-' + 'a' * 30 + '\n')]
        for relative, content in invalid:
            payload = {'files': [{**entry, 'content': content} if entry['path'] == relative else entry
                                 for entry in self.payload['files']]}
            with self.subTest(relative=relative), self.assertRaises(ContractError):
                artifacts.validate_new_files(self.packet(), payload)

    def test_byte_caps_count_utf8_bytes_not_characters(self):
        packet = self.packet(allowed_paths=['notes.md'])
        with self.assertRaises(ContractError):
            artifacts.validate_new_files(packet, {'files': [{'path': 'notes.md', 'content': '가' * 30000 + '\n'}]})
        paths = ['part' + str(index) + '.md' for index in range(5)]
        packet = self.packet(allowed_paths=paths)
        with self.assertRaises(ContractError):
            artifacts.validate_new_files(packet, {'files': [{'path': path, 'content': 'x' * 65535 + '\n'} for path in paths]})

    def test_full_validation_precedes_any_file_or_manifest_write(self):
        candidate = self.candidate()
        invalid = {'files': [*self.payload['files'][:2], {'path': 'docs/README.md', 'content': 'bad final line'}]}
        with self.assertRaises(ContractError):
            artifacts.apply_new_files(self.packet(), candidate, invalid)
        self.assertEqual(list(candidate.iterdir()), [])
        self.assertFalse((candidate.parent / '.candidate.artifact-output.json').exists())

    def test_no_overwrite_or_prepopulated_directory_even_for_allowed_file(self):
        candidate = self.candidate()
        (candidate / 'main.py').write_text('keep me\n')
        with self.assertRaises(ContractError):
            artifacts.apply_new_files(self.packet(), candidate, self.payload)
        self.assertEqual((candidate / 'main.py').read_text(), 'keep me\n')
        self.assertEqual(sorted(path.name for path in candidate.iterdir()), ['main.py'])

    def test_prepopulated_symlink_never_touches_its_target(self):
        candidate = self.candidate()
        secret_canary = self.root / 'canary'
        secret_canary.write_text('untouched\n')
        (candidate / 'main.py').symlink_to(secret_canary)
        with self.assertRaises(ContractError):
            artifacts.apply_new_files(self.packet(), candidate, self.payload)
        self.assertEqual(secret_canary.read_text(), 'untouched\n')

    def test_empty_but_unowned_directory_cannot_be_used(self):
        candidate = self.workspace / 'unowned'
        candidate.mkdir()
        with self.assertRaises((ContractError, FileNotFoundError)):
            artifacts.apply_new_files(self.packet(), candidate, self.payload)
        self.assertEqual(list(candidate.iterdir()), [])

    def test_packet_and_directory_identity_are_bound(self):
        candidate = self.candidate()
        with self.assertRaises(ContractError):
            artifacts.apply_new_files(self.packet(objective='Different task'), candidate, self.payload)
        moved = candidate.with_name('old-candidate')
        candidate.rename(moved)
        candidate.mkdir()
        with self.assertRaises(ContractError):
            artifacts.apply_new_files(self.packet(), candidate, self.payload)
        self.assertEqual(list(candidate.iterdir()), [])

    def test_success_creates_all_files_with_exclusive_no_follow_opens(self):
        candidate = self.candidate()
        original_open = os.open
        calls = []
        def observe(path, flags, *args, **kwargs):
            calls.append((path, flags, kwargs.get('dir_fd')))
            return original_open(path, flags, *args, **kwargs)
        with patch.object(artifacts.os, 'open', side_effect=observe):
            result = artifacts.apply_new_files(self.packet(), candidate, self.payload)
        self.assertEqual(result['changed_paths'], sorted(self.raw['allowed_paths']))
        self.assertIn('--- /dev/null', result['patch'])
        self.assertIn('+++ b/main.py', result['patch'])
        for relative in self.raw['allowed_paths']:
            self.assertEqual(stat.S_IMODE((candidate / relative).stat().st_mode), 0o600)
        writes = [call for call in calls if call[1] & os.O_CREAT]
        self.assertTrue(writes)
        self.assertTrue(all(flags & os.O_EXCL and flags & os.O_NOFOLLOW and fd is not None for _, flags, fd in writes))
        self.assertTrue(artifacts.inspect_artifact_scope(self.packet(), candidate)['passed'])
        with self.assertRaises(ContractError):
            artifacts.apply_new_files(self.packet(), candidate, self.payload)

    def test_scope_detects_missing_extra_modes_and_content_drift(self):
        candidate = self.candidate()
        artifacts.apply_new_files(self.packet(), candidate, self.payload)
        (candidate / 'main.py').write_text('value = 999\n')
        (candidate / 'docs/README.md').chmod(0o755)
        (candidate / 'data/result.json').unlink()
        (candidate / 'unexpected-directory').mkdir()
        result = artifacts.inspect_artifact_scope(self.packet(), candidate)
        self.assertFalse(result['passed'])
        self.assertEqual(result['violations'], ['data/result.json', 'docs/README.md', 'main.py', 'unexpected-directory'])

    def test_scope_rejects_symlinks_and_hardlinks_without_following_them(self):
        candidate = self.candidate()
        artifacts.apply_new_files(self.packet(), candidate, self.payload)
        (candidate / 'main.py').unlink()
        (candidate / 'main.py').symlink_to(self.root / 'absent-outside')
        os.link(candidate / 'docs/README.md', self.root / 'outside-link')
        result = artifacts.inspect_artifact_scope(self.packet(), candidate)
        self.assertFalse(result['passed'])
        self.assertIn('main.py', result['violations'])
        self.assertIn('docs/README.md', result['violations'])


if __name__ == '__main__':
    unittest.main()
