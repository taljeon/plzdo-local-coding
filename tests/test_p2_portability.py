from engine_types import no_start_cleanup
"""Independent source/state and exact-runtime policy checks; no live providers."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock, patch

import pytest

import host_paths
import workflow_core as core
import workflow_validation as validation


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _policy(tmp_path, monkeypatch, *, executable=True):
    binary = tmp_path / 'python3'
    binary.write_bytes(b'synthetic runtime bytes; no execution')
    binary.chmod(0o700)
    library = tmp_path / 'runtime.dylib'
    library.write_bytes(b'synthetic library bytes')
    document = {'schema': 'local-coding-runtime.v1',
                'executables': [{'command': 'python3', 'path': str(binary), 'sha256': _digest(binary)}]
                if executable else [],
                'read_files': [{'path': str(library), 'sha256': _digest(library)}]}
    manifest = tmp_path / 'runtime-policy.json'
    manifest.write_text(json.dumps(document))
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY', str(manifest))
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY_SHA256', _digest(manifest))
    return binary, library, manifest, document


def _python_policy(tmp_path, monkeypatch):
    prefix = tmp_path / 'python-prefix'
    binary = prefix / 'bin/python3.12'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'synthetic Python runtime; never executed in fixture')
    binary.chmod(0o700)
    files = []
    for name in ('os.py', 'codecs.py', 'encodings/__init__.py', 'site-packages/dependency/__init__.py'):
        path = prefix / 'lib/python3.12' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'' if name.startswith('site-packages') else b'# synthetic standard library fixture\n')
        files.append({'path': str(path), 'sha256': _digest(path)})
    document = {'schema': 'local-coding-runtime.v1',
                'executables': [{'command': 'python3', 'path': str(binary), 'sha256': _digest(binary)}],
                'read_files': files}
    manifest = tmp_path / 'python-policy.json'
    manifest.write_text(json.dumps(document))
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY', str(manifest))
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY_SHA256', _digest(manifest))
    return binary, prefix, manifest, document


@pytest.fixture(autouse=True)
def _clean_runtime_env(monkeypatch):
    for name in ('LOCAL_CODING_RUNTIME_POLICY', 'LOCAL_CODING_RUNTIME_POLICY_SHA256',
                 'LOCAL_CODING_CONTRACT_BACKEND', 'LOCAL_CODING_LEGACY_HN_ROOT'):
        monkeypatch.delenv(name, raising=False)


def test_state_derivation_does_not_read_or_create_private_state(tmp_path, monkeypatch):
    state = tmp_path / 'not-created/state'
    monkeypatch.setenv('LOCAL_CODING_STATE_ROOT', str(state))
    with patch.object(Path, 'open', side_effect=AssertionError('private read')), \
            patch.object(Path, 'mkdir', side_effect=AssertionError('private write')), \
            patch.object(Path, 'stat', side_effect=AssertionError('private stat')):
        assert host_paths.state_root() == state
    assert not state.exists()


@pytest.mark.parametrize('value', ['relative/state', '/', '/private', '/private/tmp/../state', '/private//state'])
def test_invalid_state_roots_fail(value):
    with pytest.raises(ValueError):
        host_paths.validate_state_root(value)


def test_state_source_overlap_and_symlinks_fail(tmp_path):
    with pytest.raises(ValueError):
        host_paths.validate_state_root(host_paths.SOURCE_DIRECTORY / 'state')
    with pytest.raises(ValueError):
        host_paths.validate_state_root(host_paths.SOURCE_DIRECTORY.parent)
    real = tmp_path / 'real'
    real.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError):
        host_paths.validate_state_root(alias / 'state')


def test_state_creation_is_explicit_and_private(tmp_path):
    state = tmp_path / 'new/state'
    assert host_paths.validate_state_root(state) == state
    assert not state.exists()
    assert host_paths.ensure_state_root(state) == state
    assert state.stat().st_mode & 0o777 == 0o700


def test_shared_state_root_is_rejected(tmp_path):
    state = tmp_path / 'state'
    state.mkdir(mode=0o777)
    state.chmod(0o777)
    with pytest.raises(ValueError):
        host_paths.validate_state_root(state)




def test_default_sandbox_does_not_grant_runtime_or_user_directories(tmp_path):
    candidate, scratch = tmp_path / 'candidate', tmp_path / 'scratch'
    candidate.mkdir()
    scratch.mkdir()
    state = core.build_permission_state(candidate, [], scratch)
    profile = state['permissionProfile']
    assert profile['network'] == 'restricted'
    explicit = [item for item in profile['file_system']['entries'] if item['path']['type'] == 'path']
    assert [item['path']['path'] for item in explicit if item['access'] == 'read'] == [str(candidate)]
    assert [item['path']['path'] for item in explicit if item['access'] == 'write'] == [str(scratch)]
    assert {'path': {'type': 'path', 'path': str(candidate / '.git')}, 'access': 'deny'} in explicit


def test_exact_runtime_policy_has_no_directory_or_write_grants(tmp_path, monkeypatch):
    binary, library, _, _ = _policy(tmp_path, monkeypatch)
    entries = host_paths.runtime_read_entries()
    assert {entry['path']['path'] for entry in entries} == {str(binary), str(library)}
    assert all(entry['access'] == 'read' and entry['path']['type'] == 'path' for entry in entries)
    assert core.prepare_check_command(['python3', '-B', 'code.py']) == ([str(binary), '-B', 'code.py'], str(binary))
    with pytest.raises(core.ContractError):
        core.prepare_check_command(['/other/python3', '-B'])


def test_runtime_manifest_and_file_drift_are_hard_failures(tmp_path, monkeypatch):
    binary, _, manifest, _ = _policy(tmp_path, monkeypatch)
    binary.write_bytes(b'tampered')
    with pytest.raises(ValueError):
        host_paths.runtime_read_entries()
    manifest.write_text('{}')
    with pytest.raises(ValueError):
        host_paths.runtime_read_entries()


@pytest.mark.parametrize('relative', [
    '.aws/credentials', '.ssh/id_ed25519', '.config/service/settings.json',
    '.codex/auth.json', 'Library/Application Support/Google/Chrome/Default/Cookies',
    'Library/Safari/History.db', 'Keychains/login.keychain-db', '.env.production', '.git-credentials',
])
def test_sensitive_runtime_entries_are_rejected_before_any_runtime_read(tmp_path, monkeypatch, relative):
    binary, library, manifest, document = _policy(tmp_path, monkeypatch)
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b'synthetic private fixture; never real credentials')
    document['read_files'].append({'path': str(target), 'sha256': _digest(target)})
    manifest.write_text(json.dumps(document))
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY_SHA256', _digest(manifest))
    opened = []
    original_open = os.open

    def tracked(path, *args, **kwargs):
        opened.append(Path(path))
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(host_paths.os, 'open', tracked)
    with pytest.raises(ValueError, match='Sensitive'):
        host_paths.runtime_policy_fingerprint()
    assert target not in opened
    assert binary not in opened and library not in opened


def test_runtime_fingerprint_binds_absence_and_exact_policy_bytes(tmp_path, monkeypatch):
    assert host_paths.runtime_policy_fingerprint() is None
    _, _, manifest, document = _policy(tmp_path, monkeypatch)
    before = host_paths.runtime_policy_fingerprint()
    assert before == _digest(manifest)
    manifest.write_text(json.dumps(document, indent=2))
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY_SHA256', _digest(manifest))
    assert host_paths.runtime_policy_fingerprint() != before


def test_permission_fingerprint_tracks_validation_implementation(tmp_path, monkeypatch):
    source = tmp_path / 'local_coding' / '_engine'
    source.mkdir(parents=True)
    for relative in host_paths.PERMISSION_SOURCE_FILES:
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b'# synthetic immutable policy source\n')
    for relative in host_paths.PACKAGE_POLICY_SOURCE_FILES:
        target = source.parent / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b'# synthetic immutable package source\n')
    (tmp_path / 'bin').mkdir()
    for name in host_paths.LAUNCHER_SOURCE_FILES:
        (tmp_path / 'bin' / name).write_bytes(b'# synthetic launcher\n')
    monkeypatch.setattr(host_paths, 'SOURCE_DIRECTORY', source)
    before = host_paths.permission_policy_fingerprint()
    assert host_paths.permission_policy_fingerprint() == before
    (source / 'workflow_validation.py').write_bytes(b'# changed validation semantics\n')
    assert host_paths.permission_policy_fingerprint() != before


def test_sensitive_policy_file_is_rejected_without_opening(monkeypatch):
    with patch.object(host_paths.os, 'open', side_effect=AssertionError('must not open sensitive file')):
        with pytest.raises(ValueError, match='Sensitive'):
            host_paths.verify_trusted_file('/synthetic/.aws/credentials', 'a' * 64)


def test_runtime_directory_symlink_and_candidate_files_are_forbidden(tmp_path, monkeypatch):
    binary, library, manifest, document = _policy(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        host_paths.runtime_read_entries(forbidden_roots=(tmp_path,))
    for target in (tmp_path, tmp_path / 'alias'):
        if target.name == 'alias':
            target.symlink_to(library)
        document['read_files'][0]['path'] = str(target)
        manifest.write_text(json.dumps(document))
        monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY_SHA256', _digest(manifest))
        with pytest.raises((OSError, ValueError)):
            host_paths.runtime_read_entries()


def test_runtime_requires_explicit_manifest_digest(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY', str(tmp_path / 'policy.json'))
    with pytest.raises(ValueError):
        host_paths.runtime_read_entries()


@pytest.mark.parametrize('command', ['python3', 'python'])
def test_builtin_checks_execute_the_pinned_python_path(tmp_path, monkeypatch, command):
    binary, prefix, manifest, document = _python_policy(tmp_path, monkeypatch)
    document['executables'][0]['command'] = command
    manifest.write_text(json.dumps(document))
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY_SHA256', _digest(manifest))
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'code.py').write_text('value = 1\n')
    (candidate / 'data.json').write_text('{"value": 1}\n')
    (candidate / 'notes.md').write_text('Synthetic notes.\n')
    packet = {'allowed_paths': ['code.py', 'data.json', 'notes.md'], 'checks': [],
              'validation_packs': [{'type': 'python-syntax', 'paths': ['code.py']},
                  {'type': 'json-schema', 'path': 'data.json', 'schema': {'const': {'value': 1}}},
                  {'type': 'text', 'path': 'notes.md', 'required': ['Synthetic']}],
              'timeout_seconds': 30}

    def check(argv, cwd, evidence, timeout, **kwargs):
        spec_path = evidence.parent / ('spec-' + evidence.name.split('-')[-1] + '.json')
        spec = json.loads(spec_path.read_text())
        frozen = evidence.parent / 'runtime/python'
        assert argv[-6:] == [str(frozen / 'bin/python3.12'), '-B', '-S',
                             str(evidence.parent / 'runtime/workflow_validation.py'), '--builtin', str(spec_path)]
        assert 'PYTHONHOME=' + str(frozen) in argv and 'PYTHONNOUSERSITE=1' in argv
        assert 'PYTHONPATH=' + str(frozen / 'lib/python3.12/site-packages') in argv
        permissions = json.loads(argv[argv.index('--sandbox-state-json') + 1])
        entries = permissions['permissionProfile']['file_system']['entries']
        reads = {entry['path'].get('path') for entry in entries
                 if entry['access'] == 'read' and entry['path']['type'] == 'path'}
        assert reads == {str(candidate), str(evidence.parent / 'runtime'), str(spec_path)}
        evidence.mkdir()
        report = validation._run_builtin(spec['pack'], Path(spec['candidate']))
        (evidence / 'events.jsonl').write_text(json.dumps(report))
        summary = {'return_code': 0, 'child_exit_code': 0, 'duration_seconds': 0.01,
                   'timed_out': False, 'supervisor_stop': False,
                   'stop_reason': 'process-exited', 'error': None, 'cleanup': no_start_cleanup()}
        (evidence / 'summary.json').write_text(json.dumps(summary))
        (evidence / 'stderr.log').write_text('')
        return summary

    runner = Mock(side_effect=check)
    monkeypatch.setattr(validation, 'run', runner)
    result = validation.run_artifact_checks(packet, candidate, tmp_path / 'checks')
    assert result['passed'] is True
    assert result['checks'][0]['argv'][0] == str(tmp_path / 'checks/runtime/python/bin/python3.12')
    assert runner.call_count == 3


def test_builtin_python_policy_drift_stops_before_sandbox_execution(tmp_path, monkeypatch):
    binary, _, _, _ = _policy(tmp_path, monkeypatch)
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'code.py').write_text('value = 1\n')
    binary.write_bytes(b'changed runtime')
    runner = Mock()
    monkeypatch.setattr(validation, 'run', runner)
    with pytest.raises(core.ContractError, match='Python runtime identity'):
        validation.run_artifact_checks({'allowed_paths': ['code.py'], 'checks': [],
            'validation_packs': [{'type': 'python-syntax', 'paths': ['code.py']}],
            'timeout_seconds': 30}, candidate, tmp_path / 'checks')
    runner.assert_not_called()


def test_python_staging_copies_only_declared_bytes_and_preserves_sources(tmp_path, monkeypatch):
    binary, prefix, _, document = _python_policy(tmp_path, monkeypatch)
    unlisted = prefix / 'lib/python3.12/not-declared.py'
    unlisted.write_text('must not be exposed\n')
    sources = [Path(item['path']) for item in document['executables'] + document['read_files']] + [unlisted]
    before = {str(path): (path.read_bytes(), path.stat().st_mode) for path in sources}
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    runtime, receipt = validation._stage_runtime(evidence, python=True)
    expected = {'python/' + path.relative_to(prefix).as_posix() for path in sources if path != unlisted}
    assert {item['name'] for item in receipt if item['name'].startswith('python/')} == expected
    assert not (runtime / 'python/lib/python3.12/not-declared.py').exists()
    for item in receipt:
        path = runtime / item['name']
        assert path.read_bytes() == Path(item['source']).read_bytes()
        assert path.stat().st_mode & 0o777 == item['mode']
        assert item['mode'] == (0o500 if item['source'] == str(binary) else 0o400)
    assert before == {str(path): (path.read_bytes(), path.stat().st_mode) for path in sources}
    assert (runtime / 'python/lib/python3.12/site-packages/dependency/__init__.py').stat().st_size == 0
    validation._verify_runtime(runtime, receipt)


@pytest.mark.parametrize('fault', ['bytes', 'mode', 'file', 'directory', 'symlink'])
def test_python_recursive_frozen_closure_rejects_drift(tmp_path, monkeypatch, fault):
    _python_policy(tmp_path, monkeypatch)
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    runtime, receipt = validation._stage_runtime(evidence, python=True)
    library = runtime / 'python/lib/python3.12'
    path = library / 'os.py'
    if fault == 'bytes':
        path.chmod(0o600)
        path.write_bytes(b'changed trusted content\n')
        path.chmod(0o400)
    elif fault == 'mode':
        (runtime / 'python/bin/python3.12').chmod(0o400)
    else:
        library.chmod(0o700)
        if fault == 'file':
            (library / 'extra.py').write_text('# unexpected file\n')
        elif fault == 'directory':
            (library / 'extra').mkdir(mode=0o500)
        else:
            path.unlink()
            path.symlink_to(library / 'codecs.py')
        library.chmod(0o500)
    with pytest.raises((core.ContractError, OSError)):
        validation._verify_runtime(runtime, receipt)


@pytest.mark.parametrize('fault', ['venv', 'missing-stdlib', 'wrong-version', 'source-symlink'])
def test_python_staging_rejects_incomplete_or_external_prefixes(tmp_path, monkeypatch, fault):
    binary, prefix, manifest, document = _python_policy(tmp_path, monkeypatch)
    if fault == 'venv':
        (prefix / 'pyvenv.cfg').write_text('home = /external/python\n')
    elif fault == 'missing-stdlib':
        document['read_files'] = [item for item in document['read_files'] if not item['path'].endswith('/os.py')]
    elif fault == 'wrong-version':
        renamed = binary.with_name('python3.11')
        binary.rename(renamed)
        document['executables'][0]['path'] = str(renamed)
    else:
        source = prefix / 'lib/python3.12/os.py'
        original = prefix / 'lib/python3.12/original-os.py'
        source.rename(original)
        source.symlink_to(original)
    manifest.write_text(json.dumps(document))
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY_SHA256', _digest(manifest))
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    with pytest.raises((core.ContractError, OSError)):
        validation._stage_runtime(evidence, python=True)
    assert not (evidence / 'runtime/python').exists()


def test_python_staging_rejects_non_prefix_layout(tmp_path, monkeypatch):
    _policy(tmp_path, monkeypatch)
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    with pytest.raises(core.ContractError, match='prefix/bin/python'):
        validation._stage_runtime(evidence, python=True)


def test_frozen_helpers_include_host_paths_and_run_without_source_imports(tmp_path):
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    runtime, receipt = validation._stage_runtime(evidence)
    try:
        assert {item['name'] for item in receipt} == {
            'workflow_validation.py', 'workflow_core.py', 'run_bounded.py', 'host_paths.py',
            'json_codec.py', 'engine_types.py', 'provider_common.py'}
        state = tmp_path / 'uncreated-state'
        result = subprocess.run([sys.executable, '-B', '-c',
            'import sys,workflow_core,workflow_validation; '
            'assert not any(n.startswith("meta_harness") for n in sys.modules); print("ok")'],
            cwd=runtime, env={'PATH': '/usr/bin:/bin', 'PYTHONPATH': str(runtime),
                             'LOCAL_CODING_STATE_ROOT': str(state), 'PYTHONDONTWRITEBYTECODE': '1'},
            capture_output=True, timeout=15)
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout == b'ok\n'
        assert not state.exists()
        validation._verify_runtime(runtime, receipt)
        helper = runtime / 'host_paths.py'
        helper.chmod(0o600)
        helper.write_text('# tampered\n')
        with pytest.raises(core.ContractError):
            validation._verify_runtime(runtime, receipt)
    finally:
        runtime.chmod(0o700)








def test_model_profile_constants_remain_frozen():
    from generation_profile import resolve_profile
    value = resolve_profile('huihui-qwen38-q6kl-v1')
    assert value['model_digest'] == '4fcc84fd9a3b60b00abd3c0d5243bed154e83f9dbfb349403a1adbf7fc5e51cf'
    assert value['options']['num_ctx'] == 81920
    assert value['options']['num_predict'] == 65536


def test_repo_managed_browser_is_rejected_before_budget_candidate_or_provider(tmp_path, monkeypatch):
    import workflow
    packet = {'kind': 'repo-edit', 'allowed_paths': ['index.html'],
              'validation_packs': [{'type': 'html-browser', 'path': 'index.html', 'driver': 'managed'}]}
    monkeypatch.setattr(workflow, 'validate_packet', lambda raw: dict(raw))
    with pytest.raises(core.ContractError, match='Unsupported managed browser scope'):
        workflow.validate_task_packet(packet)
    kernel, candidate, checks = (Mock() for _ in range(3))
    monkeypatch.setattr(workflow, 'create_candidate', candidate)
    monkeypatch.setattr(workflow, 'run_checks', checks)
    with pytest.raises(core.ContractError, match='Unsupported managed browser scope'):
        workflow.run_pipeline(packet, 'run', kernel=kernel)
    assert kernel.mock_calls == []
    candidate.assert_not_called()
    checks.assert_not_called()
    assert not (tmp_path / 'run').exists()






