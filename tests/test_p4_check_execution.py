from engine_types import no_start_cleanup
"""Actual checker receipts and foreground hard stops; no real providers."""
import importlib.util
import hashlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

import workflow
import workflow_core as core
import workflow_validation as validation


def summary(exit_code=1):
    return {'return_code': exit_code, 'child_exit_code': exit_code, 'timed_out': False,
            'supervisor_stop': False, 'stop_reason': 'process-exited', 'error': None,
            'duration_seconds': 0.01, 'cleanup': no_start_cleanup()}


def receipt(root, stderr, exit_code=1):
    root.mkdir()
    value = summary(exit_code)
    (root / 'summary.json').write_text(json.dumps(value))
    (root / 'stderr.log').write_text(stderr)
    return core.check_execution_receipt(value, root)


@pytest.mark.parametrize('phase', ['init_fs_encoding', 'init_import_site', 'init_sys_streams'])
def test_fatal_interpreter_bootstrap_is_not_an_executed_assertion(tmp_path, phase):
    result = receipt(tmp_path / 'check', f'Fatal Python error: {phase}: bootstrap failed\n')
    assert result['passed'] is False
    assert result['diagnostic_codes'] == ['CHECK_INTERPRETER_BOOTSTRAP_FAILED']


@pytest.mark.parametrize('stderr', [
    'AssertionError: wrong parsed setting\n',
    "ModuleNotFoundError: No module named 'application_helper'\n",
    'The documentation mentions Fatal Python error: init_fs_encoding: example\n',
])
def test_ordinary_candidate_failure_is_not_bootstrap_failure(tmp_path, stderr):
    assert receipt(tmp_path / 'check', stderr)['passed'] is True


def test_bootstrap_text_never_invalidates_successful_process_as_attestation(tmp_path):
    assert receipt(tmp_path / 'check', 'Fatal Python error: init_fs_encoding: printed prose\n', 0)['passed'] is True












def test_frozen_python_never_rebinds_to_another_explicit_interpreter(tmp_path, monkeypatch):
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'value.py').write_text('value = 1\n')
    monkeypatch.setattr(core, 'snapshot', lambda _: {})
    monkeypatch.setattr(core, 'prepare_check_command', lambda argv: (['/synthetic/python', *argv[1:]], '/synthetic/python'))
    monkeypatch.setattr(validation, '_python_runtime_plan', lambda: {'executable': Path('/different/python3')})
    start = Mock()
    monkeypatch.setattr(core, 'run', start)
    with pytest.raises(core.CheckExecutionError, match='preparation failed'):
        core.run_checks({'allowed_paths': ['value.py'], 'checks': [['python', '-c', 'pass']],
                         'timeout_seconds': 10}, candidate, tmp_path / 'evidence')
    start.assert_not_called()


@pytest.mark.parametrize('error,infrastructure', [
    ('PermissionError', True), ('OSError', True), ('ImportError', True),
    ('ModuleNotFoundError', True), ('FileNotFoundError', True),
    ('JSONDecodeError', False), ('ValueError', False), ('UnknownError', True),
])
def test_actual_builtin_report_distinguishes_infrastructure_from_bad_data(tmp_path, monkeypatch, error, infrastructure):
    monkeypatch.delenv('LOCAL_CODING_RUNTIME_POLICY', raising=False)
    monkeypatch.delenv('LOCAL_CODING_RUNTIME_POLICY_SHA256', raising=False)
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'data.json').write_text('{"status":"synthetic"}\n')
    packet = {'allowed_paths': ['data.json'], 'checks': [], 'timeout_seconds': 10,
              'validation_packs': [{'type': 'json-schema', 'path': 'data.json', 'schema': {}}]}

    def fake_process(argv, cwd, evidence, timeout, **kwargs):
        evidence.mkdir()
        result = summary(1)
        (evidence / 'summary.json').write_text(json.dumps(result))
        (evidence / 'stderr.log').write_text('')
        (evidence / 'events.jsonl').write_text(json.dumps({'passed': False, 'executed': True, 'error': error}))
        return result

    monkeypatch.setattr(validation, 'run', fake_process)
    result = validation.run_artifact_checks(packet, candidate, tmp_path / 'checks')
    assert result['passed'] is False
    assert result['checks'][0]['execution_receipt']['passed'] is (not infrastructure)
    if infrastructure:
        with pytest.raises(core.CheckExecutionError):
            workflow._require_check_execution_evidence(result)
    else:
        workflow._require_check_execution_evidence(result)


@pytest.mark.parametrize('mutate', [False, True])
def test_frozen_raw_python_uses_exact_copy_and_detects_tamper(tmp_path, monkeypatch, mutate):
    prefix = tmp_path / 'approved-python'
    binary = prefix / 'bin/python3.12'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'synthetic Python; never executed')
    binary.chmod(0o700)
    files = []
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ('os.py', 'codecs.py', 'encodings/__init__.py', 'site-packages/dummy/__init__.py'):
        path = prefix / 'lib/python3.12' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('# synthetic fixture\n')
        files.append({'path': str(path), 'sha256': sha(path)})
    policy = tmp_path / 'runtime-policy.json'
    policy.write_text(json.dumps({'schema': 'local-coding-runtime.v1',
        'executables': [{'command': 'python3', 'path': str(binary), 'sha256': sha(binary)}],
        'read_files': files}))
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY', str(policy))
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY_SHA256', sha(policy))
    monkeypatch.setenv('LOCAL_CODING_STATE_ROOT', str(tmp_path / 'state'))
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'value.py').write_text('value = 1\n')
    monkeypatch.setattr(core, '_git', lambda *args: b'')
    captured = []

    def fake_process(argv, cwd, evidence, timeout, **kwargs):
        captured.append(argv)
        state = json.loads(argv[argv.index('--sandbox-state-json') + 1])
        reads = {e['path'].get('path') for e in state['permissionProfile']['file_system']['entries']
                 if e['access'] == 'read' and e['path']['type'] == 'path'}
        runtime = evidence.parent / 'runtime'
        assert reads == {str(candidate), str(runtime), str(evidence.parent / 'command-1.json')}
        assert str(prefix) not in reads and str(binary) not in reads
        assert argv[-5:] == [str(runtime / 'python/bin/python3.12'), '-S', '-B', '-c', 'assert True']
        assert 'PYTHONHOME=' + str(runtime / 'python') in argv
        assert 'PYTHONNOUSERSITE=1' in argv
        evidence.mkdir()
        result = summary(0)
        (evidence / 'summary.json').write_text(json.dumps(result))
        (evidence / 'stderr.log').write_text('')
        if mutate:
            frozen = runtime / 'python/lib/python3.12/os.py'
            frozen.chmod(0o600)
            frozen.write_text('# altered synthetic runtime\n')
        return result

    monkeypatch.setattr(core, 'run', fake_process)
    packet = {'allowed_paths': ['value.py'], 'checks': [['python3', '-B', '-c', 'assert True']],
              'base_revision': 'a' * 40, 'timeout_seconds': 10}
    if mutate:
        with pytest.raises(core.CheckExecutionError, match='changed during execution'):
            core.run_checks(packet, candidate, tmp_path / 'checks')
    else:
        assert core.run_checks(packet, candidate, tmp_path / 'checks')['passed'] is True
    assert len(captured) == 1
    assert all(sha(Path(item['path'])) == item['sha256'] for item in files)
