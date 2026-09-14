"""Custom Python check boundaries with synthetic runtime bytes; no sandbox calls."""
import hashlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from engine_types import no_start_cleanup
import workflow_core as core
import workflow_validation as validation


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _save_policy(manifest, document, monkeypatch):
    manifest.write_text(json.dumps(document))
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY', str(manifest))
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY_SHA256', _digest(manifest))


@pytest.fixture
def custom_check(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCAL_CODING_STATE_ROOT', str(tmp_path / 'state'))
    for name in ('LOCAL_CODING_CONTRACT_BACKEND', 'LOCAL_CODING_LEGACY_HN_ROOT'):
        monkeypatch.delenv(name, raising=False)
    prefix = tmp_path / 'python-prefix'
    binary = prefix / 'bin/python3.12'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'synthetic Python; must never be executed')
    binary.chmod(0o700)
    reads = []
    for name in ('os.py', 'codecs.py', 'encodings/__init__.py'):
        path = prefix / 'lib/python3.12' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('# synthetic standard library\n')
        reads.append({'path': str(path), 'sha256': _digest(path)})
    checker = tmp_path / 'check-files/check.py'
    checker.parent.mkdir()
    checker.write_text('# immutable host checker fixture\n')
    checker.chmod(0o400)
    reads.append({'path': str(checker), 'sha256': _digest(checker)})
    unlisted = checker.with_name('unlisted.py')
    unlisted.write_text('# must not be granted\n')
    unused = checker.with_name('unused.json')
    unused.write_text('{"unused":true}\n')
    reads.append({'path': str(unused), 'sha256': _digest(unused)})
    other = tmp_path / 'other-runtime'
    other.write_text('synthetic other executable; never executed\n')
    other.chmod(0o700)
    document = {'schema': 'local-coding-runtime.v1', 'read_files': reads,
                'executables': [{'command': 'python3', 'path': str(binary), 'sha256': _digest(binary)},
                                {'command': 'other-runtime', 'path': str(other), 'sha256': _digest(other)}]}
    manifest = tmp_path / 'runtime-policy.json'
    _save_policy(manifest, document, monkeypatch)
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'code.py').write_text('value = 1\n')
    packet = {'allowed_paths': ['code.py'], 'checks': [['python3', '-I', '-S', '-B', str(checker)]],
              'validation_packs': [], 'timeout_seconds': 30}
    return {'prefix': prefix, 'binary': binary, 'checker': checker, 'unlisted': unlisted, 'unused': unused,
            'other': other, 'manifest': manifest, 'document': document,
            'candidate': candidate, 'packet': packet}


def _complete(evidence, report=None):
    evidence.mkdir()
    if report is not None:
        (evidence / 'events.jsonl').write_text(json.dumps(report) + '\n')
    summary = {'return_code': 0, 'child_exit_code': 0, 'duration_seconds': 0.01,
               'timed_out': False, 'supervisor_stop': False,
               'stop_reason': 'process-exited', 'error': None, 'cleanup': no_start_cleanup()}
    (evidence / 'summary.json').write_text(json.dumps(summary))
    (evidence / 'stderr.log').write_text('')
    return summary


@pytest.mark.parametrize('with_builtin', [False, True])
def test_custom_python_stages_without_changing_flags_or_expanding_reads(
        tmp_path, monkeypatch, custom_check, with_builtin):
    case = custom_check
    if with_builtin:
        case['packet']['validation_packs'] = [{'type': 'python-syntax', 'paths': ['code.py']}]
    source_before = {item['path']: (Path(item['path']).read_bytes(), Path(item['path']).stat().st_mode)
                     for item in case['document']['executables'] + case['document']['read_files']}

    def check(argv, cwd, evidence, timeout, **kwargs):
        assert kwargs['pipe_output'] is True and timeout > 0
        assert cwd == case['candidate']
        state = json.loads(argv[argv.index('--sandbox-state-json') + 1])
        assert state['permissionProfile']['network'] == 'restricted'
        entries = state['permissionProfile']['file_system']['entries']
        assert [entry['path']['path'] for entry in entries if entry['access'] == 'write'] == [
            str(evidence.parent / 'scratch')]
        reads = {entry['path']['path'] for entry in entries
                 if entry['access'] == 'read' and entry['path']['type'] == 'path'}
        runtime = evidence.parent / 'runtime'
        spec_path = evidence.parent / ('spec-' + evidence.name.split('-')[-1] + '.json')
        spec = json.loads(spec_path.read_text())
        expected = {str(case['candidate']), str(runtime), str(spec_path)}
        if spec['pack'] is None:
            assert argv[-5:] == [str(runtime / 'python/bin/python3.12'),
                                  *case['packet']['checks'][0][1:4], str(runtime / 'check-files/1/check.py')]
            assert not any(arg.startswith(('PYTHONHOME=', 'PYTHONPATH=')) for arg in argv)
        else:
            assert 'PYTHONHOME=' + str(runtime / 'python') in argv
        assert reads == expected
        assert str(case['checker'].parent) not in reads
        assert all(str(case[name]) not in reads for name in ('prefix', 'binary', 'checker', 'other', 'unlisted', 'unused'))
        assert (runtime / 'python/bin/python3.12').read_bytes() == case['binary'].read_bytes()
        assert (runtime / 'python/bin/python3.12').stat().st_mode & 0o777 == 0o500
        assert (runtime / 'python/lib/python3.12/encodings/__init__.py').is_file()
        frozen_checker = runtime / 'check-files/1/check.py'
        assert frozen_checker.read_bytes() == case['checker'].read_bytes()
        assert frozen_checker.stat().st_mode & 0o777 == 0o400
        receipt = json.loads((evidence.parent / 'runtime-receipt.json').read_text())
        assert [item['source'] for item in receipt['files'] if item['name'].startswith('check-files/')] == [
            str(case['checker'])]
        return _complete(evidence, validation._run_builtin(spec['pack'], cwd) if spec['pack'] else None)

    runner = Mock(side_effect=check)
    monkeypatch.setattr(validation, 'run', runner)
    result = validation.run_artifact_checks(case['packet'], case['candidate'], tmp_path / 'checks')
    assert result['passed'] is True
    assert runner.call_count == 1 + int(with_builtin)
    record = result['checks'][0]
    mapping = record['python_runtime']
    assert record['argv'][1:4] == case['packet']['checks'][0][1:4]
    assert mapping['declared_executable'] == 'python3'
    assert mapping['source_executable'] == str(case['binary'])
    assert mapping['source_sha256'] == _digest(case['binary'])
    assert mapping['staged_executable'] == record['argv'][0]
    assert mapping['runtime_policy_path'] == str(case['manifest'])
    assert mapping['runtime_policy_sha256'] == _digest(case['manifest'])
    assert mapping['file_arguments'] == [{'argv_index': 4, 'source_path': str(case['checker']),
        'source_sha256': _digest(case['checker']), 'staged_path': record['argv'][4]}]
    assert record['argv'][4] == str(tmp_path / 'checks/runtime/check-files/1/check.py')
    assert source_before == {path: (Path(path).read_bytes(), Path(path).stat().st_mode) for path in source_before}
    if with_builtin:
        assert 'python_runtime' not in result['checks'][1]


def test_custom_python_refuses_a_different_declared_interpreter(tmp_path, monkeypatch, custom_check):
    case = custom_check
    other = tmp_path / 'other-prefix/bin/python'
    other.parent.mkdir(parents=True)
    other.write_text('different synthetic interpreter\n')
    other.chmod(0o700)
    case['document']['executables'].append({'command': 'python', 'path': str(other), 'sha256': _digest(other)})
    _save_policy(case['manifest'], case['document'], monkeypatch)
    case['packet']['checks'][0][0] = 'python'
    runner = Mock()
    monkeypatch.setattr(validation, 'run', runner)
    with pytest.raises(core.ContractError, match='custom Python executable differs'):
        validation.run_artifact_checks(case['packet'], case['candidate'], tmp_path / 'checks')
    runner.assert_not_called()


@pytest.mark.parametrize('fault', ['policy-bytes', 'repinned-closure', 'checker-bytes', 'repinned-checker', 'staged-checker'])
def test_custom_python_rejects_drift_between_staging_and_execution(
        tmp_path, monkeypatch, custom_check, fault):
    case = custom_check
    stage = validation._stage_runtime

    def changed_stage(*args, **kwargs):
        result = stage(*args, **kwargs)
        if fault == 'policy-bytes':
            case['manifest'].write_text('{}')
        elif fault in ('repinned-closure', 'repinned-checker'):
            source = case['prefix'] / 'lib/python3.12/os.py' if fault == 'repinned-closure' else case['checker']
            source.chmod(0o600)
            source.write_text('# changed source after staging\n')
            for item in case['document']['read_files']:
                if item['path'] == str(source):
                    item['sha256'] = _digest(source)
            _save_policy(case['manifest'], case['document'], monkeypatch)
        elif fault == 'staged-checker':
            source = result[0] / 'check-files/1/check.py'
            source.chmod(0o600)
            source.write_text('# changed frozen checker\n')
            source.chmod(0o400)
        else:
            case['checker'].chmod(0o600)
            case['checker'].write_text('# changed checker after staging\n')
        return result

    runner = Mock()
    monkeypatch.setattr(validation, '_stage_runtime', changed_stage)
    monkeypatch.setattr(validation, 'run', runner)
    with pytest.raises(core.ContractError, match='Runtime identity: custom|Trusted validation runtime changed'):
        validation.run_artifact_checks(case['packet'], case['candidate'], tmp_path / 'checks')
    runner.assert_not_called()


@pytest.mark.parametrize('fault', ['checker', 'staged-python', 'staged-checker', 'candidate'])
def test_custom_python_cannot_accept_drift_after_check(tmp_path, monkeypatch, custom_check, fault):
    case = custom_check

    def changed_check(argv, cwd, evidence, timeout, **kwargs):
        if fault == 'checker':
            changed = case['checker']
        elif fault == 'staged-python':
            changed = evidence.parent / 'runtime/python/lib/python3.12/os.py'
        elif fault == 'staged-checker':
            changed = evidence.parent / 'runtime/check-files/1/check.py'
        else:
            changed = cwd / 'code.py'
        changed.chmod(0o600)
        changed.write_text('# changed during mocked check\n')
        if fault != 'candidate':
            changed.chmod(0o400)
        return _complete(evidence)

    runner = Mock(side_effect=changed_check)
    monkeypatch.setattr(validation, 'run', runner)
    if fault == 'candidate':
        result = validation.run_artifact_checks(case['packet'], case['candidate'], tmp_path / 'checks')
        assert result['passed'] is False
        assert result['scope']['changed_paths'] == ['code.py']
        assert result['scope']['passed'] is False
    else:
        expected = 'declared checker/data file changed' if fault == 'checker' else 'Trusted validation runtime changed'
        with pytest.raises(core.ContractError, match=expected):
            validation.run_artifact_checks(case['packet'], case['candidate'], tmp_path / 'checks')
    assert runner.call_count == 1


def test_exact_file_arguments_are_deduplicated_and_other_tokens_preserved(tmp_path, monkeypatch, custom_check):
    case = custom_check
    data = tmp_path / 'data/example.json'
    data.parent.mkdir()
    data.write_text('{"expected":42}\n')
    case['document']['read_files'].append({'path': str(data), 'sha256': _digest(data)})
    _save_policy(case['manifest'], case['document'], monkeypatch)
    original = ['python3', '-I', '-S', '-B', '--', str(case['checker']), '--input', str(data),
                '--label=' + str(data), 'literal ' + str(data), str(data)]
    case['packet']['checks'] = [original]
    monkeypatch.setattr(validation, 'run', lambda argv, cwd, evidence, timeout, **kwargs: _complete(evidence))
    result = validation.run_artifact_checks(case['packet'], case['candidate'], tmp_path / 'checks')
    assert result['passed'] is True
    record = result['checks'][0]
    mappings = record['python_runtime']['file_arguments']
    assert [item['argv_index'] for item in mappings] == [5, 7, 10]
    assert mappings[1]['source_path'] == mappings[2]['source_path'] == str(data)
    assert mappings[1]['source_sha256'] == mappings[2]['source_sha256'] == _digest(data)
    assert mappings[1]['staged_path'] == mappings[2]['staged_path']
    restored = list(record['argv'])
    restored[0] = record['python_runtime']['declared_executable']
    for item in mappings:
        assert Path(item['staged_path']).read_bytes() == Path(item['source_path']).read_bytes()
        restored[item['argv_index']] = item['source_path']
    assert restored == original
    assert record['argv'][8:10] == original[8:10]
    receipt = json.loads(Path(result['runtime_receipt']).read_text())
    assert [item['source'] for item in receipt['files'] if item['name'].startswith('check-files/')] == [
        str(case['checker']), str(data)]


@pytest.mark.parametrize('arguments', [
    ['-c', '{checker}'], ['-m', '{checker}'], ['-W', '{checker}'],
    ['-X', 'utf8', '{checker}'], ['-ISB', '{checker}'], ['relative.py', '{checker}']])
def test_ambiguous_file_mapping_context_is_rejected_before_staging(
        tmp_path, monkeypatch, custom_check, arguments):
    case = custom_check
    case['packet']['checks'] = [['python3', *[value.replace('{checker}', str(case['checker'])) for value in arguments]]]
    runner = Mock()
    monkeypatch.setattr(validation, 'run', runner)
    with pytest.raises(core.ContractError, match='code/module/option contexts are unsupported'):
        validation.run_artifact_checks(case['packet'], case['candidate'], tmp_path / 'checks')
    runner.assert_not_called()
    assert not (tmp_path / 'checks').exists()


def test_inline_code_is_never_rewritten_or_used_to_discover_files(tmp_path, monkeypatch, custom_check):
    case = custom_check
    code = 'print(' + repr(str(case['checker'])) + ')'
    original = ['python3', '-I', '-S', '-B', '-c', code]
    case['packet']['checks'] = [original]
    monkeypatch.setattr(validation, 'run', lambda argv, cwd, evidence, timeout, **kwargs: _complete(evidence))
    result = validation.run_artifact_checks(case['packet'], case['candidate'], tmp_path / 'checks')
    assert result['checks'][0]['argv'][1:] == original[1:]
    assert result['checks'][0]['python_runtime']['file_arguments'] == []
    receipt = json.loads(Path(result['runtime_receipt']).read_text())
    assert not any(item['name'].startswith('check-files/') for item in receipt['files'])


def test_staging_cannot_add_an_unadmitted_file(tmp_path, monkeypatch, custom_check):
    case = custom_check
    evidence = tmp_path / 'checks'
    evidence.mkdir()
    with pytest.raises(core.ContractError, match='custom check files were not admitted'):
        validation._stage_runtime(evidence, python=True,
            check_files=[{'path': str(case['unlisted']), 'sha256': _digest(case['unlisted'])}])
    assert not (evidence / 'runtime/check-files').exists()


def test_multiple_commands_reuse_the_same_file_and_existing_python_copy(tmp_path, monkeypatch, custom_check):
    case = custom_check
    library = case['prefix'] / 'lib/python3.12/os.py'
    case['packet']['regression_checks'] = [['python3', '-S', str(case['checker']), str(library)]]
    mock_run = Mock(side_effect=lambda argv, cwd, evidence, timeout, **kwargs: _complete(evidence))
    monkeypatch.setattr(validation, 'run', mock_run)
    result = validation.run_artifact_checks(case['packet'], case['candidate'], tmp_path / 'checks')
    assert result['passed'] is True and mock_run.call_count == 2
    first, second = result['checks']
    assert first['argv'][4] == second['argv'][2]
    assert second['argv'][1] == '-S'
    assert second['argv'][3] == str(tmp_path / 'checks/runtime/python/lib/python3.12/os.py')
    assert [item['argv_index'] for item in second['python_runtime']['file_arguments']] == [2, 3]
    receipt = json.loads(Path(result['runtime_receipt']).read_text())
    assert sum(item['source'] == str(library) for item in receipt['files']) == 1
    assert sum(item['source'] == str(case['checker']) for item in receipt['files']) == 1


def test_original_file_is_reverified_immediately_before_execution(tmp_path, monkeypatch, custom_check):
    case = custom_check
    state = validation._state

    def changed_state(*args, **kwargs):
        result = state(*args, **kwargs)
        case['checker'].chmod(0o600)
        case['checker'].write_text('# changed after permission preparation\n')
        case['checker'].chmod(0o400)
        return result

    mock_run = Mock()
    monkeypatch.setattr(validation, '_state', changed_state)
    monkeypatch.setattr(validation, 'run', mock_run)
    with pytest.raises(core.ContractError, match='declared checker/data file changed'):
        validation.run_artifact_checks(case['packet'], case['candidate'], tmp_path / 'checks')
    mock_run.assert_not_called()
