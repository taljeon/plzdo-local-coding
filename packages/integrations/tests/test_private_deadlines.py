"""Injected clocks and process doubles only; never launch a provider or Git."""
from pathlib import Path
import hashlib
import json
import os
import shutil

import pytest

from local_coding.api import Work, EngineFailure, canonical_bytes, no_start_cleanup
from plzdo_private_overlay import engines, transports, grok_admission


def engine_and_work(tmp_path, engine_id='codex-openai', *, timeout=30):
    binary = tmp_path / 'fixture-provider'
    binary.write_bytes(b'fixture binary; never execute\n')
    binary.chmod(0o700)
    pin = {'path': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
    operation = 'generate' if engine_id == 'codex-openai' else 'review'
    schema = (grok_admission.GROK_SCHEMA if engine_id == 'grok-cli' else
              transports.REVIEW_SCHEMA if engine_id == 'claude' else {'type': 'object'})
    work = Work(operation, canonical_bytes('Synthetic private work'), canonical_bytes(schema),
                canonical_bytes({}), timeout, tmp_path / 'evidence', 'fixture-reservation')
    return engines.ExternalEngine(engine_id, canonical_bytes(pin)), work


def fake_clock(monkeypatch, work):
    clock = [work.deadline_monotonic - work.timeout_seconds]
    monkeypatch.setattr(transports, 'monotonic', lambda: clock[0])
    return clock


def process_result(destination, stdout):
    destination = Path(destination)
    destination.mkdir(parents=True)
    (destination / 'events.jsonl').write_bytes(stdout)
    (destination / 'stderr.log').write_bytes(b'')
    return {'return_code': 0, 'child_exit_code': 0, 'timed_out': False, 'error': None,
            'cleanup': {'schema': 'plzdo.engine-cleanup.v1', 'completed': True,
                        'passed': True, 'owned': True, 'started': True,
                        'scope': 'initial-posix-process-group'}}


def codex_result(argv, destination):
    payload = {}
    Path(argv[argv.index('--output-last-message') + 1]).write_bytes(canonical_bytes(payload))
    events = [{'type': 'turn.started'}, {'type': 'item.completed',
               'item': {'type': 'agent_message', 'text': json.dumps(payload)}}, {'type': 'turn.completed'}]
    return process_result(destination, ('\n'.join(json.dumps(row) for row in events) + '\n').encode())


def test_expired_work_never_restarts_a_budget_at_engine_entry(tmp_path, monkeypatch):
    engine, work = engine_and_work(tmp_path)
    clock = fake_clock(monkeypatch, work)
    clock[0] = work.deadline_monotonic
    monkeypatch.setattr(engines.ExternalEngine, 'identity', lambda self: pytest.fail('identity after expiry'))
    monkeypatch.setattr(transports, 'run_bounded', lambda *args, **kw: pytest.fail('process after expiry'))
    with pytest.raises(EngineFailure, match='deadline exhausted') as failure:
        engine.execute(work)
    assert failure.value.cleanup == no_start_cleanup()
    assert not work.evidence_dir.exists()


@pytest.mark.parametrize('engine_id', ['codex-openai', 'claude', 'grok-cli'])
def test_identity_delay_exhausts_all_external_work_before_any_process(tmp_path, monkeypatch, engine_id):
    engine, work = engine_and_work(tmp_path, engine_id)
    clock = fake_clock(monkeypatch, work)
    original = engines.ExternalEngine.identity
    def delayed(self):
        identity = original(self)
        clock[0] = work.deadline_monotonic
        return identity
    monkeypatch.setattr(engines.ExternalEngine, 'identity', delayed)
    monkeypatch.setattr(transports, 'run_bounded', lambda *args, **kw: pytest.fail('process after hash deadline'))
    with pytest.raises(EngineFailure, match='deadline exhausted') as failure:
        engine.execute(work)
    assert failure.value.cleanup == no_start_cleanup()


@pytest.mark.parametrize('timeout,expected', [(30, 23), (400, 180)])
def test_preflight_time_is_subtracted_before_provider_launch(tmp_path, monkeypatch, timeout, expected):
    engine, work = engine_and_work(tmp_path, timeout=timeout)
    clock = fake_clock(monkeypatch, work)
    original = transports._open_evidence
    def delayed(work, trace):
        result = original(work, trace)
        clock[0] += 7
        return result
    monkeypatch.setattr(transports, '_open_evidence', delayed)
    timeouts = []
    def run(argv, cwd, destination, timeout, **kwargs):
        timeouts.append(timeout)
        return codex_result(argv, destination)
    monkeypatch.setattr(transports, 'run_bounded', run)
    result = engine.execute(work)
    assert timeouts == [pytest.approx(expected)] and result.cleanup['passed'] is True


def test_final_identity_deadline_failure_preserves_real_cleanup(tmp_path, monkeypatch):
    engine, work = engine_and_work(tmp_path)
    clock = fake_clock(monkeypatch, work)
    original = engines.ExternalEngine.identity
    identities = []
    def delayed_final(self):
        value = original(self)
        identities.append(value)
        if len(identities) == 2:
            clock[0] = work.deadline_monotonic
        return value
    monkeypatch.setattr(engines.ExternalEngine, 'identity', delayed_final)
    monkeypatch.setattr(transports, 'run_bounded',
                        lambda argv, cwd, destination, timeout, **kw: codex_result(argv, destination))
    with pytest.raises(EngineFailure, match='deadline exhausted') as failure:
        engine.execute(work)
    assert failure.value.cleanup['completed'] is True and failure.value.cleanup['passed'] is True
    assert failure.value.cleanup['started'] is True


@pytest.mark.parametrize('work_timeout,git_timeouts,provider_timeout', [
    (30, [30, 28, 26, 24, 22], 20),
    (400, [30] * 5, 390),
    (2000, [30] * 5, 1800),
])
def test_grok_uses_only_fixed_system_git_and_shares_one_deadline(
        tmp_path, monkeypatch, work_timeout, git_timeouts, provider_timeout):
    engine, work = engine_and_work(tmp_path, 'grok-cli', timeout=work_timeout)
    clock = fake_clock(monkeypatch, work)
    monkeypatch.setenv('PATH', '/a/forbidden/non-system-git')
    monkeypatch.setattr(shutil, 'which', lambda *args, **kwargs: pytest.fail('ambient executable discovery'))
    calls = []
    def run(argv, cwd, destination, timeout, **kwargs):
        calls.append((argv, Path(cwd), destination, timeout, kwargs))
        if argv[0] == '/usr/bin/git':
            assert Path(cwd) != Path.cwd()
            assert kwargs['env_allowlist'] == frozenset()
            assert kwargs['env_override']['PATH'] == os.defpath
            assert kwargs['env_override']['GIT_CONFIG_GLOBAL'] == os.devnull
            assert not Path(destination).is_relative_to(Path(cwd))
            assert 'core.hooksPath=/dev/null' in argv and '--no-replace-objects' in argv
            clock[0] += 2
            if argv[-1] == 'ls-files':
                output = b'admitted-review-prompt.md\n'
            elif 'show' in argv:
                output = (Path(cwd) / 'admitted-review-prompt.md').read_bytes()
            else:
                output = b''
            return process_result(destination, output)
        assert timeout == pytest.approx(provider_timeout)
        return process_result(destination, b'Synthetic Grok review\n')
    monkeypatch.setattr(transports, 'run_bounded', run)
    result = engine.execute(work)
    assert len(calls) == 6 and [row[3] for row in calls[:5]] == git_timeouts
    assert result.evidence['provider_timeout']['cap_seconds'] == 1800
    assert result.evidence['provider_timeout']['remaining_work_seconds_at_spawn'] == pytest.approx(work_timeout - 10)
    assert result.evidence['provider_timeout']['effective_seconds'] == pytest.approx(provider_timeout)
    assert result.evidence['progress_observation']['stdout_silence_proves_inactivity'] is False
    assert len(result.evidence['git_preflight_cleanup']) == 5
    assert all(row['cleanup']['passed'] for row in result.evidence['git_preflight_cleanup'])


def test_grok_git_delay_closes_owned_step_and_prevents_all_later_launches(tmp_path, monkeypatch):
    engine, work = engine_and_work(tmp_path, 'grok-cli')
    clock = fake_clock(monkeypatch, work)
    calls = []
    def run(argv, cwd, destination, timeout, **kwargs):
        calls.append(argv)
        assert argv[0] == '/usr/bin/git'
        clock[0] = work.deadline_monotonic
        return process_result(destination, b'')
    monkeypatch.setattr(transports, 'run_bounded', run)
    with pytest.raises(EngineFailure, match='deadline exhausted') as failure:
        engine.execute(work)
    assert len(calls) == 1
    assert failure.value.cleanup['completed'] is True and failure.value.cleanup['passed'] is True
    assert len(failure.value.evidence['git_preflight_cleanup']) == 1


def test_grok_missing_later_cleanup_keeps_earlier_step_evidence(tmp_path, monkeypatch):
    engine, work = engine_and_work(tmp_path, 'grok-cli')
    fake_clock(monkeypatch, work)
    calls = []
    def run(argv, cwd, destination, timeout, **kwargs):
        calls.append(argv)
        assert argv[0] == '/usr/bin/git'
        result = process_result(destination, b'')
        if len(calls) == 2:
            result.pop('cleanup')
        return result
    monkeypatch.setattr(transports, 'run_bounded', run)
    with pytest.raises(EngineFailure, match='ENGINE_CLEANUP_FAILED') as failure:
        engine.execute(work)
    assert len(calls) == 2 and failure.value.cleanup == {}
    assert len(failure.value.evidence['git_preflight_cleanup']) == 1
