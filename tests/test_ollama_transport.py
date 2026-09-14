"""Offline transport/ownership verification; no Ollama, model, or sandbox jobs."""
from contextlib import contextmanager
import io
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from engine_types import EngineFailure, EngineIdentity, Work, no_start_cleanup
from generation_profile import HUIHUI_PROFILE_ID, HUIHUI_MODEL, HUIHUI_DIGEST, resolve_profile, profile_sha256
from json_codec import canonical_bytes
import ollama_engine as ollama


@pytest.fixture
def profile():
    return resolve_profile(HUIHUI_PROFILE_ID)


@pytest.fixture
def identity():
    return EngineIdentity('ollama', ('generate',), 'b' * 64)


def work(root, profile):
    return Work('generate', canonical_bytes('Create the approved text.'), canonical_bytes({'type': 'object'}),
                canonical_bytes(profile), 30, root / 'provider', 'reserved-1')


@pytest.fixture
def local_fixture(tmp_path, monkeypatch, profile):
    manifest = tmp_path / 'manifest'
    manifest.write_bytes(b'fixture')
    loaded = {'name': HUIHUI_MODEL, 'model': HUIHUI_MODEL,
              'digest': HUIHUI_DIGEST, 'context_length': profile['options']['num_ctx']}
    monkeypatch.setattr(ollama, 'HUIHUI_MANIFEST', manifest)
    monkeypatch.setattr(ollama, 'sha', lambda data: HUIHUI_DIGEST)
    governor = Mock()
    governor.summary.return_value = {'fixture': True}
    monkeypatch.setattr('generation_health.GenerationHealth', lambda *args: governor)
    state = {'before': [], 'calls': [], 'requests': [], 'profile': profile}
    def status(endpoint, **kwargs):
        state['calls'].append(endpoint)
        if endpoint == 'version':
            return {'version': '0.33.3'}
        if endpoint == 'tags':
            return {'models': [loaded]}
        return {'models': state['before'] if state['calls'].count('ps') == 1 else [loaded]}
    monkeypatch.setattr(ollama, 'local_status', status)
    def generate(argv, cwd, evidence, timeout, **kwargs):
        request = json.loads((tmp_path / 'provider' / 'request.json').read_text())
        state['requests'].append(request)
        response = {'model': HUIHUI_MODEL.lower(), 'done': True, 'done_reason': 'stop',
                    'message': {'content': '{"files":[]}'}, 'prompt_eval_count': 20, 'eval_count': 10}
        (tmp_path / 'provider' / 'response.json').write_text(json.dumps(response))
        return {'return_code': 0, 'duration_seconds': 1, 'supervisor_stop': False,
                'cleanup': {'schema': 'plzdo.engine-cleanup.v1', 'completed': True,
                            'passed': True, 'started': True, 'owned': True}}
    runner = Mock(side_effect=generate)
    monkeypatch.setattr(ollama, 'run', runner)
    return state, loaded, governor, runner


def test_original_profile_byte_hashes_are_preserved():
    expected = {
        'qwen3-coder-official-v1': 'eba813d02eaad342a0be89f0513068f8d65b4be94558736f6ac0c5967cd9fb2c',
        'qwen3-coder-official-v2': '2fb0605b6f1d15a36e5a2363ee187104fe1d0fc3689998555af8dec0eae75c28',
        'qwen3-coder-official-v3': '211665f60d08f519357f7dc9a6b9a2225338258be3f0c2e2e33330c69b96e590',
        'huihui-qwen38-q6kl-v1': '5dc0d61715840a1b0518a8ce2278e22e680712fb0e422ab588b5bb4f6e0e9c55'}
    assert {key: profile_sha256(key) for key in expected} == expected


def test_pinned_request_and_launch_evidence(tmp_path, profile, local_fixture):
    state, loaded, governor, runner = local_fixture
    launched = Mock()
    payload = ollama.local_edits('Create approved text', {'type': 'object'}, tmp_path / 'provider', 30,
                                 generation_profile=profile, _on_launch=launched)
    assert payload == {'files': []}
    assert state['requests'][0]['model'] == HUIHUI_MODEL
    assert state['requests'][0]['options'] == profile['options']
    assert state['requests'][0]['think'] is True
    launched.assert_called_once()
    assert 0 < runner.call_args.args[3] <= 30
    assert '-I' in runner.call_args.args[0] and '-S' in runner.call_args.args[0]
    assert runner.call_args.kwargs['pipe_output'] is True
    assert json.loads((tmp_path / 'provider' / 'identity.json').read_text())['digest'] == HUIHUI_DIGEST


def test_preloaded_model_cannot_be_claimed(tmp_path, profile, local_fixture):
    state, loaded, governor, runner = local_fixture
    state['before'] = [loaded]
    launched = Mock()
    with pytest.raises(ollama.LocalGenerationError) as exc:
        ollama.local_edits('Create approved text', {}, tmp_path / 'provider', 30,
                           generation_profile=profile, _on_launch=launched)
    assert exc.value.generation_error_code == 'MODEL_ALREADY_LOADED'
    assert exc.value.generation_hard_stop is True
    launched.assert_not_called()
    runner.assert_not_called()


@pytest.mark.parametrize('phase', ['preflight', 'close'])
def test_health_failure_never_produces_success(tmp_path, profile, local_fixture, phase):
    state, loaded, governor, runner = local_fixture
    getattr(governor, phase).side_effect = OSError('Synthetic health failure')
    with pytest.raises(ollama.LocalGenerationError) as exc:
        ollama.local_edits('Create approved text', {}, tmp_path / 'provider', 30,
                           generation_profile=profile)
    assert exc.value.generation_hard_stop is True
    assert exc.value.generation_error_code in {'MEMORY_ADMISSION_FAILED', 'HEALTH_EVIDENCE_FAILED'}
    if phase == 'preflight':
        runner.assert_not_called()


@pytest.mark.parametrize('owned,changed', [(False, {}), (True, {'digest': 'foreign'}),
                                           (True, {'context_length': 4096})])
def test_unload_cannot_evict_unowned_or_foreign_model(monkeypatch, profile, owned, changed):
    loaded = {'name': HUIHUI_MODEL, 'model': HUIHUI_MODEL, 'digest': HUIHUI_DIGEST,
              'context_length': profile['options']['num_ctx'], **changed}
    monkeypatch.setattr(ollama, 'local_status', lambda endpoint: {'models': [loaded]})
    opener = Mock()
    monkeypatch.setattr('urllib.request.build_opener', opener)
    with pytest.raises(ollama.ContractError):
        ollama.unload_profile(profile, owned=owned)
    opener.assert_not_called()


def test_owned_unload_uses_fixed_loopback_and_requires_empty_after(monkeypatch, profile):
    loaded = {'name': HUIHUI_MODEL, 'model': HUIHUI_MODEL, 'digest': HUIHUI_DIGEST,
              'context_length': profile['options']['num_ctx']}
    statuses = iter([{'models': [loaded]}, {'models': []}])
    monkeypatch.setattr(ollama, 'local_status', lambda endpoint: next(statuses))
    response = io.BytesIO(canonical_bytes({'model': HUIHUI_MODEL, 'done': True, 'done_reason': 'unload'}))
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr('urllib.request.build_opener', lambda *args: opener)
    receipt = ollama.unload_profile(profile, owned=True)
    request = opener.open.call_args.args[0]
    assert request.full_url == 'http://127.0.0.1:11434/api/generate'
    assert json.loads(request.data) == {'model': HUIHUI_MODEL, 'stream': False, 'keep_alive': 0}
    assert receipt['unload_sent'] is True and receipt['after'] == {'models': []}


def install_owned_fixtures(monkeypatch, events, *, failure=None, started=True, cleanup_failure=False):
    @contextmanager
    def slot(*args, **kwargs):
        events.append('lock')
        yield lambda: events.append('verify-lock')
        events.append('unlock')
    def generate(prompt, schema, evidence, timeout, **kwargs):
        evidence.mkdir()
        if started:
            kwargs['_on_launch']()
            (evidence / 'process').mkdir()
            (evidence / 'process' / 'summary.json').write_bytes(canonical_bytes({'cleanup': {
                'schema': 'plzdo.engine-cleanup.v1', 'completed': True, 'passed': True,
                'owned': True, 'started': True, 'scope': 'initial-posix-process-group'}}))
        events.append('generate')
        if failure is not None:
            raise failure
        return {'files': []}
    def unload(profile, *, owned):
        events.append('unload')
        assert owned
        if cleanup_failure:
            raise OSError('Synthetic cleanup failure')
        return {'unload_sent': True, 'after': {'models': []}}
    monkeypatch.setattr(ollama, 'local_model_slot', slot)
    monkeypatch.setattr(ollama, 'local_edits', generate)
    monkeypatch.setattr(ollama, 'unload_profile', unload)
    monkeypatch.setattr('generation_health.sample_system', lambda: {'pressure': 1})


def test_owned_transport_cleans_under_lock_before_return(tmp_path, monkeypatch, profile, identity):
    events = []
    install_owned_fixtures(monkeypatch, events)
    response = ollama.execute_owned_ollama(work(tmp_path, profile), identity)
    events.append('returned')
    assert events.index('unload') < events.index('unlock') < events.index('returned')
    assert response.cleanup['started'] is True and response.cleanup['completed'] is True
    assert response.evidence['trust'] == 'personal-local' and response.evidence['isolation_verified'] is False
    assert json.loads((tmp_path / 'provider' / 'owned-cleanup.json').read_text())['passed'] is True


def test_owned_transport_does_not_unload_failed_admission(tmp_path, monkeypatch, profile, identity):
    events = []
    failure = ollama.LocalGenerationError('MODEL_ALREADY_LOADED', 'Leave another session untouched', hard_stop=True)
    install_owned_fixtures(monkeypatch, events, failure=failure, started=False)
    with pytest.raises(EngineFailure) as exc:
        ollama.execute_owned_ollama(work(tmp_path, profile), identity)
    assert 'unload' not in events and exc.value.cleanup == no_start_cleanup()
    assert exc.value.code == 'MODEL_ALREADY_LOADED' and exc.value.retryable is False


def test_cleanup_failure_overrides_an_otherwise_valid_payload(tmp_path, monkeypatch, profile, identity):
    events = []
    install_owned_fixtures(monkeypatch, events, cleanup_failure=True)
    with pytest.raises(EngineFailure) as exc:
        ollama.execute_owned_ollama(work(tmp_path, profile), identity)
    assert exc.value.code == 'ENGINE_CLEANUP_FAILED'
    assert exc.value.cleanup['passed'] is False


@pytest.mark.parametrize('code', ['ACTIVITY_STALL', 'FIRST_ACTIVITY_STALL', 'CLOCK_INVALID', 'REPETITION_DETECTED', 'NOVEL_FAILURE'])
def test_closed_failure_codes_do_not_add_new_retry_permissions(tmp_path, code):
    process = tmp_path / 'process'
    process.mkdir()
    (process / 'events.jsonl').write_bytes(canonical_bytes({'status': 'failed', 'error_code': code}))
    failure = ollama._profile_stream_failure(tmp_path)
    assert failure.generation_hard_stop is True


def test_missing_loaded_model_receipt_never_counts_as_empty(monkeypatch, profile):
    monkeypatch.setattr(ollama, 'local_status', lambda endpoint: {})
    opener = Mock()
    monkeypatch.setattr('urllib.request.build_opener', opener)
    with pytest.raises(ollama.ContractError):
        ollama.unload_profile(profile, owned=True)
    opener.assert_not_called()


def test_missing_process_summary_still_attempts_model_cleanup_but_blocks(tmp_path, monkeypatch, profile, identity):
    events = []
    install_owned_fixtures(monkeypatch, events)
    author = ollama.local_edits
    def missing(*args, **kwargs):
        value = author(*args, **kwargs)
        (args[2] / 'process' / 'summary.json').unlink()
        return value
    monkeypatch.setattr(ollama, 'local_edits', missing)
    with pytest.raises(EngineFailure) as exc:
        ollama.execute_owned_ollama(work(tmp_path, profile), identity)
    assert 'unload' in events
    assert exc.value.code == 'ENGINE_CLEANUP_FAILED'
    assert exc.value.cleanup['completed'] is False


def test_missing_ps_baseline_cannot_launch(tmp_path, profile, local_fixture, monkeypatch):
    state, loaded, governor, runner = local_fixture
    def status(endpoint, **kwargs):
        if endpoint == 'version':
            return {'version': '0.33.3'}
        return {'models': [loaded]} if endpoint == 'tags' else {}
    monkeypatch.setattr(ollama, 'local_status', status)
    launched = Mock()
    with pytest.raises(ollama.ContractError):
        ollama.local_edits('Create approved text', {}, tmp_path / 'provider', 30,
                           generation_profile=profile, _on_launch=launched)
    launched.assert_not_called()
    runner.assert_not_called()


def test_work_created_before_dispatch_cannot_reset_its_deadline(tmp_path, monkeypatch, profile, identity):
    from dataclasses import FrozenInstanceError
    from types import SimpleNamespace
    task = work(tmp_path, profile)
    assert isinstance(task.deadline_monotonic, float)
    with pytest.raises(FrozenInstanceError):
        task.deadline_monotonic += 30
    monkeypatch.setattr(ollama, 'time', SimpleNamespace(monotonic=lambda: task.deadline_monotonic + 1))
    monkeypatch.setattr(ollama, 'local_model_slot', lambda *args, **kwargs: pytest.fail('Expired Work acquired a model slot'))
    monkeypatch.setattr(ollama, 'local_edits', lambda *args, **kwargs: pytest.fail('Expired Work started generation'))
    with pytest.raises(EngineFailure) as exc:
        ollama.execute_owned_ollama(task, identity)
    assert exc.value.code == 'GENERATION_DEADLINE'
    assert exc.value.cleanup == no_start_cleanup()
    assert not task.evidence_dir.exists()
