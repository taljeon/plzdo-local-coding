"""Focused shared-boundary fixtures. No model, provider CLI, or sandbox jobs."""
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

import engine_types as types
from generation_profile import HUIHUI_PROFILE_ID, LEGACY_PROFILE_ID, resolve_profile
from json_codec import canonical_bytes, strict_json
import ollama_engine as ollama
import workflow
import workflow_artifacts as artifacts
import workflow_core as core
import workflow_validation as validation


def packet():
    return {'kind': 'artifact-create', 'id': 'small-task', 'authorityId': 'active-root',
            'objective': 'Create the approved greeting', 'allowed_paths': ['hello.txt'],
            'generation_profile': HUIHUI_PROFILE_ID, 'local_attempts': 2,
            'validation_packs': [{'type': 'text', 'path': 'hello.txt', 'required': ['hello']}],
            'timeout_seconds': 30}


def checks(passed=True):
    return {'passed': passed, 'scope': {'passed': True},
            'checks': [{'return_code': 0 if passed else 1, 'executed': True,
                        'execution_receipt': {'schema': 'check-execution-receipt.v1', 'passed': True}}],
            'diff_check': {'passed': True}, 'pending_browser': []}


def result(payload=None, *, cleanup=None, engine_id='ollama'):
    payload = {'files': [{'path': 'hello.txt', 'content': 'hello\n'}]} if payload is None else payload
    return types.WorkResult(payload if isinstance(payload, bytes) else canonical_bytes(payload),
                            types.EngineIdentity(engine_id, ('generate',), 'a' * 64),
                            {'fixture': True}, types.no_start_cleanup() if cleanup is None else cleanup)


class FakeKernel:
    def __init__(self, root, outcomes, events):
        self.root, self.outcomes, self.events = root, list(outcomes), events
        self.completed = []

    def plan(self, packet):
        return tuple({'engineId': 'ollama', 'role': 'generate', 'ordinal': index}
                     for index in range(1, len(self.outcomes) + 1))

    def begin_run(self, packet, run_name, resume=False):
        self.events.append('begin')
        return SimpleNamespace(root=self.root / run_name, run_id=run_name)

    def generate(self, packet, run_id, ordinal, prompt_bytes, schema_bytes, evidence_dir):
        self.events.append('generate:' + str(ordinal))
        assert isinstance(strict_json(prompt_bytes), str)
        assert canonical_bytes(strict_json(schema_bytes)) == schema_bytes
        outcome = self.outcomes[ordinal - 1]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def complete_attempt(self, packet, run_id, ordinal, receipt):
        self.events.append('complete:' + str(ordinal))
        self.completed.append(strict_json(receipt.read_bytes()))


@pytest.fixture
def state(tmp_path, monkeypatch):
    root = tmp_path / 'state'
    root.mkdir(mode=0o700)
    monkeypatch.setenv('LOCAL_CODING_STATE_ROOT', str(root))
    for module in (workflow, core, artifacts):
        monkeypatch.setattr(module, 'DIRECTORY', root)
    monkeypatch.setattr(workflow, 'WORKFLOWS', root / 'runs')
    return root


def test_new_packets_require_authority_and_explicit_pinned_hui():
    normalized = workflow.validate_task_packet(packet())
    assert normalized['authorityId'] == 'active-root'
    assert normalized['generation_profile'] == resolve_profile(HUIHUI_PROFILE_ID)
    for field in ('hn_formalization', 'codex_attempts', 'external_ai_allowed'):
        with pytest.raises(core.ContractError):
            workflow.validate_task_packet({**packet(), field: True})
    for changes in ({'generation_profile': LEGACY_PROFILE_ID}, {'generation_profile': None}, {'authorityId': ''}):
        with pytest.raises(core.ContractError):
            workflow.validate_task_packet({**packet(), **changes})
    missing = packet()
    del missing['generation_profile']
    with pytest.raises(core.ContractError):
        workflow.validate_task_packet(missing)


def test_engine_values_are_deeply_immutable(tmp_path):
    identity = types.EngineIdentity('ollama', ('generate',), 'a' * 64)
    evidence = {'rows': [{'closed': True}]}
    work_result = types.WorkResult(b'{}', identity, evidence, types.no_start_cleanup())
    evidence['rows'][0]['closed'] = False
    assert work_result.evidence['rows'][0]['closed'] is True
    with pytest.raises(TypeError):
        work_result.evidence['rows'][0]['closed'] = False
    with pytest.raises(FrozenInstanceError):
        identity.engine_id = 'foreign'
    with pytest.raises(ValueError):
        types.Work('generate', b'"prompt"', b'{ "type":"object"}', b'{}', 10, tmp_path, 'reserved')
    with pytest.raises(ValueError):
        strict_json('{"number":1e999}')


def test_public_ollama_refuses_before_model_or_status_access(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Model/endpoint access happened before refusal')
    for name in ('local_edits', 'local_status', '_verify_local_manifest', 'execute_owned_ollama'):
        monkeypatch.setattr(ollama, name, forbidden)
    with pytest.raises(types.EngineFailure) as error:
        ollama.OllamaEngine().execute(None)
    assert error.value.code == 'ISOLATION_PROFILE_UNSUPPORTED'
    assert error.value.cleanup == types.no_start_cleanup()


def test_shared_pipeline_closes_receipt_before_next_generation(state, monkeypatch):
    events = []
    kernel = FakeKernel(state, [result(), result()], events)
    calls = iter([False, True])
    def check(*args):
        events.append('check')
        return checks(next(calls))
    monkeypatch.setattr(workflow, 'run_artifact_checks', check)
    done = workflow.run_pipeline(packet(), 'sequence', kernel=kernel)
    assert done['state'] == 'candidate_ready'
    assert events == ['begin', 'generate:1', 'check', 'complete:1', 'generate:2', 'check', 'complete:2']
    assert (Path(done['candidate']) / 'hello.txt').read_text() == 'hello\n'
    assert done['cleanup']['completed'] is True
    assert len(kernel.completed) == 2
    assert workflow.read_result(state / 'sequence')['state'] == 'candidate_ready'
    assert list((state / 'sequence').glob('result.history-*.json'))


@pytest.mark.parametrize('bad', [None, {}, {'passed': True},
    {'schema': types.CLEANUP_SCHEMA, 'completed': False, 'passed': True, 'owned': True, 'started': True},
    {'schema': types.CLEANUP_SCHEMA, 'completed': True, 'passed': True, 'owned': False, 'started': True}])
def test_missing_or_unclosed_cleanup_never_runs_checks_or_retry(state, monkeypatch, bad):
    events = []
    outcome = result(cleanup=bad if bad is not None else {})
    kernel = FakeKernel(state, [outcome, result()], events)
    monkeypatch.setattr(workflow, 'run_artifact_checks', lambda *args: pytest.fail('Checks preceded cleanup'))
    done = workflow.run_pipeline(packet(), 'unclosed', kernel=kernel)
    assert done['state'] == 'blocked'
    assert events == ['begin', 'generate:1', 'complete:1']
    assert not (Path(done['attempts'][0]['candidate']) / 'hello.txt').exists()


@pytest.mark.parametrize('error', [RuntimeError('unknown'), ValueError('unknown'),
    types.EngineFailure('UNRECOGNIZED_FAILURE', 'No retry authority', evidence={},
                        cleanup=types.no_start_cleanup(), retryable=True),
    types.EngineFailure('REPETITION_DETECTED', 'Not a new retry condition', evidence={},
                        cleanup=types.no_start_cleanup(), retryable=True)])
def test_unknown_errors_and_retry_boolean_alone_hard_stop(state, monkeypatch, error):
    events = []
    kernel = FakeKernel(state, [error, result()], events)
    monkeypatch.setattr(workflow, 'run_artifact_checks', lambda *args: pytest.fail('Unexpected check'))
    done = workflow.run_pipeline(packet(), 'unknown', kernel=kernel)
    assert done['state'] == 'blocked'
    assert done['attempts'][0]['fatal'] is True
    assert events == ['begin', 'generate:1', 'complete:1']


def test_known_bad_json_retries_after_explicit_cleanup(state, monkeypatch):
    events = []
    kernel = FakeKernel(state, [result(b'{broken'), result()], events)
    monkeypatch.setattr(workflow, 'run_artifact_checks', lambda *args: checks())
    done = workflow.run_pipeline(packet(), 'malformed', kernel=kernel)
    assert done['state'] == 'candidate_ready'
    assert done['attempts'][0]['error_code'] == 'INVALID_CONTENT_JSON'
    assert events.index('complete:1') < events.index('generate:2')


def test_missing_checker_receipt_is_not_an_assertion_failure(state, monkeypatch):
    events = []
    kernel = FakeKernel(state, [result(), result()], events)
    broken = checks(False)
    del broken['checks'][0]['execution_receipt']
    monkeypatch.setattr(workflow, 'run_artifact_checks', lambda *args: broken)
    done = workflow.run_pipeline(packet(), 'bad-check', kernel=kernel)
    assert done['state'] == 'blocked'
    assert done['attempts'][0]['error_code'] == 'CHECK_EXECUTION_FAILED'
    assert len(kernel.completed) == 1


def test_receipt_close_failure_blocks_success_and_next_attempt(state, monkeypatch):
    events = []
    kernel = FakeKernel(state, [result(), result()], events)
    def no_close(*args):
        raise OSError('Synthetic receipt failure')
    kernel.complete_attempt = no_close
    monkeypatch.setattr(workflow, 'run_artifact_checks', lambda *args: checks())
    with pytest.raises(OSError):
        workflow.run_pipeline(packet(), 'receipt', kernel=kernel)
    done = workflow.read_result(state / 'receipt')
    assert done['state'] == 'blocked'
    assert len(done['attempts']) == 1
    assert events == ['begin', 'generate:1']


def test_staged_checker_contains_neutral_codec_and_runs_without_transport(tmp_path):
    evidence = tmp_path / 'evidence'
    evidence.mkdir()
    candidate = tmp_path / 'candidate'
    candidate.mkdir()
    (candidate / 'hello.txt').write_text('hello\n')
    spec = tmp_path / 'spec.json'
    spec.write_bytes(canonical_bytes({'pack': {'type': 'text', 'path': 'hello.txt', 'required': ['hello'], 'forbidden': []},
                                     'candidate': str(candidate)}))
    runtime, receipt = validation._stage_runtime(evidence)
    try:
        names = {row['name'] for row in receipt}
        assert 'json_codec.py' in names and 'generate_edits.py' not in names
        code = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                'import workflow_validation;raise SystemExit(workflow_validation.main())')
        child = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', code, str(runtime), '--builtin', str(spec)],
                               capture_output=True, text=True, timeout=10)
        assert child.returncode == 0, child.stderr + child.stdout
        assert strict_json(child.stdout)['passed'] is True
    finally:
        runtime.chmod(0o700)


def repo_packet(root):
    repository = root / 'source'
    repository.mkdir()
    (repository / 'app.py').write_text('VALUE = 1\n')
    def git(*args):
        done = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', *args],
                              cwd=repository, capture_output=True, text=True, check=True,
                              env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
                                   'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'})
        return done.stdout.strip()
    git('init', '-q')
    git('add', 'app.py')
    git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.com', 'commit', '-qm', 'fixture')
    task = {'id': 'repo-regression', 'authorityId': 'active-root', 'repository': str(repository),
            'base_revision': git('rev-parse', 'HEAD'), 'objective': 'Set the approved value to 2',
            'allowed_paths': ['app.py'], 'required_changed_paths': ['app.py'],
            'checks': [['python3', '-B', '-c', 'import app; assert app.VALUE == 2']],
            'regression_checks': [['python3', '-B', '-c', 'import app; assert app.VALUE == 2']],
            'generation_profile': HUIHUI_PROFILE_ID, 'local_attempts': 1}
    return task, repository


def test_repo_baseline_precedes_generation_and_original_stays_unchanged(state, tmp_path, monkeypatch):
    task, repository = repo_packet(tmp_path)
    events = []
    proposed = result({'edits': [{'path': 'app.py', 'old_text': 'VALUE = 1', 'new_text': 'VALUE = 2'}]})
    kernel = FakeKernel(state, [proposed], events)
    def check(current, candidate, evidence):
        baseline = 'baseline' in evidence.name
        events.append('baseline' if baseline else 'check')
        assert (candidate / 'app.py').read_text() == ('VALUE = 1\n' if baseline else 'VALUE = 2\n')
        if baseline:
            assert current['regression_checks'] == [] and current['required_changed_paths'] == []
        return checks(not baseline)
    monkeypatch.setattr(workflow, 'run_checks', check)
    done = workflow.run_pipeline(task, 'repo', kernel=kernel)
    assert done['state'] == 'candidate_ready' and done['baseline_regression_failed'] is True
    assert events == ['begin', 'baseline', 'generate:1', 'check', 'complete:1']
    assert (repository / 'app.py').read_text() == 'VALUE = 1\n'
    assert (Path(done['candidate']) / 'app.py').read_text() == 'VALUE = 2\n'


def test_passing_regression_baseline_blocks_before_generation(state, tmp_path, monkeypatch):
    task, repository = repo_packet(tmp_path)
    events = []
    kernel = FakeKernel(state, [result()], events)
    monkeypatch.setattr(workflow, 'run_checks', lambda *args: checks(True))
    with pytest.raises(core.ContractError, match='already pass'):
        workflow.run_pipeline(task, 'already', kernel=kernel)
    assert events == ['begin']
    assert workflow.read_result(state / 'already')['state'] == 'blocked'
    assert (repository / 'app.py').read_text() == 'VALUE = 1\n'


def test_compute_handoff_validation_never_enters_generation(state):
    task = {'kind': 'compute-analysis', 'id': 'calculation', 'authorityId': 'active-root',
            'objective': 'Verify the supplied values using actual calculation tools', 'inputs': {'values': [1, 2]}}
    assert workflow.validate_task_packet(task) == task
    for extra in ({'external_ai_allowed': True}, {'generation_profile': HUIHUI_PROFILE_ID}, {'hn_formalization': 'old'}):
        with pytest.raises(core.ContractError):
            workflow.validate_task_packet({**task, **extra})
    events = []
    kernel = FakeKernel(state, [result()], events)
    with pytest.raises(core.ContractError, match='zero-provider handoff'):
        workflow.run_pipeline(task, 'calculation', kernel=kernel)
    assert events == []


def test_typed_generation_evidence_failures_remain_visible_and_never_retry(state, monkeypatch):
    events = []
    failure = types.EngineFailure('HTTP_ERROR', 'Synthetic generation evidence failure',
        evidence={'status_write_failed': True, 'evidence_close_failed': True}, cleanup=types.no_start_cleanup())
    kernel = FakeKernel(state, [failure, result()], events)
    monkeypatch.setattr(workflow, 'run_artifact_checks', lambda *args: pytest.fail('Checks followed failed evidence'))
    done = workflow.run_pipeline(packet(), 'evidence-error', kernel=kernel)
    assert done['state'] == 'blocked'
    assert done['attempts'][0]['status_write_failed'] is True
    assert done['attempts'][0]['evidence_close_failed'] is True
    assert done['attempts'][0]['error_code'] == 'HTTP_ERROR'
    assert events == ['begin', 'generate:1', 'complete:1']
