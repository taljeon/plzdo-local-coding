"""Frozen finalizer acceptance checks; no model, listener, or browser is run.

The observation shape is reduced from the completed static-HTML proof. These
are coordinator-observation fixtures, not fabricated native-browser attestations.
Only admission and the closure socket are mocked; real observation validation,
proof files, and atomic result publication remain under test in temporary dirs.
"""
import copy
import errno
import hashlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from types import SimpleNamespace
from engine_types import no_start_cleanup

import workflow
import workflow_browser as browser
from workflow_core import ContractError


class FinalizerFixture:
    def __init__(self, temporary):
        self.root = temporary.resolve() / 'run'
        self.candidate = self.root / 'ollama-1' / 'candidate'
        self.candidate.mkdir(parents=True)
        content = b'<!doctype html><html><body><h1>Title</h1></body></html>\n'
        (self.candidate / 'summary.html').write_bytes(content)
        self.snapshot = {'summary.html': {
            'sha256': hashlib.sha256(content).hexdigest(),
            'mode': (self.candidate / 'summary.html').stat().st_mode & 0o777,
        }}
        self.packet = {
            'kind': 'artifact-create', 'id': 'finalizer-contract',
            'authorityId': 'test-only-no-live-admission',
            'objective': 'Create the approved static preview.',
            'generation_profile': 'huihui-qwen38-q6kl-v1',
            'allowed_paths': ['summary.html'],
        }
        self.packet_sha = workflow.packet_hash(self.packet)
        self.pack = {
            'type': 'html-browser', 'driver': 'managed', 'path': 'summary.html',
            'widths': [390], 'expected_text': ['Title'], 'clicks': [],
        }
        self.requests = [{'pack_index': 0, 'pack': self.pack}]
        self.proof_dir = self.root / 'browser-previews' / '1'
        self.proof_dir.mkdir(parents=True)
        self.preview = {
            'session_id': 'fixture-preview-session', 'pid': 123,
            'packet_sha256': self.packet_sha, 'host': '127.0.0.1', 'port': 5555,
            'started_at': '2026-09-07T00:00:00+00:00', 'ttl_seconds': 300,
            'urls': {'summary.html': 'http://127.0.0.1:5555/fixture-nonce/summary.html'},
            'files': {'summary.html': {'sha256': self.snapshot['summary.html']['sha256'],
                                       'bytes': len(content)}},
        }
        self.stopped = {
            'session_id': self.preview['session_id'], 'pid': self.preview['pid'],
            'server_closed': True, 'stopped_at': '2026-09-07T00:02:00+00:00',
        }
        self.observation = {
            'authority': 'coordinator-observed', 'transport': 'cua-in-app-browser',
            'preview_session_id': self.preview['session_id'], 'preview_index': 1,
            'packet_sha256': self.packet_sha,
            'console_scope': 'captured-errors-for-this-created-tab',
            'packs': [{'pack_index': 0, 'viewports': [{
                'width': 390, 'url': self.preview['urls']['summary.html'],
                'layout': {'observed_width': 390, 'body_present': True,
                           'horizontal_overflow': False},
                'expected_text': [{'text': 'Title', 'visible': True}], 'clicks': [],
                'console_errors': [], 'visual_review_passed': True,
                'screenshot': {
                    'source': 'cua-tool-output', 'mime_type': 'image/jpeg',
                    'header_bytes': [255, 216, 255, 224, 0, 16, 74, 70],
                    'byte_length': 12779, 'captured_at': '2026-09-07T00:01:00Z',
                },
            }]}],
        }
        self.observation_path = self.root / 'browser-observation-1.json'
        self.patch = self.root / 'ollama-1' / 'actual.patch'
        self.patch.write_text('--- /dev/null\n+++ b/summary.html\n', encoding='utf-8')
        self.result = {
            'state': 'awaiting_browser_validation', 'kind': 'artifact-create', 'run_id': 'fixture-run',
            'apply_status': 'not_applied', 'candidate': str(self.candidate),
            'cleanup': no_start_cleanup(),
            'pending_snapshot': self.snapshot, 'pending_patch': str(self.patch),
            'pending_browser': self.requests,
            'attempts': [{
                'provider': 'ollama', 'number': 1, 'candidate': str(self.candidate),
                'operation': {'engineId': 'ollama', 'role': 'generate', 'ordinal': 1},
                'cleanup': no_start_cleanup(),
                'passed': None, 'status': 'awaiting_browser_validation',
                'checks': {
                    'passed': False, 'scope': {'passed': True},
                    'diff_check': {'passed': True}, 'pending_browser': self.requests,
                    'status': 'awaiting_browser_validation',
                    'checks': [{'status': 'awaiting_browser_validation',
                                'executed': False, 'return_code': None}],
                },
            }],
        }
        self.kernel = SimpleNamespace(complete_attempt=Mock(), generate=Mock(side_effect=AssertionError('Finalization cannot generate')))
        self.write_json(self.candidate.parent / 'attempt.json', self.result['attempts'][0])
        self.write_json(self.root / 'result.json', self.result)
        self.write_json(self.root / 'packet.json', self.packet)
        self.sync_observation_inputs()
        (self.root / 'preview-starts.jsonl').write_text(json.dumps({
            'index': 1, 'packet_sha256': self.packet_sha,
            'snapshot_sha256': browser.digest(self.snapshot), 'attempt': 1,
            'at': '2026-09-07T00:00:00+00:00',
        }) + '\n', encoding='utf-8')

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    def sync_observation_inputs(self):
        self.write_json(self.proof_dir / 'preview.json', self.preview)
        self.write_json(self.proof_dir / 'stopped.json', self.stopped)
        self.write_json(self.observation_path, self.observation)

    @property
    def screenshot(self):
        return self.observation['packs'][0]['viewports'][0]['screenshot']

    def pending(self, _, *, kernel):
        current = json.loads((self.root / 'result.json').read_text())
        if current['state'] != 'awaiting_browser_validation':
            raise ContractError('Fixture run is not pending')
        return (self.root, copy.deepcopy(self.packet), current, self.candidate,
                {'maxSessionsPerRun': 3, 'maxLifetimeSeconds': 300}, self.packet_sha)

    def finish(self):
        return browser.finish_browser(self.root, self.observation_path, kernel=self.kernel)

    def file_bytes(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes()
                for p in self.root.rglob('*') if p.is_file()}

    def expected_proofs(self):
        # This is the real validator, not a supplied passed=True response.
        records = browser.validate_observations(self.observation, self.requests, self.preview)
        return {
            'closed-probe.json': {
                'host': self.preview['host'], 'port': self.preview['port'],
                'errno': errno.ECONNREFUSED, 'connection_refused': True,
                'observed_at': '2026-09-07T00:02:01+00:00',
            },
            'validated-observations.json': {
                'records': records, 'authority': 'coordinator-observed',
                'observation_path': str(self.observation_path),
            },
        }


@pytest.fixture
def finalizer(tmp_path, monkeypatch):
    fixture = FinalizerFixture(tmp_path)
    monkeypatch.setattr(browser, 'pending_run', fixture.pending)
    monkeypatch.setattr(browser, 'require_active_session', lambda: None)
    probe = Mock(name='fake-closure-probe')
    probe.connect_ex.return_value = errno.ECONNREFUSED
    connection = Mock(name='fake-socket-context')
    connection.__enter__ = Mock(return_value=probe)
    connection.__exit__ = Mock(return_value=False)
    fixture.socket_factory = Mock(return_value=connection)
    fixture.probe = probe
    monkeypatch.setattr(browser.socket, 'socket', fixture.socket_factory)
    yield fixture
    fixture.kernel.generate.assert_not_called()


@pytest.mark.parametrize('start,stop,capture,ttl', [
    ('2026-09-07T00:00:00Z', '2026-09-07T00:02:00Z', '2026-09-07T00:01:00Z', 300),
    ('2026-09-07T00:00:00Z', '2026-09-07T00:02:00Z', '2026-09-07T00:00:00Z', 300),
    ('2026-09-07T00:00:00Z', '2026-09-07T00:02:00Z', '2026-09-07T00:02:00Z', 300),
    ('2026-09-07T09:00:00+09:00', '2026-09-07T00:02:00Z', '2026-09-07T09:01:00+09:00', 300),
    ('2026-09-07T00:00:00Z', '2026-09-07T00:06:00Z', '2026-09-07T00:05:00Z', 300),
    ('2026-09-07T00:00:00Z', '2026-09-07T00:00:01Z', '2026-09-07T00:00:01Z', 1),
])
def test_valid_lifecycle_and_inclusive_boundaries_pass(finalizer, start, stop, capture, ttl):
    finalizer.preview.update(started_at=start, ttl_seconds=ttl)
    finalizer.stopped['stopped_at'] = stop
    finalizer.screenshot['captured_at'] = capture
    finalizer.sync_observation_inputs()
    result = finalizer.finish()
    assert result['state'] == 'candidate_ready' and result['browser_passed'] is True
    effective = json.loads((finalizer.root / 'result.json').read_text())
    assert effective['attempts'][0]['checks']['passed'] is True
    record = effective['attempts'][0]['checks']['checks'][0]
    assert record['authority'] == 'coordinator-observed' and record['return_code'] is None
    finalizer.probe.connect_ex.assert_called_once_with(('127.0.0.1', 5555))


@pytest.mark.parametrize('field,value,late_stop', [
    ('capture', '2026-09-06T23:59:59Z', False),
    ('capture', '2026-09-07T00:02:01Z', False),
    ('capture', '2026-09-07T00:05:01Z', True),
    ('capture', '2099-01-01T00:00:00Z', False),
    ('capture', 'not-a-timestamp', False),
    ('capture', '2026-09-07T00:01:00', False),
    ('capture', None, False),
    ('start', 'not-a-timestamp', False),
    ('start', '2026-09-07T00:00:00', False),
    ('start', None, False),
    ('stop', '2026-09-06T23:59:59Z', False),
    ('stop', 'not-a-timestamp', False),
    ('stop', '2026-09-07T00:02:00', False),
    ('stop', None, False),
    ('ttl', 0, False), ('ttl', 301, False), ('ttl', True, False),
    ('ttl', 300.0, False), ('ttl', '300', False), ('ttl', None, False),
    ('missing-ttl', None, False),
])
def test_invalid_lifecycle_rejects_without_publishing_proof_or_result(finalizer, field, value, late_stop):
    if late_stop:
        finalizer.stopped['stopped_at'] = '2026-09-07T00:06:00Z'
    if field == 'capture':
        finalizer.screenshot['captured_at'] = value
    elif field == 'start':
        finalizer.preview['started_at'] = value
    elif field == 'stop':
        finalizer.stopped['stopped_at'] = value
    elif field == 'ttl':
        finalizer.preview['ttl_seconds'] = value
    else:
        finalizer.preview.pop('ttl_seconds')
    finalizer.sync_observation_inputs()
    before = finalizer.file_bytes()
    with pytest.raises(ContractError):
        finalizer.finish()
    assert finalizer.file_bytes() == before


@pytest.mark.parametrize('cut', ['after-closed-probe', 'before-result-publication'])
def test_interrupted_finalization_reuses_identical_proofs_and_reprobes(finalizer, monkeypatch, cut):
    initial_result = (finalizer.root / 'result.json').read_bytes()
    original_save = workflow.save

    def interrupt_after_probe(path, value):
        original_save(path, value)
        if Path(path).name == 'closed-probe.json':
            raise KeyboardInterrupt('Injected interruption after durable closure proof')

    def interrupt_before_result(*_):
        raise KeyboardInterrupt('Injected interruption before result publication')

    with monkeypatch.context() as interruption:
        if cut == 'after-closed-probe':
            interruption.setattr(workflow, 'save', interrupt_after_probe)
        else:
            interruption.setattr(workflow, 'store_result', interrupt_before_result)
        with pytest.raises(KeyboardInterrupt):
            finalizer.finish()
    names = ['closed-probe.json'] + (['validated-observations.json'] if cut == 'before-result-publication' else [])
    proof_bytes = {name: (finalizer.proof_dir / name).read_bytes() for name in names}
    assert (finalizer.root / 'result.json').read_bytes() == initial_result
    assert finalizer.probe.connect_ex.call_count == 1

    result = finalizer.finish()
    assert result['state'] == 'candidate_ready' and result['browser_passed'] is True
    assert finalizer.probe.connect_ex.call_count == 2
    for name, previous in proof_bytes.items():
        assert (finalizer.proof_dir / name).read_bytes() == previous
    assert json.loads((finalizer.root / 'result.json').read_text())['state'] == 'candidate_ready'


@pytest.mark.parametrize('proof_name,field,value', [
    ('closed-probe.json', 'host', '127.0.0.2'),
    ('closed-probe.json', 'port', 5556),
    ('closed-probe.json', 'errno', 0),
    ('closed-probe.json', 'connection_refused', False),
    ('validated-observations.json', 'observation_path', '/different-observation.json'),
    ('validated-observations.json', 'records', []),
    ('validated-observations.json', 'authority', 'model-authored'),
])
def test_conflicting_existing_proof_stops_without_overwriting(finalizer, proof_name, field, value):
    proofs = finalizer.expected_proofs()
    proofs[proof_name][field] = value
    for name, proof in proofs.items():
        finalizer.write_json(finalizer.proof_dir / name, proof)
    before = finalizer.file_bytes()
    with pytest.raises(ContractError):
        finalizer.finish()
    assert finalizer.file_bytes() == before


@pytest.mark.parametrize('closure_code', [0, errno.ETIMEDOUT, errno.EACCES])
def test_existing_proofs_never_replace_a_fresh_closure_probe(finalizer, closure_code):
    for name, proof in finalizer.expected_proofs().items():
        finalizer.write_json(finalizer.proof_dir / name, proof)
    finalizer.probe.connect_ex.return_value = closure_code
    before = finalizer.file_bytes()
    with pytest.raises(ContractError):
        finalizer.finish()
    assert finalizer.file_bytes() == before
    finalizer.probe.connect_ex.assert_called_once_with(('127.0.0.1', 5555))
