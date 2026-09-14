"""Shared browser accounting using synthetic observations and no live listener/UI."""
import copy
import errno
import hashlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from engine_types import EngineFailure
from generation_profile import HUIHUI_PROFILE_ID
from json_codec import canonical_bytes, strict_json
from test_shared_pipeline import FakeKernel, result, state
import workflow
import workflow_browser as browser


@pytest.fixture
def pending(state, monkeypatch):
    events = []
    kernel = FakeKernel(state / 'runs', [result({'files': [{'path': 'summary.html',
        'content': '<!doctype html><html><body><h1>Title</h1></body></html>\n'}]})] * 2, events)
    kernel.state_root = state
    authorization = {'approved': True, 'bind': '127.0.0.1', 'source': 'exact-generated-artifact-allowlist-only',
                     'requireStopBeforeFinalize': True, 'maxLifetimeSeconds': 300, 'maxSessionsPerRun': 3}
    kernel.approved_contract = lambda packet: ({'execution': {'previewAuthorization': authorization},
                                               'expiresAt': '2099-01-01T00:00:00Z'}, {})
    packet = {'kind': 'artifact-create', 'id': 'managed-test', 'authorityId': 'active-root',
              'objective': 'Create the approved static page', 'allowed_paths': ['summary.html'],
              'generation_profile': HUIHUI_PROFILE_ID, 'validation_packs': [{'type': 'html-browser',
                  'driver': 'managed', 'path': 'summary.html', 'widths': [390], 'expected_text': ['Title']}],
              'local_attempts': 2}
    def checks(task, candidate, evidence):
        requests = [{'pack_index': 0, 'pack': task['validation_packs'][0]}]
        return {'passed': False, 'scope': {'passed': True}, 'diff_check': {'passed': True},
                'pending_browser': requests, 'checks': [{'status': 'awaiting_browser_validation',
                                                       'executed': False, 'return_code': None}]}
    monkeypatch.setattr(workflow, 'run_artifact_checks', checks)
    done = workflow.run_pipeline(packet, 'browser-run', kernel=kernel)
    root = state / 'runs' / 'browser-run'
    candidate = Path(done['candidate'])
    packet = strict_json((root / 'packet.json').read_bytes())
    packet_hash = workflow.packet_hash(packet)
    proof = root / 'browser-previews' / '1'
    proof.mkdir(parents=True)
    content = (candidate / 'summary.html').read_bytes()
    preview = {'session_id': 'fixture-preview-session', 'pid': 123, 'packet_sha256': packet_hash,
               'host': '127.0.0.1', 'port': 5555, 'started_at': '2026-09-13T00:00:00+00:00', 'ttl_seconds': 300,
               'urls': {'summary.html': 'http://127.0.0.1:5555/fixture-nonce/summary.html'},
               'files': {'summary.html': {'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content)}}}
    stopped = {'session_id': preview['session_id'], 'pid': preview['pid'], 'server_closed': True,
               'stopped_at': '2026-09-13T00:02:00+00:00'}
    observed = {'authority': 'coordinator-observed', 'transport': 'cua-in-app-browser',
                'preview_session_id': preview['session_id'], 'preview_index': 1, 'packet_sha256': packet_hash,
                'console_scope': 'captured-errors-for-this-created-tab',
                'packs': [{'pack_index': 0, 'viewports': [{
                    'width': 390, 'url': preview['urls']['summary.html'],
                    'layout': {'observed_width': 390, 'body_present': True, 'horizontal_overflow': False},
                    'expected_text': [{'text': 'Title', 'visible': True}], 'clicks': [],
                    'console_errors': [], 'visual_review_passed': True,
                    'screenshot': {'source': 'cua-tool-output', 'mime_type': 'image/png',
                                   'header_bytes': [137, 80, 78, 71, 13, 10, 26, 10], 'byte_length': 12779,
                                   'captured_at': '2026-09-13T00:01:00Z'}}]}]}
    observation = root / 'browser-observation.json'
    for path, value in ((proof / 'preview.json', preview), (proof / 'stopped.json', stopped), (observation, observed)):
        workflow.save(path, value)
    (root / 'preview-starts.jsonl').write_bytes(canonical_bytes({'index': 1,
        'packet_sha256': packet_hash, 'snapshot_sha256': browser.digest(done['pending_snapshot']), 'attempt': 1}) + b'\n')
    monkeypatch.setattr(browser, 'require_active_session', lambda: None)
    probe = Mock()
    probe.connect_ex.return_value = errno.ECONNREFUSED
    socket = Mock()
    socket.__enter__ = Mock(return_value=probe)
    socket.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(browser.socket, 'socket', lambda *args, **kwargs: socket)
    return {'root': root, 'kernel': kernel, 'packet': packet, 'events': events,
            'observation': observation, 'observed': observed, 'probe': probe}


def test_browser_terminal_receipt_precedes_visible_success(pending):
    root, kernel = pending['root'], pending['kernel']
    original = (root / 'ollama-1' / 'attempt.json').read_bytes()
    complete = kernel.complete_attempt
    def close(packet, run_id, ordinal, path):
        assert workflow.read_result(root)['state'] == 'awaiting_browser_validation'
        return complete(packet, run_id, ordinal, path)
    kernel.complete_attempt = close
    done = browser.finish_browser(root, pending['observation'], kernel=kernel)
    assert done['state'] == 'candidate_ready'
    assert (root / 'ollama-1' / 'attempt.json').read_bytes() == original
    terminal = strict_json((root / 'ollama-1' / 'attempt.browser-final.json').read_bytes())
    binding = terminal['browser_finalization']
    assert binding['original_receipt_sha256'] == hashlib.sha256(original).hexdigest()
    for name in ('observations', 'closure'):
        assert binding[name + '_sha256'] == hashlib.sha256(Path(binding[name]).read_bytes()).hexdigest()
    assert terminal['passed'] is True
    assert len(kernel.completed) == 2
    assert pending['events'].count('generate:1') == 1


def test_failed_browser_receipt_closes_same_slot_then_resumes_next(pending):
    observed = copy.deepcopy(pending['observed'])
    observed['packs'][0]['viewports'][0]['expected_text'][0]['visible'] = False
    pending['observation'].write_bytes(canonical_bytes(observed))
    kernel = pending['kernel']
    done = browser.finish_browser(pending['root'], pending['observation'], kernel=kernel)
    assert done['state'] == 'retry_required'
    terminal = kernel.completed[-1]
    assert terminal['passed'] is False and terminal['error_code'] == 'BROWSER_CHECK_FAILED'
    resumed = workflow.run_pipeline(pending['packet'], 'browser-run', kernel=kernel, resume=True)
    assert resumed['state'] == 'awaiting_browser_validation'
    assert resumed['attempts'][-1]['number'] == 2
    assert pending['events'].count('generate:1') == 1 and pending['events'].count('generate:2') == 1


def test_interrupted_browser_close_is_idempotent_and_never_publishes_success(pending):
    root, kernel = pending['root'], pending['kernel']
    complete = kernel.complete_attempt
    def unavailable(*args):
        raise OSError('Synthetic closure storage failure')
    kernel.complete_attempt = unavailable
    with pytest.raises(OSError):
        browser.finish_browser(root, pending['observation'], kernel=kernel)
    terminal_path = root / 'ollama-1' / 'attempt.browser-final.json'
    preserved = terminal_path.read_bytes()
    assert workflow.read_result(root)['state'] == 'awaiting_browser_validation'
    kernel.complete_attempt = complete
    done = browser.finish_browser(root, pending['observation'], kernel=kernel)
    assert done['state'] == 'candidate_ready'
    assert terminal_path.read_bytes() == preserved
    assert pending['events'].count('generate:1') == 1


def test_pending_browser_rejects_missing_cleanup_and_receipt_drift(pending):
    root = pending['root']
    current = workflow.read_result(root)
    current['cleanup'] = {'passed': True}
    workflow.store_result(root, current)
    with pytest.raises(EngineFailure):
        browser.pending_run(root, kernel=pending['kernel'])
    pending['probe'].connect_ex.assert_not_called()


def test_browser_resume_requires_exact_final_receipt(pending):
    observed = copy.deepcopy(pending['observed'])
    observed['packs'][0]['viewports'][0]['expected_text'][0]['visible'] = False
    pending['observation'].write_bytes(canonical_bytes(observed))
    browser.finish_browser(pending['root'], pending['observation'], kernel=pending['kernel'])
    current = workflow.read_result(pending['root'])
    current['attempts'][0]['error_code'] = 'ALTERED'
    workflow.store_result(pending['root'], current)
    with pytest.raises(workflow.ContractError, match='browser-final'):
        workflow.run_pipeline(pending['packet'], 'browser-run', kernel=pending['kernel'], resume=True)
    assert 'generate:2' not in pending['events']
