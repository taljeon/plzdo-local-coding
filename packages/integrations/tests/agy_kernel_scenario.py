"""Fresh real-Kernel scenario; the AGY process boundary is a fixed test double."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile

integration = Path(__file__).resolve().parents[1]
runtime = integration.parents[1]
sys.path[:0] = [str(integration), str(runtime), str(runtime.parent / 'plzdo'), sys.argv[1]]

from local_coding.api import EngineFailure, canonical_bytes, strict_json
from plzdo_private_overlay import agy_context, agy_transport, transports
from plzdo_private_overlay.orchestration import compose


def refusal(call):
    try:
        call()
    except (ValueError, RuntimeError):
        return
    raise AssertionError('Unexpectedly admitted operation')


with tempfile.TemporaryDirectory(prefix='plzdo-agy-kernel-') as directory:
    root = Path(directory).resolve()
    home = root / 'synthetic-account'
    home.mkdir(mode=0o700)
    agy_context.account_home = lambda: home
    binary = root / 'never-execute-provider'
    binary.write_bytes(b'fixture, not a provider\n')
    binary.chmod(0o700)
    other_pin = {'path': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
    agy_pin = {'path': str(binary), 'sha256': agy_transport.AGY_BINARY_SHA256}
    agy_transport.verified_runtime = lambda pin: {**agy_pin, 'size': 24, 'mode': 0o700, 'device': 1, 'inode': 1}
    kernel = compose({'schemaVersion': 'plzdo.private-config.v1', 'stateRoot': str(root / 'state'),
        'providerPins': {'codex-openai': other_pin, 'claude': other_pin, 'grok-cli': other_pin, 'agy': agy_pin},
        'agyModel': 'gemini-3.8-flash-high', 'agyGlobalRulesSha256': None})
    assert len(kernel.policy.engine_roles) == 5 and kernel.policy.engine_roles['agy'] == ('review',)
    assert kernel.policy.generation_order == ('ollama', 'codex-openai')
    assert kernel.policy.generation_limits == {'ollama': 2, 'codex-openai': 1}
    packet = {'kind': 'artifact-create', 'id': 'synthetic', 'authorityId': 'agy-review',
        'objective': 'Review a synthetic design only', 'allowed_paths': ['unused.txt'],
        'generation_profile': 'huihui-qwen38-q6kl-v1', 'local_attempts': 1,
        'checks': [['/usr/bin/true']]}
    draft = kernel.draft_contract('agy-review', [packet],
        expires_at=(datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        max_live_integration_calls=2, allowed_engines=['agy'])
    digest = kernel.payload_sha256(draft)
    kernel.approve_contract('agy-review', expected_payload_sha256=digest,
                            confirmation='APPROVE agy-review ' + digest)
    prompt = canonical_bytes('Review this synthetic design only.')
    schema = canonical_bytes(transports.REVIEW_SCHEMA)
    calls = []
    def fake_process(argv, cwd, evidence, timeout, **kwargs):
        calls.append(argv)
        evidence.mkdir(parents=True)
        conversation = 'c3b66b04-872b-4fbe-a3a4-058a026ef20a'
        value = {'verdict': 'pass', 'summary': 'Synthetic review.', 'issues': [], 'plan': []}
        answer = json.dumps(value)
        rows = [
            {'event': 'init', 'conversation_id': conversation, 'init': {'cwd': str(cwd),
                'tools': ['read_file'], 'permission_mode': 'request-review',
                'model': 'gemini-3.8-flash-high'}},
            {'event': 'step_update', 'step_update': {'conversation_id': conversation, 'step_index': 0,
                'state': 'DONE', 'step_type': 'user_input'}},
            {'event': 'step_update', 'step_update': {'conversation_id': conversation, 'step_index': 2,
                'state': 'DONE', 'step_type': 'agent_response', 'text_delta': answer}},
            {'event': 'result', 'result': {'conversation_id': conversation, 'status': 'SUCCESS',
                'response': answer, 'duration_seconds': 1, 'num_turns': 1,
                'usage': {'input_tokens': 1, 'output_tokens': 1}}},
        ]
        if len(calls) == 2:
            rows[2]['step_update'].update(step_type='tool', tool_name='read_file')
        (evidence / 'events.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        (evidence / 'stderr.log').write_text('')
        return {'return_code': 0, 'child_exit_code': 0, 'timed_out': False, 'error': None,
            'cleanup': {'schema': 'plzdo.engine-cleanup.v1', 'completed': True, 'passed': True,
                        'owned': True, 'started': True, 'scope': 'initial-posix-process-group'}}
    agy_transport.run_bounded = fake_process
    refusal(lambda: kernel.reserve_review(packet, 'agy', 'generate', '0' * 64, prompt, schema))
    first = kernel.reserve_review(packet, 'agy', 'review', '1' * 64, prompt, schema)
    refusal(lambda: kernel.dispatch_review(packet, first['reservation_id'],
        canonical_bytes('changed input'), schema, kernel.state_root / 'wrong-bytes'))
    assert calls == []
    result = kernel.dispatch_review(packet, first['reservation_id'], prompt, schema, kernel.state_root / 'review-one')
    assert strict_json(result.payload_bytes)['verdict'] == 'pass'
    refusal(lambda: kernel.dispatch_review(packet, first['reservation_id'], prompt, schema,
                                           kernel.state_root / 'replay'))
    second = kernel.reserve_review(packet, 'agy', 'review', '2' * 64, prompt, schema)
    try:
        kernel.dispatch_review(packet, second['reservation_id'], prompt, schema, kernel.state_root / 'review-two')
    except EngineFailure as failure:
        assert failure.retryable is False and failure.cleanup['passed'] is True
    else:
        raise AssertionError('Observed tool activity was accepted')
    refusal(lambda: kernel.dispatch_review(packet, second['reservation_id'], prompt, schema,
                                           kernel.state_root / 'failed-replay'))
    refusal(lambda: kernel.reserve_review(packet, 'agy', 'review', '3' * 64, prompt, schema))
    assert len(calls) == 2
    receipts = [strict_json(path.read_bytes()) for path in (kernel.state_root / 'engine-receipts').glob('*.json')]
    assert len(receipts) == 2 and sorted(item['succeeded'] for item in receipts) == [False, True]
    assert all(item['cleanup']['passed'] is True for item in receipts)
    print(json.dumps({'private_registry': 5, 'bounded_fake_dispatches': 2,
        'failed_send_consumed': True, 'replay_refused': True, 'provider_calls': 0}))
