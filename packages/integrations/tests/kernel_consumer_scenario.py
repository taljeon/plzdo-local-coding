"""One fresh-process, fake-provider integration scenario; never launch providers."""
from pathlib import Path
from datetime import datetime, timedelta, timezone
import hashlib
import json
import shutil
import sys
import tempfile

integration = Path(__file__).resolve().parents[1]
runtime = integration.parents[1]
sys.path[:0] = [str(integration), str(runtime), str(runtime.parent / 'plzdo'), sys.argv[1]]

from local_coding.api import canonical_bytes, strict_json, no_start_cleanup, WorkResult
from plzdo_private_overlay.orchestration import compose, run_private
from plzdo_private_overlay import engines, grok_admission, transports


def check_refusal(call):
    try:
        call()
    except (ValueError, RuntimeError):
        return
    raise AssertionError('operation unexpectedly escaped its boundary')


with tempfile.TemporaryDirectory(prefix='plzdo-private-consumer-') as temporary:
    root = Path(temporary).resolve()
    binary = root / 'fixture-provider'
    binary.write_bytes(b'fixture executable; never launch\n')
    binary.chmod(0o700)
    pin = {'path': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
    kernel = compose({'schemaVersion': 'plzdo.private-config.v1', 'stateRoot': str(root / 'state'),
                      'providerPins': {'codex-openai': pin, 'grok-cli': pin}})
    packet = {'kind': 'artifact-create', 'id': 'fixture', 'authorityId': 'private-review',
              'objective': 'Synthetic bounded fixture', 'allowed_paths': ['answer.txt'],
              'generation_profile': 'huihui-qwen38-q6kl-v1', 'local_attempts': 1,
              'checks': [['/usr/bin/true']]}
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    draft = kernel.draft_contract('private-review', [packet], expires_at=expiry,
        max_live_integration_calls=2, allowed_engines=['codex-openai', 'grok-cli'])
    value_hash = kernel.payload_sha256(draft)
    kernel.approve_contract('private-review', expected_payload_sha256=value_hash,
                            confirmation='APPROVE private-review ' + value_hash)
    calls = []
    def fake_codex(work, pin, model, trace, *, deadline):
        calls.append(('codex-openai', work.operation, work.prompt_bytes))
        trace['cleanup'] = no_start_cleanup()
        work.evidence_dir.mkdir()
        transports._save_json(work.evidence_dir / 'owned-cleanup.json', trace['cleanup'])
        if work.operation == 'generate':
            return {'files': [{'path': 'answer.txt', 'content': 'verified fixture\n'}]}
        return {'verdict': 'pass', 'summary': 'Offline fixture', 'issues': [], 'plan': []}
    transports.codex = fake_codex
    prompt, schema = canonical_bytes('Synthetic review'), canonical_bytes(transports.REVIEW_SCHEMA)
    call = kernel.reserve_review(packet, 'codex-openai', 'design-review',
        hashlib.sha256(b'direct-review').hexdigest(), prompt, schema)
    check_refusal(lambda: kernel.dispatch_review(packet, call['reservation_id'],
        canonical_bytes('changed review'), schema, kernel.state_root / 'wrong-input'))
    assert calls == []
    kernel.dispatch_review(packet, call['reservation_id'], prompt, schema, kernel.state_root / 'direct-review')
    check_refusal(lambda: kernel.dispatch_review(packet, call['reservation_id'], prompt,
                                                schema, kernel.state_root / 'duplicate-dispatch'))
    assert len(calls) == 1
    document, binding = kernel.approved_contract(packet)
    prepared = grok_admission.prepare('Synthetic Grok review', directory=root / 'grok-prepared',
        admission_id='review-one', authority_id=document['id'], packet_sha256=binding['packetSha256'],
        state_root=kernel.state_root, policy_fingerprint=document['policyFingerprint'],
        engine_implementation_sha256=document['execution']['enginePins']['grok-cli']['implementationSha256'],
        expires_at=expiry)
    def proof(action, value_hash, *, confirmed):
        assert confirmed is True
        return {'action': action, 'hashPrefix': value_hash[:12], 'flag': True, 'tty': True,
                'foreground': True, 'ttyPath': '/dev/tty', 'actor': 'operator-confirmed-active-session',
                'confirmedAt': grok_admission.now().isoformat(), 'denyMarkersPresent': []}
    grok_admission.foreground_confirmation = proof
    admission = grok_admission.approve(kernel, packet, Path(prepared['prepared_path']), confirmed=True)
    def fake_grok(work, pin, trace, *, deadline):
        calls.append(('grok-cli', work.operation, work.prompt_bytes))
        trace['cleanup'] = no_start_cleanup()
        work.evidence_dir.mkdir()
        transports._save_json(work.evidence_dir / 'owned-cleanup.json', trace['cleanup'])
        return {'text': 'Synthetic reviewed answer', 'authority': 'advisory',
                'source_of_truth': False, 'apply_status': 'not_applied'}
    transports.grok = fake_grok
    sent = grok_admission.send(kernel, Path(admission['admission_path']),
                               kernel.state_root / 'grok-output', confirmed=True)
    imported = grok_admission.import_result(kernel, Path(admission['admission_path']), Path(sent['report_path']))
    assert imported['text'] == 'Synthetic reviewed answer' and imported['provider_call_performed'] is False
    check_refusal(lambda: grok_admission.send(kernel, Path(admission['admission_path']),
                                              kernel.state_root / 'grok-repeat', confirmed=True))
    assert [engine for engine, _, _ in calls] == ['codex-openai', 'grok-cli']
    view = kernel.status('private-review')
    assert len([row for row in view['ledger']['records'] if row['kind'] == 'review']) == 2
    assert len([row for row in view['ledger']['records'] if row['kind'] == 'child-send']) == 1
    assert len([row for row in view['ledger']['records'] if row['kind'] == 'dispatch']) == 2
    assert len([row for row in view['ledger']['records'] if row['kind'] == 'engine-result']) == 2
    before_expiry_records = view['ledger']['records']
    contract_clock, admission_clock = kernel.contracts._now, grok_admission.now
    expired_time = datetime.fromisoformat(expiry) + timedelta(seconds=1)
    kernel.contracts._now = lambda: expired_time
    grok_admission.now = lambda: expired_time
    expired_import = grok_admission.import_result(kernel, Path(admission['admission_path']), Path(sent['report_path']))
    assert expired_import['status'] == 'imported'
    check_refusal(lambda: kernel.reserve_review(packet, 'codex-openai', 'design-review',
        hashlib.sha256(b'after-expiry').hexdigest(), prompt, schema))
    check_refusal(lambda: kernel.dispatch_review(packet, call['reservation_id'], prompt,
                                                schema, kernel.state_root / 'expired-dispatch'))
    assert kernel.status('private-review')['ledger']['records'] == before_expiry_records
    kernel.contracts._now, grok_admission.now = contract_clock, admission_clock
    report_path = Path(sent['report_path'])
    report = strict_json(report_path.read_bytes())
    report['payload']['text'] = 'forged review'
    report['payloadSha256'] = grok_admission.digest(report['payload'])
    report_path.write_bytes(canonical_bytes(report))
    check_refusal(lambda: grok_admission.import_result(kernel, Path(admission['admission_path']), report_path))

    # Real shared pipeline/ledger and candidate scope; engines/check process are
    # synthetic here. Actual checker/transport execution belongs to their gates.
    generation = {**packet, 'authorityId': 'private-generation'}
    draft = kernel.draft_contract('private-generation', [generation], expires_at=expiry,
        max_live_integration_calls=2, allowed_engines=['codex-openai', 'ollama'])
    value_hash = kernel.payload_sha256(draft)
    kernel.approve_contract('private-generation', expected_payload_sha256=value_hash,
                            confirmation='APPROVE private-generation ' + value_hash)
    def fake_ollama(work, identity):
        calls.append(('ollama', work.operation, work.prompt_bytes))
        work.evidence_dir.mkdir()
        return WorkResult(b'not-json', identity, {'synthetic': True}, no_start_cleanup())
    engines.execute_owned_ollama = fake_ollama
    def fake_checks(packet, candidate, evidence):
        return {'passed': True, 'scope': {'passed': True}, 'checks': [
            {'return_code': 0, 'executed': True, 'execution_receipt': {'passed': True}}]}
    kernel.workflow.run_artifact_checks = fake_checks
    result = run_private(kernel, generation, run_name='fallback')
    assert result['state'] == 'candidate_ready', result
    assert [attempt['provider'] for attempt in result['attempts']] == ['ollama', 'codex-openai']
    assert (Path(result['candidate']) / 'answer.txt').read_text() == 'verified fixture\n'
    records = kernel.status('private-generation')['ledger']['records']
    assert len([row for row in records if row['kind'] == 'generate']) == 2
    assert [row['disposition'] for row in records if row['kind'] == 'outcome'] == ['retry', 'accepted']
    check_refusal(lambda: kernel.begin_run(generation, 'another-run'))
    launcher_fixture = root / 'launcher-fixture'
    launcher_fixture.mkdir(mode=0o700)
    original_launcher_directory = engines._launcher_directory
    for name in engines.LAUNCHER_FILES:
        shutil.copyfile(original_launcher_directory() / name, launcher_fixture / name)
    engines._launcher_directory = lambda: launcher_fixture
    launcher_packet = {**packet, 'authorityId': 'launcher-bound'}
    draft = kernel.draft_contract('launcher-bound', [launcher_packet], expires_at=expiry,
        max_live_integration_calls=1, allowed_engines=['codex-openai'])
    value_hash = kernel.payload_sha256(draft)
    kernel.approve_contract('launcher-bound', expected_payload_sha256=value_hash,
                            confirmation='APPROVE launcher-bound ' + value_hash)
    altered = launcher_fixture / 'plzdo-private'
    altered.write_bytes(altered.read_bytes() + b'\n# fixture launcher drift\n')
    check_refusal(lambda: kernel.reserve_review(launcher_packet, 'codex-openai', 'design-review',
        hashlib.sha256(b'launcher-drift').hexdigest(), prompt, schema))
    assert kernel.status('launcher-bound')['ledger']['records'] == []
    engines._launcher_directory = original_launcher_directory
    print(json.dumps({'direct_review': 'passed', 'grok_admission_send_import': 'passed',
                      'durable_dispatch_replay': 'refused', 'forged_import': 'refused',
                      'expired_import': 'passed', 'expired_new_call': 'refused',
                      'shared_pipeline_fallback': 'passed', 'provider_calls': 0,
                      'launcher_drift_before_debit': 'refused',
                      'synthetic_engine_executions': len(calls)}))
