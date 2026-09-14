"""Native AGY boundary fixtures only; no AGY binary, auth, or model execution."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

import pytest

from local_coding.api import EngineFailure, Work, canonical_bytes, no_start_cleanup, strict_json
from plzdo_private_overlay import agy_context, agy_transport, engines, transports
from plzdo_private_overlay.cli import _parser
from plzdo_private_overlay.orchestration import load_config


MODEL = 'gemini-3.8-flash-high'
CONVERSATION = 'c3b66b04-872b-4fbe-a3a4-058a026ef20a'
REVIEW = {'verdict': 'pass', 'summary': 'Synthetic review only.', 'issues': [], 'plan': []}
RECEIPT = {'schema': 'plzdo.engine-cleanup.v1', 'completed': True, 'passed': True,
           'owned': True, 'started': True, 'scope': 'initial-posix-process-group'}


@pytest.fixture
def account(tmp_path, monkeypatch):
    home = tmp_path / 'fixture-account'
    home.mkdir(mode=0o700)
    monkeypatch.setattr(agy_context, 'account_home', lambda: home)
    return home


def save(home, relative, data):
    path = home / relative
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def transcript(cwd, *, model=MODEL, review=None):
    review = review or REVIEW
    response = json.dumps(review)
    split = len(response) // 2
    return [
        {'event': 'init', 'conversation_id': CONVERSATION, 'init': {
            'cwd': str(cwd), 'tools': ['ask_permission', 'run_command', 'write_to_file'],
            'permission_mode': 'request-review', 'model': model}},
        {'event': 'step_update', 'step_update': {'conversation_id': CONVERSATION,
            'step_index': 0, 'state': 'DONE', 'step_type': 'user_input'}},
        {'event': 'step_update', 'step_update': {'conversation_id': CONVERSATION,
            'step_index': 2, 'state': 'ACTIVE', 'step_type': 'agent_response', 'text_delta': response[:split]}},
        {'event': 'step_update', 'step_update': {'conversation_id': CONVERSATION,
            'step_index': 2, 'state': 'DONE', 'step_type': 'agent_response', 'text_delta': response[split:]}},
        {'event': 'step_update', 'step_update': {'conversation_id': CONVERSATION,
            'step_index': 3, 'state': 'DONE', 'step_type': 'checkpoint'}},
        {'event': 'result', 'result': {'conversation_id': CONVERSATION, 'status': 'SUCCESS',
            'response': response, 'duration_seconds': 1.2, 'num_turns': 1,
            'usage': {'input_tokens': 12, 'output_tokens': 10, 'total_tokens': 22}}},
    ]


def encoded(events):
    return ''.join(json.dumps(value) + '\n' for value in events)


def parse(events, cwd):
    return agy_transport.parse_stream(encoded(events), cwd=cwd, model=MODEL)


def fixture_engine(tmp_path, monkeypatch, *, rules=None, operation='review'):
    pin = {'path': str(tmp_path / 'never-execute-agy'), 'sha256': agy_transport.AGY_BINARY_SHA256}
    identity = {**pin, 'size': 7, 'mode': 0o700, 'device': 1, 'inode': 2}
    monkeypatch.setattr(agy_transport, 'verified_runtime', lambda selected: identity)
    engine = engines.ExternalEngine('agy', canonical_bytes(pin), MODEL, rules)
    work = Work(operation, canonical_bytes('Review this synthetic design: preserve input bytes.'),
                canonical_bytes(transports.REVIEW_SCHEMA), canonical_bytes({}),
                30, tmp_path / 'evidence', 'synthetic-reservation')
    return engine, work


def process_result(destination, events, *, stderr=''):
    destination = Path(destination)
    destination.mkdir(parents=True)
    (destination / 'events.jsonl').write_text(encoded(events))
    (destination / 'stderr.log').write_text(stderr)
    return {'return_code': 0, 'child_exit_code': 0, 'timed_out': False, 'error': None,
            'cleanup': dict(RECEIPT), 'supervisor_stop': False}


def test_context_admits_only_hash_bound_generic_rules_and_records_no_contents(account):
    raw = b'Think carefully and state uncertainty.\n'
    save(account, '.gemini/GEMINI.md', raw)
    save(account, '.gemini/settings.json', b'{"selectedAuthType":"oauth-personal","theme":"Default"}')
    save(account, '.gemini/config/mcp_config.json', b'')
    digest = hashlib.sha256(raw).hexdigest()
    result = agy_context.snapshot(digest)
    assert result['globalRulesSha256'] == digest
    assert result['globalRulesAdmission'] == 'operator-admitted-generic-context'
    assert result['contentsRecorded'] is False and result['credentialStoresRead'] is False
    assert raw.decode().strip() not in json.dumps(result)
    assert 'oauth-personal' not in json.dumps(result) and str(account) not in json.dumps(result)
    assert result == agy_context.snapshot(digest)
    with pytest.raises(transports.ProviderError, match='admitted hash'):
        agy_context.snapshot(None)
    with pytest.raises(transports.ProviderError, match='admitted hash'):
        agy_context.snapshot('0' * 64)


def test_rules_cannot_expand_unpinned_file_references(account):
    raw = b'Also read @another-file.md\n'
    save(account, '.gemini/GEMINI.md', raw)
    with pytest.raises(transports.ProviderError, match='unbound file reference'):
        agy_context.snapshot(hashlib.sha256(raw).hexdigest())


def test_native_model_and_home_trust_are_exact_admitted_state(account):
    path = save(account, '.gemini/antigravity-cli/settings.json', json.dumps({
        'model': 'Gemini 3.8 Flash (High)', 'trustedWorkspaces': [str(account)]}).encode())
    before = agy_context.snapshot(None)
    assert before['snapshotAtomic'] is False
    assert 'not-an-added-workspace' in before['nativeTrustAdmission']
    assert str(account) not in json.dumps(before)
    for trusted in [['/'], [str(account / 'another-workspace')], [str(account), '/another'], ['*'], True]:
        path.write_text(json.dumps({'model': 'Gemini 3.8 Flash (High)', 'trustedWorkspaces': trusted}))
        with pytest.raises(transports.ProviderError, match='native trust'):
            agy_context.snapshot(None)


def test_empty_global_file_is_not_null_and_broken_symlink_is_not_absence(account):
    path = save(account, '.gemini/GEMINI.md', b'')
    with pytest.raises(transports.ProviderError, match='admitted hash'):
        agy_context.snapshot(None)
    assert agy_context.snapshot(hashlib.sha256(b'').hexdigest())['globalRulesAdmission'] != 'absent'
    path.unlink()
    path.symlink_to(account / 'does-not-exist')
    with pytest.raises(transports.ProviderError):
        agy_context.snapshot(None)


@pytest.mark.parametrize('relative,raw', [
    ('.gemini/.env', b'PASSWORD=synthetic-must-not-be-read\n'),
    ('.gemini/config/AGENTS.md', b'unadmitted additional instructions\n'),
    ('.gemini/GEMINI.md', b'unadmitted global instructions\n'),
    ('.gemini/GEMINI.md', b''),
])
def test_unadmitted_empty_only_or_null_rules_refuse_without_content_reads(account, monkeypatch, relative, raw):
    save(account, relative, raw)
    monkeypatch.setattr(agy_context, '_bounded_read',
                        lambda *args, **kwargs: pytest.fail('unadmitted ambient contents were read'))
    with pytest.raises(transports.ProviderError):
        agy_context.snapshot(None)


@pytest.mark.parametrize('relative,data', [
    ('.gemini/settings.json', b'{"mcpServers":{"x":{}}}'),
    ('.gemini/config/settings.json', b'{"permissions":{"allow":["command(*)"]}}'),
    ('.gemini/antigravity-cli/settings.json', b'{"toolPermission":"always-proceed"}'),
    ('.gemini/antigravity/settings.json', b'{"statusLine":{"command":"unsafe"}}'),
    ('.gemini/settings.json', b'{"selectedAuthType":"gemini-api-key"}'),
    ('.gemini/config/mcp_config.json', b'{"mcpServers":{"service":{"command":"unsafe"}}}'),
    ('.gemini/antigravity-cli/hooks.json', b'{"hooks":{"SessionStart":[{}]}}'),
    ('.gemini/AGENTS.md', b'extra context'),
    ('.gemini/config/GEMINI.md', b'extra context'),
    ('.gemini/antigravity-cli/.env', b'UNSUPPORTED=1'),
    ('.gemini/settings.json', b'{"theme":"Default","theme":"Other"}'),
])
def test_ambient_configs_refuse_unknown_capabilities(account, relative, data):
    save(account, relative, data)
    with pytest.raises((ValueError, RuntimeError)):
        agy_context.snapshot(None)


@pytest.mark.parametrize('base', agy_context.GLOBAL_ROOTS)
@pytest.mark.parametrize('name', ['hooks', 'skills', 'agents', 'plugins', 'rules', 'extensions'])
def test_shared_and_legacy_customization_sources_refuse(account, base, name):
    save(account, base + '/' + name + '/unread-private-content', b'do not read this')
    with pytest.raises(transports.ProviderError, match='not empty'):
        agy_context.snapshot(None)


def test_context_rejects_symlinks_hardlinks_and_permission_drift(account):
    source = save(account, 'outside', b'{}')
    target = account / '.gemini/settings.json'
    target.parent.mkdir(mode=0o700)
    target.symlink_to(source)
    with pytest.raises(transports.ProviderError):
        agy_context.snapshot(None)
    target.unlink()
    os.link(source, target)
    with pytest.raises(transports.ProviderError):
        agy_context.snapshot(None)
    target.unlink()
    target.write_bytes(b'{}')
    first = agy_context.snapshot(None)
    target.chmod(0o600)
    assert first != agy_context.snapshot(None)
    target.chmod(0o666)
    with pytest.raises(transports.ProviderError):
        agy_context.snapshot(None)


@pytest.mark.parametrize('name', ['GEMINI_API_KEY', 'GOOGLE_APPLICATION_CREDENTIALS',
    'AGY_CLI_MODEL_API_MAX_RETRIES', 'JETSKI_APP_DATA_DIR', 'HTTPS_PROXY', 'DYLD_INSERT_LIBRARIES'])
def test_environment_override_refuses_before_any_context_read(account, monkeypatch, name):
    monkeypatch.setenv(name, 'synthetic-override')
    monkeypatch.setattr(agy_context, 'account_home', lambda: pytest.fail('override must refuse first'))
    with pytest.raises(transports.ProviderError, match='override present'):
        agy_context.snapshot(None)


def test_stream_accepts_registered_tools_but_only_completed_text():
    cwd = Path('/synthetic/owned-workspace')
    result = parse(transcript(cwd), cwd)
    assert result['review'] == REVIEW and result['observed_model'] == MODEL
    assert result['registered_tools'] == ['ask_permission', 'run_command', 'write_to_file']


@pytest.mark.parametrize('change', [
    lambda rows: rows[0]['init'].update(model='gemini-3.7-flash-high'),
    lambda rows: rows[0]['init'].update(cwd='/another-workspace'),
    lambda rows: rows[0]['init'].update(permission_mode='always-proceed'),
    lambda rows: rows[0]['init'].update(json_schema={'type': 'object'}),
    lambda rows: rows[0]['init'].update(agent='custom-agent'),
    lambda rows: rows[2]['step_update'].update(step_type='tool', tool_name='read_file'),
    lambda rows: rows[2]['step_update'].update(step_type='tool', tool_name='finish'),
    lambda rows: rows[2]['step_update'].update(step_type='tool', tool_name='FINISH'),
    lambda rows: rows[2]['step_update'].update(step_type='tool', tool_name='StructuredOutput'),
    lambda rows: rows[2]['step_update'].update(tool_info={}),
    lambda rows: rows[2]['step_update'].update(subagent_info={}),
    lambda rows: rows[2]['step_update'].update(state='ERROR'),
    lambda rows: rows[2]['step_update'].update(step_index=True),
    lambda rows: rows[3]['step_update'].update(state='ACTIVE'),
    lambda rows: rows[-1]['result'].update(status='ERROR'),
    lambda rows: rows[-1]['result'].update(num_turns=2),
    lambda rows: rows[-1]['result'].update(num_turns=True),
    lambda rows: rows[-1]['result'].update(json_schema={'type': 'object'}),
    lambda rows: rows[-1]['result'].update(structured_output=REVIEW),
    lambda rows: rows[-1]['result'].update(response='{}'),
    lambda rows: rows[-1]['result'].update(error='permission denied'),
    lambda rows: rows[-1]['result'].update(usage={'tool_calls': 1}),
    lambda rows: rows[-1]['result'].update(conversation_id='another-conversation'),
    lambda rows: rows.append(deepcopy(rows[-1])),
    lambda rows: rows.insert(1, deepcopy(rows[0])),
    lambda rows: rows.pop(),
])
def test_stream_rejects_malformed_mismatched_or_active_results(change):
    cwd = Path('/synthetic/workspace')
    events = deepcopy(transcript(cwd))
    change(events)
    with pytest.raises((ValueError, RuntimeError)):
        parse(events, cwd)


def test_stream_parser_handles_partial_utf8_without_hiding_completed_tool_event(tmp_path):
    path = tmp_path / 'events.jsonl'
    cwd = Path('/synthetic/workspace')
    events = transcript(cwd)
    events[2]['step_update']['step_type'] = 'tool'
    path.write_bytes(encoded(events[:3]).encode() + b'{"partial":"\xed\x95')
    with pytest.raises(transports.ProviderError, match='tool'):
        agy_transport.parse_stream(agy_transport._complete_event_lines(path), cwd=cwd, model=MODEL,
                                   complete=False)


def test_native_review_uses_shared_deadline_and_one_closed_dispatch(account, tmp_path, monkeypatch):
    engine, work = fixture_engine(tmp_path, monkeypatch)
    markers = {'META_HARNESS_HEARTBEAT_LANE': 'false', 'META_HARNESS_ORIGIN': 'interactive',
               'CI': '0', 'LOCAL_CODING_UNATTENDED': '0'}
    for name, value in markers.items():
        monkeypatch.setenv(name, value)
    clock = [work.deadline_monotonic - 30]
    monkeypatch.setattr(transports, 'monotonic', lambda: clock[0])
    original = transports._open_evidence
    def slow_open(work, trace):
        result = original(work, trace)
        clock[0] += 7
        return result
    monkeypatch.setattr(transports, '_open_evidence', slow_open)
    calls = []
    def run(argv, cwd, destination, timeout, **kwargs):
        calls.append((argv, cwd, timeout))
        assert timeout == pytest.approx(23)
        assert argv[argv.index('--print-timeout') + 1] == '22000ms'
        assert argv[argv.index('--model') + 1] == MODEL
        assert all(flag in argv for flag in ('--sandbox', '--disable-slash-commands', '--new-project'))
        assert not any(flag in argv for flag in ('--continue', '--conversation', '--project',
            '--dangerously-skip-permissions', '--add-dir', '--agent', '--mode', '--json-schema'))
        assert argv[argv.index('--log-file') + 1] == os.devnull
        sent_prompt = argv[argv.index('-p') + 1]
        assert sent_prompt == agy_transport.build_provider_prompt(strict_json(work.prompt_bytes))
        assert canonical_bytes(transports.REVIEW_SCHEMA).decode('utf-8') in sent_prompt
        assert 'Do not call finish, FINISH, StructuredOutput' in sent_prompt
        assert kwargs['env_allowlist'] == frozenset({'HOME', *markers})
        assert {name: os.environ[name] for name in markers} == markers
        assert not set(markers).intersection(kwargs['env_override'])
        assert kwargs['env_override']['AGY_CLI_DISABLE_AUTO_UPDATE'] == 'true'
        assert kwargs['env_override']['PATH'] == os.defpath
        assert 'HOME' not in kwargs['env_override'] and 'CODEX_HOME' not in kwargs['env_override']
        assert list(Path(cwd).iterdir()) == [] and not Path(destination).is_relative_to(cwd)
        result = process_result(destination, transcript(cwd))
        assert kwargs['stop_check']() is None
        return result
    monkeypatch.setattr(agy_transport, 'run_bounded', run)
    result = engine.execute(work)
    assert strict_json(result.payload_bytes) == REVIEW and len(calls) == 1
    assert result.cleanup == RECEIPT
    assert result.evidence['adapter_retries'] == 0 and result.evidence['adapter_dispatches'] == 1
    assert result.evidence['context_matches_after'] is True and result.evidence['workspace_unchanged'] is True
    assert result.evidence['tools_disabled'] is False
    assert result.evidence['native_schema_enforcement'] is False
    sent_prompt = calls[0][0][calls[0][0].index('-p') + 1]
    assert result.evidence['provider_prompt_sha256'] == hashlib.sha256(sent_prompt.encode()).hexdigest()
    assert result.evidence['work_prompt_sha256'] == hashlib.sha256(work.prompt_bytes).hexdigest()
    assert result.evidence['provider_prompt_bytes'] == len(sent_prompt.encode())
    input_evidence = strict_json((work.evidence_dir / 'provider-input.json').read_bytes())
    assert input_evidence['provider_prompt_sha256'] == result.evidence['provider_prompt_sha256']
    assert sent_prompt not in json.dumps(input_evidence)
    assert not calls[0][1].exists()


@pytest.mark.parametrize('event_index', [0, -1])
def test_native_schema_fields_are_forbidden_in_plain_text_protocol(event_index):
    cwd = Path('/synthetic/workspace')
    events = deepcopy(transcript(cwd))
    key = 'init' if event_index == 0 else 'result'
    events[event_index][key]['json_schema'] = transports.REVIEW_SCHEMA
    with pytest.raises(transports.ProviderError, match='differs'):
        parse(events, cwd)


def test_provider_prompt_transform_is_deterministic_and_payload_sensitive():
    first = agy_transport.build_provider_prompt('Synthetic work A')
    assert first == agy_transport.build_provider_prompt('Synthetic work A')
    assert first.startswith('Synthetic work A\n\n')
    assert first != agy_transport.build_provider_prompt('Synthetic work B')
    assert transports.sha256(first.encode()) != transports.sha256(
        agy_transport.build_provider_prompt('Synthetic work B').encode())


def test_appended_instructions_cannot_exceed_provider_input_bound(account, tmp_path, monkeypatch):
    engine, work = fixture_engine(tmp_path, monkeypatch)
    prompt = 'x' * (transports.MAX_BUNDLE_BYTES - 2)
    changed = Work(work.operation, canonical_bytes(prompt), work.schema_bytes, work.profile_bytes,
                   work.timeout_seconds, work.evidence_dir, work.reservation_id)
    monkeypatch.setattr(agy_transport, 'run_bounded', lambda *a, **k: pytest.fail('oversized prompt started a provider'))
    with pytest.raises(EngineFailure, match='96000-byte limit') as error:
        engine.execute(changed)
    assert error.value.cleanup == no_start_cleanup()


def test_plain_response_requires_host_schema_validation_and_matching_fragments():
    cwd = Path('/synthetic/workspace')
    invalid = {'verdict': 'pass', 'summary': 'Missing required fields'}
    with pytest.raises(transports.ProviderError, match='required object'):
        parse(transcript(cwd, review=invalid), cwd)
    events = transcript(cwd)
    events[-1]['result']['response'] = json.dumps({**REVIEW, 'summary': 'A different valid review'})
    with pytest.raises(transports.ProviderError, match='captured response'):
        parse(events, cwd)


def test_requested_schema_boolean_drift_refuses_before_dispatch(account, tmp_path, monkeypatch):
    engine, work = fixture_engine(tmp_path, monkeypatch)
    schema = deepcopy(transports.REVIEW_SCHEMA)
    schema['additionalProperties'] = 0
    changed = Work(work.operation, work.prompt_bytes, canonical_bytes(schema), work.profile_bytes,
                   work.timeout_seconds, work.evidence_dir, work.reservation_id)
    monkeypatch.setattr(agy_transport, 'run_bounded', lambda *a, **k: pytest.fail('schema drift started a provider'))
    with pytest.raises(EngineFailure, match='fixed advisory review schema') as error:
        engine.execute(changed)
    assert error.value.cleanup == no_start_cleanup()


@pytest.mark.parametrize('failure', ['ambient', 'workspace', 'denial', 'tool', 'timeout', 'cleanup'])
def test_postlaunch_failure_preserves_cleanup_and_never_retries(account, tmp_path, monkeypatch, failure):
    engine, work = fixture_engine(tmp_path, monkeypatch)
    calls = []
    def run(argv, cwd, destination, timeout, **kwargs):
        calls.append(argv)
        events = transcript(cwd)
        if failure == 'ambient':
            save(account, '.gemini/settings.json', b'{"theme":"Changed"}')
        if failure == 'workspace':
            Path(cwd).chmod(0o700)
            (Path(cwd) / 'unexpected-file').write_text('synthetic change')
        if failure == 'tool':
            events[2]['step_update'].update(step_type='tool', tool_name='write_to_file')
        result = process_result(destination, events,
            stderr='Tool is denied and requires approval.\n' if failure == 'denial' else '')
        if failure in {'denial', 'tool'}:
            assert kwargs['stop_check']() == 'agy-observed-boundary-failure'
        if failure == 'timeout':
            result.update(timed_out=True, return_code=124)
        if failure == 'cleanup':
            result.pop('cleanup')
        return result
    monkeypatch.setattr(agy_transport, 'run_bounded', run)
    with pytest.raises(EngineFailure) as error:
        engine.execute(work)
    assert len(calls) == 1 and error.value.retryable is False
    assert error.value.cleanup == ({} if failure == 'cleanup' else RECEIPT)
    assert not (work.evidence_dir / 'review.json').exists()


@pytest.mark.parametrize('failure', ['rules', 'expiry', 'role'])
def test_preflight_failure_explicitly_never_starts_provider(account, tmp_path, monkeypatch, failure):
    engine, work = fixture_engine(tmp_path, monkeypatch, operation='generate' if failure == 'role' else 'review')
    if failure == 'rules':
        save(account, '.gemini/GEMINI.md', b'unapproved context')
    if failure == 'expiry':
        monkeypatch.setattr(transports, 'monotonic', lambda: work.deadline_monotonic)
    monkeypatch.setattr(agy_transport, 'run_bounded', lambda *a, **k: pytest.fail('no launch authorized'))
    with pytest.raises(EngineFailure) as error:
        engine.execute(work)
    assert error.value.cleanup == no_start_cleanup()


def test_config_and_cli_require_exact_agy_inputs_without_a_generation_role(account, tmp_path):
    pin = {'path': '/synthetic/never-execute-agy', 'sha256': agy_transport.AGY_BINARY_SHA256}
    config = {'schemaVersion': 'plzdo.private-config.v1', 'stateRoot': str(tmp_path / 'state'),
              'providerPins': {'agy': pin}, 'agyModel': MODEL, 'agyGlobalRulesSha256': None}
    path = tmp_path / 'private.json'
    path.write_text(json.dumps(config))
    assert load_config(path) == config and engines.ROLES['agy'] == ('review',)
    for key in ('agyModel', 'agyGlobalRulesSha256'):
        bad = deepcopy(config)
        del bad[key]
        path.write_text(json.dumps(bad))
        with pytest.raises((ValueError, RuntimeError)):
            load_config(path)
    for model in ('gemini', 'gemini-3.8', 'claude-sonnet-4-6', MODEL + ' --dangerously-skip-permissions'):
        with pytest.raises((ValueError, RuntimeError)):
            engines.fixed_engines({'agy': pin}, agy_model=model, agy_global_rules_sha256=None)
    with pytest.raises((ValueError, RuntimeError)):
        engines.fixed_engines({}, agy_model=MODEL, agy_global_rules_sha256=None)
    with pytest.raises((ValueError, RuntimeError)):
        engines.ExternalEngine('agy', canonical_bytes({**pin, 'sha256': '0' * 64}), MODEL)
    args = _parser().parse_args(['review', '--packet', '/packet', '--engine', 'agy', '--bundle',
                                '/bundle', '--id', 'synthetic', '--evidence-dir', '/evidence'])
    assert args.engine == 'agy'


def test_agy_identity_binds_model_global_rules_and_ambient_settings(account, tmp_path, monkeypatch):
    engine, _ = fixture_engine(tmp_path, monkeypatch)
    first = engine.identity()
    save(account, '.gemini/settings.json', b'{"theme":"Default"}')
    assert first != engine.identity()
    second = engines.ExternalEngine('agy', engine.pin_bytes, 'gemini-3.8-flash-medium')
    assert second.identity() != engine.identity()
    raw = b'Generic reasoning guidance only.\n'
    save(account, '.gemini/GEMINI.md', raw)
    pinned = engines.ExternalEngine('agy', engine.pin_bytes, MODEL, hashlib.sha256(raw).hexdigest())
    assert pinned.identity() != first
    with pytest.raises(transports.ProviderError):
        engine.identity()
