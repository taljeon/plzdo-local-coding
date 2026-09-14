import hashlib
import io
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import tomllib

import pytest

from local_coding.api import (EngineFailure, Work, WorkResult, canonical_bytes,
                              no_start_cleanup, strict_json)
from plzdo_private_overlay import engines, grok_admission, transports
from plzdo_private_overlay.private_hn_backend import verify_parent_snapshot, HNBackendUnsupported


def pin(tmp_path):
    path = tmp_path / 'provider'
    path.write_bytes(b'#!/bin/sh\nexit 99\n')
    path.chmod(0o700)
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def work(tmp_path, operation='generate', schema=None):
    return Work(operation, canonical_bytes('Review only this synthetic fixture.'),
                canonical_bytes(schema or {'type': 'object'}), canonical_bytes({}),
                30, tmp_path / 'evidence', 'reservation-fixture')


def test_roles_and_binary_model_pins_are_closed(tmp_path):
    value = pin(tmp_path)
    engine = engines.ExternalEngine('claude', canonical_bytes(value))
    with pytest.raises(EngineFailure) as error:
        engine.execute(work(tmp_path, 'generate'))
    assert error.value.cleanup == no_start_cleanup()
    with pytest.raises(ValueError):
        engines.fixed_engines({'arbitrary-module': value})
    with pytest.raises(ValueError):
        engines.ExternalEngine('codex-openai', canonical_bytes(value), 'ollama-qwen')
    with pytest.raises(ValueError):
        engines.ExternalEngine('claude', canonical_bytes(value), 'generate-capable-model')


def test_reused_argv_has_no_tool_or_endpoint_escape(tmp_path):
    command = transports.build_codex_command('/exact/codex', 'fixture', tmp_path / 's',
                                             tmp_path / 'r', tmp_path, 'gpt-fixture')
    assert 'model_provider="openai"' in command
    assert command[command.index('--sandbox') + 1] == 'read-only'
    assert 'features.shell_tool=false' in command and '--ignore-user-config' in command
    command = transports.build_claude_command('/exact/claude', 'fixture', 'opus')
    assert command[command.index('--tools') + 1] == '' and '--strict-mcp-config' in command
    assert command[command.index('--model') + 1] == 'opus'
    command = transports.restricted_argv('/exact/grok', tmp_path / 'prompt')
    assert '--no-subagents' in command and '--disable-web-search' in command
    assert command[command.index('--tools') + 1] == ''
    assert command[command.index('--deny') + 1] == '*'


def test_endpoint_and_unattended_overrides_refuse_before_binary_access(tmp_path, monkeypatch):
    monkeypatch.setenv('OPENAI_BASE_URL', 'https://invalid.example')
    monkeypatch.setattr(transports, 'verified_binary', lambda *args: pytest.fail('must not touch provider'))
    with pytest.raises(transports.ProviderError, match='endpoint override'):
        transports.codex(work(tmp_path), {}, None, {}, deadline=transports.monotonic()+30)
    monkeypatch.delenv('OPENAI_BASE_URL')
    monkeypatch.setenv('LOCAL_CODING_UNATTENDED', '1')
    with pytest.raises(transports.ProviderError, match='active user session'):
        transports.require_active_session()


def test_missing_process_cleanup_never_becomes_success(tmp_path, monkeypatch):
    value = pin(tmp_path)
    identity = transports.verified_binary(value['path'], value['sha256'])
    monkeypatch.setattr(transports, 'run_bounded', lambda *args, **kw: {
        'return_code': 0, 'child_exit_code': 0, 'timed_out': False, 'error': None})
    trace = {}
    with pytest.raises(EngineFailure, match='ENGINE_CLEANUP_FAILED'):
        transports._run(identity, [identity['path']], tmp_path, tmp_path, transports.monotonic()+30, trace)
    assert trace['cleanup'] == {}


def test_provider_process_receipt_is_preserved(tmp_path, monkeypatch):
    value = pin(tmp_path)
    identity = transports.verified_binary(value['path'], value['sha256'])
    receipt = {'schema': 'plzdo.engine-cleanup.v1', 'completed': True, 'passed': True,
               'owned': True, 'started': True, 'scope': 'initial-posix-process-group'}
    monkeypatch.setattr(transports, 'run_bounded', lambda *args, **kw: {
        'return_code': 0, 'child_exit_code': 0, 'timed_out': False,
        'error': None, 'cleanup': receipt})
    trace = {}
    transports._run(identity, [identity['path']], tmp_path, tmp_path, transports.monotonic()+30, trace)
    assert trace['cleanup'] == receipt
    assert strict_json((tmp_path / 'owned-cleanup.json').read_bytes()) == receipt


@pytest.mark.parametrize('output_name', ['process/events.jsonl', 'process/stderr.log', 'response.json'])
@pytest.mark.parametrize('extra_byte', [0, 1])
def test_natural_exit_output_limit_keeps_cleanup_and_exact_boundary(tmp_path, monkeypatch, output_name, extra_byte):
    value = pin(tmp_path)
    identity = transports.verified_binary(value['path'], value['sha256'])
    receipt = {'schema': 'plzdo.engine-cleanup.v1', 'completed': True, 'passed': True,
               'owned': True, 'started': True, 'scope': 'initial-posix-process-group'}

    def exited_before_poll(*args, **kwargs):
        # Natural exit can precede the supervisor callback; final acceptance
        # must check all declared outputs independently of that callback.
        output = tmp_path / output_name
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('wb') as stream:
            stream.seek(transports.MAX_RESULT_BYTES + extra_byte - 1)
            stream.write(b'x')
        return {'return_code': 0, 'child_exit_code': 0, 'timed_out': False,
                'error': None, 'cleanup': receipt}

    monkeypatch.setattr(transports, 'run_bounded', exited_before_poll)
    trace = {}
    if extra_byte:
        with pytest.raises(transports.ProviderError, match='output.*bound'):
            transports._run(identity, [identity['path']], tmp_path, tmp_path, transports.monotonic()+30, trace)
    else:
        transports._run(identity, [identity['path']], tmp_path, tmp_path, transports.monotonic()+30, trace)
    assert trace['cleanup'] == receipt and trace['process']['return_code'] == 0
    assert strict_json((tmp_path / 'owned-cleanup.json').read_bytes()) == receipt


def test_engine_identity_binds_config_and_private_source(tmp_path):
    value = pin(tmp_path)
    first = engines.ExternalEngine('codex-openai', canonical_bytes(value), 'gpt-fixture')
    second = engines.ExternalEngine('codex-openai', canonical_bytes(value), 'gpt-other')
    assert first.identity().implementation_sha256 != second.identity().implementation_sha256
    assert first.identity() == first.identity()


def test_personal_ollama_reuses_public_transport(tmp_path, monkeypatch):
    calls = []
    def transport(w, identity):
        calls.append((w, identity))
        return WorkResult(b'{}', identity, {'trust': 'personal-local', 'isolation_verified': False},
                          no_start_cleanup())
    monkeypatch.setattr(engines, 'execute_owned_ollama', transport)
    selected = engines.PersonalOllamaEngine()
    w = work(tmp_path)
    result = selected.execute(w)
    assert calls == [(w, selected.identity())]
    assert result.evidence['trust'] == 'personal-local'
    assert result.evidence['isolation_verified'] is False


def test_hn_unsupported_never_reads_old_authority(monkeypatch):
    monkeypatch.setattr(Path, 'read_bytes', lambda *args: pytest.fail('must not read HN'))
    with pytest.raises(HNBackendUnsupported, match='v2 read-only snapshot'):
        verify_parent_snapshot({'anything': 'not-authority'})


def test_grok_prepare_is_not_authority_and_stable_id_cannot_reset_claim(tmp_path):
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    import datetime
    expiry = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat()
    kwargs = dict(admission_id='review-one', authority_id='private-one', packet_sha256='1' * 64,
                  state_root=state, policy_fingerprint='2' * 64,
                  engine_implementation_sha256='3' * 64, expires_at=expiry)
    first = grok_admission.prepare('Synthetic review A', directory=tmp_path / 'a', **kwargs)
    second = grok_admission.prepare('Synthetic review B', directory=tmp_path / 'b', **kwargs)
    left, left_bytes = grok_admission.load_prepared(Path(first['prepared_path']))
    right, _ = grok_admission.load_prepared(Path(second['prepared_path']))
    assert left['preparationIdDigest'] == right['preparationIdDigest']
    assert left['artifacts'] != right['artifacts']
    assert list(state.iterdir()) == [] and first['live_send_performed'] is False
    assert strict_json(left_bytes).endswith('Synthetic review A')
    (tmp_path / 'a' / 'bundle.md').write_text('changed')
    with pytest.raises(transports.ProviderError, match='bytes changed'):
        grok_admission.load_prepared(Path(first['prepared_path']))


def test_grok_confirmation_requires_real_foreground_flag(monkeypatch):
    monkeypatch.setattr(grok_admission, 'open', lambda *args, **kwargs: pytest.fail('no TTY without explicit flag'), raising=False)
    with pytest.raises(transports.ProviderError, match='explicit foreground'):
        grok_admission.foreground_confirmation('APPROVE', 'a' * 64, confirmed=False)


@pytest.mark.parametrize('marker', sorted(grok_admission.DENY_CONTEXT))
def test_grok_denied_context_never_opens_confirmation_tty(monkeypatch, marker):
    for name in grok_admission.DENY_CONTEXT:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(marker, '1')
    monkeypatch.setattr(grok_admission, 'open', lambda *args, **kwargs: pytest.fail('denied context opened TTY'), raising=False)
    with pytest.raises(transports.ProviderError, match='cannot confirm'):
        grok_admission.foreground_confirmation('APPROVE', 'a' * 64, confirmed=True)


@pytest.mark.parametrize('fault', ['not-tty', 'background'])
def test_grok_both_confirmation_streams_must_be_foreground_ttys(monkeypatch, fault):
    for name in grok_admission.DENY_CONTEXT:
        monkeypatch.delenv(name, raising=False)
    reader, writer = io.StringIO('APPROVE aaaaaaaaaaaa\n'), io.StringIO()
    reader.isatty, writer.isatty = lambda: True, lambda: fault != 'not-tty'
    reader.fileno, writer.fileno = lambda: 101, lambda: 102
    modes = []
    def opened(path, mode, *, encoding):
        assert path == '/dev/tty' and encoding == 'utf-8'
        modes.append(mode)
        return {'r': reader, 'w': writer}[mode]
    monkeypatch.setattr(grok_admission, 'open', opened, raising=False)
    monkeypatch.setattr(grok_admission.os, 'getpgrp', lambda: 100)
    monkeypatch.setattr(grok_admission.os, 'tcgetpgrp', lambda fd: 100 if fd == 101 else 200)
    with pytest.raises(transports.ProviderError, match='foreground controlling TTY'):
        grok_admission.foreground_confirmation('APPROVE', 'a' * 64, confirmed=True)
    assert modes == ['r', 'w'] and reader.closed and writer.closed


def test_grok_reader_closes_if_writer_open_fails(monkeypatch):
    for name in grok_admission.DENY_CONTEXT:
        monkeypatch.delenv(name, raising=False)
    reader = io.StringIO()
    def opened(path, mode, *, encoding):
        assert path == '/dev/tty' and encoding == 'utf-8'
        if mode == 'r':
            return reader
        assert mode == 'w'
        raise OSError('synthetic controlling-tty write failure')
    monkeypatch.setattr(grok_admission, 'open', opened, raising=False)
    with pytest.raises(transports.ProviderError, match='foreground /dev/tty'):
        grok_admission.foreground_confirmation('APPROVE', 'a' * 64, confirmed=True)
    assert reader.closed


def _owned_tty_confirmation(tmp_path, *, action, supplied_phrase, controlling_tty, denied=False):
    """Exercise only the primitive with a dummy hash, never approval/debit/SEND APIs."""
    import errno
    import jsonschema
    private = Path(__file__).resolve().parents[1]
    runtime = private.parents[1]
    public = runtime.parent / 'plzdo'
    roots = [str(private), str(public), str(runtime),
             str(Path(jsonschema.__file__).resolve().parent.parent)]
    code = '''import fcntl,json,os,sys,termios
sys.path[:0]=json.loads(sys.argv[1])
from plzdo_private_overlay import grok_admission as g
slave=int(sys.argv[2]); action=sys.argv[3]
if slave >= 0:
    fcntl.ioctl(slave,termios.TIOCSCTTY,0)
    os.tcsetpgrp(slave,os.getpgrp())
    assert os.isatty(slave) and os.tcgetpgrp(slave)==os.getpgrp()
def descriptors():
    result=set()
    for fd in range(64):
        try: os.fstat(fd)
        except OSError: continue
        result.add(fd)
    return result
before=descriptors()
try:
    proof=g.foreground_confirmation(action,'a'*64,confirmed=True)
    g._confirmation(proof,action,'a'*64)
    result={'status':'confirmed-fixture-only','proof':proof}
except g.StateError as error:
    result={'status':'rejected','reason':str(error),
            'cause':repr(error.__cause__) if error.__cause__ is not None else None}
result['confirmation_descriptors_closed']=before==descriptors()
result['stdin_is_tty']=os.isatty(0)
if slave >= 0: os.close(slave)
print(json.dumps(result),flush=True)
'''
    master, slave = os.openpty() if controlling_tty else (-1, -1)
    input_read, input_write = os.pipe()
    os.write(input_write, (action + ' aaaaaaaaaaaa\n').encode())
    os.close(input_write)
    environment = dict(os.environ)
    for name in grok_admission.DENY_CONTEXT:
        environment.pop(name, None)  # Only this owned synthetic child models a foreground operator.
    if denied:
        environment['META_HARNESS_AGENT_CONTEXT'] = '1'
    unused_state = tmp_path / 'must-not-create-state'
    environment['LOCAL_CODING_STATE_ROOT'] = str(unused_state)
    process, terminal = None, bytearray()
    deadline = time.monotonic() + 5
    try:
        process = subprocess.Popen([sys.executable, '-I', '-S', '-B', '-c', code,
                                    json.dumps(roots), str(slave), action],
                                   stdin=input_read, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   pass_fds=(slave,) if controlling_tty else (),
                                   start_new_session=True, env=environment)
        os.close(input_read)
        input_read = -1
        if slave >= 0:
            os.close(slave)
            slave = -1
            os.set_blocking(master, False)
        prompt = ('Type `' + action + ' aaaaaaaaaaaa`').encode()
        stdout, stderr, sent = bytearray(), bytearray(), False
        streams = {process.stdout.fileno(): stdout, process.stderr.fileno(): stderr}
        if master >= 0:
            streams[master] = terminal
        for descriptor in streams:
            os.set_blocking(descriptor, False)
        # Keep draining the PTY after sending input too: terminal close can wait
        # for echoed output to drain. stdout/stderr remain separate real pipes.
        while streams or process.poll() is None:
            assert time.monotonic() < deadline, 'Owned confirmation child exceeded its deadline'
            for descriptor in select.select(list(streams), [], [], 0.05)[0]:
                try:
                    block = os.read(descriptor, 4096)
                except BlockingIOError:
                    continue
                except OSError as error:
                    if descriptor == master and error.errno == errno.EIO:
                        block = b''
                    else:
                        raise
                if block:
                    streams[descriptor].extend(block)
                    assert len(streams[descriptor]) <= 16384
                else:
                    del streams[descriptor]
            if controlling_tty and not denied and not sent and prompt in terminal:
                os.write(master, (supplied_phrase + '\n').encode())
                sent = True
        if controlling_tty and not denied:
            assert sent, 'Owned TTY prompt missing: ' + stdout.decode('utf-8', 'replace')[:1000]
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
        assert process.returncode == 0, stderr.decode('utf-8', 'replace')
        assert stderr == b''
        result = json.loads(stdout)
        assert result['confirmation_descriptors_closed'] is True and result['stdin_is_tty'] is False
        assert not unused_state.exists()
        return result, terminal.decode('utf-8').replace('\r\n', '\n')
    finally:
        # Release terminal queues before waiting on an interrupted child.
        for descriptor in (master, slave, input_read):
            if descriptor >= 0:
                os.close(descriptor)
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        if process is not None:
            process.stdout.close()
            process.stderr.close()
            assert process.poll() is not None
            with pytest.raises(ProcessLookupError):
                os.killpg(process.pid, 0)


@pytest.mark.skipif(os.name != 'posix', reason='requires an owned POSIX controlling PTY')
@pytest.mark.parametrize('action,supplied_phrase,controlling_tty,denied,expected', [
    ('APPROVE', 'APPROVE aaaaaaaaaaaa', True, False, 'confirmed-fixture-only'),
    ('SEND', 'SEND aaaaaaaaaaaa', True, False, 'confirmed-fixture-only'),
    ('APPROVE', 'APPROVE wrong-phrase', True, False, 'rejected'),
    ('APPROVE', '', False, False, 'rejected'),
    ('APPROVE', '', True, True, 'rejected'),
])
def test_grok_confirmation_with_real_owned_pty(tmp_path, action, supplied_phrase, controlling_tty, denied, expected):
    result, terminal = _owned_tty_confirmation(tmp_path, action=action, supplied_phrase=supplied_phrase,
                                              controlling_tty=controlling_tty, denied=denied)
    assert result['status'] == expected
    if controlling_tty and not denied:
        assert grok_admission.APPROVAL_SEMANTICS['providerRetentionDisclosure'] in terminal
        assert 'Type `' + action + ' aaaaaaaaaaaa`' in terminal
    if expected == 'confirmed-fixture-only':
        assert result['proof']['action'] == action and result['proof']['hashPrefix'] == 'a' * 12
    elif denied:
        assert 'cannot confirm' in result['reason'] and not terminal
    elif not controlling_tty:
        assert 'foreground /dev/tty' in result['reason']
    else:
        assert 'phrase mismatch' in result['reason']  # Correct piped stdin was not accepted instead.


def test_private_package_does_not_own_public_files_or_entries():
    root = Path(__file__).resolve().parents[1]
    configuration = tomllib.loads((root / 'pyproject.toml').read_text())
    assert configuration['project']['dependencies'] == ['plzdo==0.3.0', 'plzdo-local-runtime==0.3.0']
    assert configuration['tool']['setuptools']['packages']['find']['include'] == ['plzdo_private_overlay*']
    assert configuration['tool']['setuptools']['script-files'] == [
        'bin/plzdo-private', 'bin/plzdo_private_entry.py']
    assert not list((root / 'plzdo_private_overlay').glob('*ledger*'))


def test_claude_allows_only_its_two_verified_package_links(tmp_path):
    root = tmp_path / 'claude-code'
    binary = root / 'bin' / 'claude.exe'
    alias = root / 'node_modules' / '@anthropic-ai' / 'claude-code-darwin-arm64' / 'claude'
    binary.parent.mkdir(parents=True)
    alias.parent.mkdir(parents=True)
    binary.write_bytes(b'fixture native executable\n')
    binary.chmod(0o700)
    os.link(binary, alias)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match='Unsafe provider executable'):
        transports.verified_binary(binary, digest)
    observed = transports.verified_binary(binary, digest, _claude_package=True)
    assert observed['packagedHardlinks']['linkCount'] == 2
    assert transports.verified_binary(alias, digest, _claude_package=True)['inode'] == observed['inode']
    extra = tmp_path / 'third-link'
    os.link(binary, extra)
    with pytest.raises(ValueError, match='Unsafe provider executable'):
        transports.verified_binary(binary, digest, _claude_package=True)
    alias.unlink()
    alias.write_bytes(binary.read_bytes())
    alias.chmod(0o700)
    with pytest.raises(ValueError, match='Unexpected packaged Claude'):
        transports.verified_binary(binary, digest, _claude_package=True)


def test_all_cli_envelopes_match_closed_schema():
    from jsonschema import Draft202012Validator
    from plzdo_private_overlay.cli import _result, _parser
    root = Path(__file__).resolve().parents[1] / 'plzdo_private_overlay'
    schema = strict_json((root / 'schemas' / 'result.schema.json').read_bytes())
    validator = Draft202012Validator(schema)
    commands = schema['properties']['command']['enum']
    for command in commands:
        validator.validate(_result(command, {'fixture': True}))
        validator.validate(_result(command, error='fixture failure', code=1))
    validator.validate(_result('run', {'state': 'awaiting_browser_validation'}, code=3))
    parsed_commands = next(action for action in _parser()._actions if hasattr(action, 'choices') and isinstance(action.choices, dict)).choices
    assert set(parsed_commands) == set(commands)


def _fake_process(output, *, result_payload=None):
    def run(argv, cwd, evidence, timeout, **kwargs):
        evidence = Path(evidence)
        evidence.mkdir()
        (evidence / 'events.jsonl').write_text(output, encoding='utf-8')
        (evidence / 'stderr.log').write_text('', encoding='utf-8')
        if result_payload is not None:
            Path(argv[argv.index('--output-last-message') + 1]).write_bytes(canonical_bytes(result_payload))
        return {'return_code': 0, 'child_exit_code': 0, 'timed_out': False, 'error': None,
                'cleanup': {'schema': 'plzdo.engine-cleanup.v1', 'completed': True,
                            'passed': True, 'owned': True, 'started': True}}
    return run


def test_codex_capture_requires_completed_matching_message(tmp_path, monkeypatch):
    value = pin(tmp_path)
    proposed = {'files': []}
    events = [{'type': 'turn.started'}, {'type': 'item.completed', 'item': {
        'type': 'agent_message', 'text': json.dumps(proposed)}}, {'type': 'turn.completed'}]
    output = '\n'.join(json.dumps(item) for item in events) + '\n'
    monkeypatch.setattr(transports, 'run_bounded', _fake_process(output, result_payload=proposed))
    engine = engines.ExternalEngine('codex-openai', canonical_bytes(value), 'gpt-fixture')
    result = engine.execute(work(tmp_path))
    assert strict_json(result.payload_bytes) == proposed and result.cleanup['passed'] is True
    other = tmp_path / 'other'
    other.mkdir()
    monkeypatch.setattr(transports, 'run_bounded', _fake_process(output, result_payload={'files': ['tampered']}))
    with pytest.raises(EngineFailure, match='captured final message') as error:
        engine.execute(work(other))
    assert error.value.cleanup['completed'] is True and error.value.retryable is False


def test_claude_observed_model_and_tool_counters_are_enforced(tmp_path, monkeypatch):
    value = pin(tmp_path)
    review = {'verdict': 'pass', 'summary': 'Synthetic fixture', 'issues': [], 'plan': []}
    envelope = {'is_error': False, 'structured_output': review,
                'modelUsage': {'claude-opus-fixture': {}}, 'usage': {}, 'subagent_stats': {}}
    engine = engines.ExternalEngine('claude', canonical_bytes(value))
    monkeypatch.setattr(transports, 'run_bounded', _fake_process(json.dumps(envelope)))
    result = engine.execute(work(tmp_path, 'review', transports.REVIEW_SCHEMA))
    assert strict_json(result.payload_bytes) == review
    other = tmp_path / 'other'
    other.mkdir()
    envelope['usage'] = {'server_tool_use': {'web_search_requests': 1}}
    monkeypatch.setattr(transports, 'run_bounded', _fake_process(json.dumps(envelope)))
    with pytest.raises(EngineFailure, match='Unexpected tool'):
        engine.execute(work(other, 'review', transports.REVIEW_SCHEMA))


def test_isolated_fixed_dependency_bootstrap_has_no_site_package_grant(tmp_path):
    import subprocess
    import sys
    import jsonschema
    root = Path(__file__).resolve().parents[3]
    dependency_parent = Path(jsonschema.__file__).resolve().parent.parent
    script = r'''
from pathlib import Path
import importlib.util
import sys
source, dependency, empty = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location('_bootstrap_fixture', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.sysconfig.get_path = lambda *args, **kwargs: str(dependency)
try:
    module.bootstrap_dependencies(empty)
except RuntimeError as exc:
    assert str(exc) == 'DECLARED_JSONSCHEMA_DEPENDENCIES_MISSING'
else:
    raise AssertionError('explicit missing root fell back to unrelated packages')
module.bootstrap_dependencies(dependency)
import jsonschema
jsonschema.Draft202012Validator({'type': 'integer'}).validate(1)
assert str(dependency) not in sys.path
assert dependency not in module.dependency_roots()
if sys.version_info < (3, 13):
    assert dependency / 'typing_extensions.py' in module.dependency_roots()
'''
    result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script,
        str(root / 'local_coding' / '_bootstrap.py'), str(dependency_parent), str(tmp_path)],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def _prepared_fixture(tmp_path):
    from datetime import datetime, timedelta, timezone
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    result = grok_admission.prepare('Synthetic admission bundle', directory=tmp_path / 'review',
        admission_id='review-one', authority_id='private-one', packet_sha256='1' * 64,
        state_root=state, policy_fingerprint='2' * 64,
        engine_implementation_sha256='3' * 64, expires_at=expiry)
    class KernelFixture:
        state_root = state
        reservations = []
        def approved_contract(self, packet):
            return {'id': 'private-one', 'policyFingerprint': '2' * 64, 'expiresAt': expiry,
                    'execution': {'enginePins': {'grok-cli': {'implementationSha256': '3' * 64}}}}, {'packetSha256': '1' * 64}
        def reserve_review(self, *args, **kwargs):
            self.reservations.append((args, kwargs))
            return {'reservation_id': 'one-global-debit'}
    return KernelFixture(), Path(result['prepared_path'])


def _synthetic_confirmation(action, value_hash, *, confirmed):
    assert confirmed is True
    return {'action': action, 'hashPrefix': value_hash[:12], 'flag': True, 'tty': True,
            'foreground': True, 'ttyPath': '/dev/tty', 'actor': 'operator-confirmed-active-session',
            'confirmedAt': grok_admission.now().isoformat(), 'denyMarkersPresent': []}


def test_grok_approval_publication_failure_does_not_hide_debit(tmp_path, monkeypatch):
    kernel, prepared_path = _prepared_fixture(tmp_path)
    monkeypatch.setattr(grok_admission, 'foreground_confirmation', _synthetic_confirmation)
    destination = prepared_path.parent / 'approved.json'
    destination.write_text('preserved existing artifact')
    with pytest.raises(FileExistsError):
        grok_admission.approve(kernel, {'authorityId': 'private-one'}, prepared_path, confirmed=True)
    assert len(kernel.reservations) == 1
    args, kwargs = kernel.reservations[0]
    assert args[1:3] == ('grok-cli', 'review')
    assert kwargs['operation_identity'] == kwargs['evidence_snapshot']['preparedIdDigest']
    assert kwargs['evidence_snapshot']['inputSha256'] == hashlib.sha256(kwargs['prompt_bytes']).hexdigest()
    assert destination.read_text() == 'preserved existing artifact'


def test_grok_private_root_mismatch_stops_before_confirmation_or_debit(tmp_path, monkeypatch):
    kernel, prepared_path = _prepared_fixture(tmp_path)
    kernel.state_root = tmp_path / 'different-root'
    monkeypatch.setattr(grok_admission, 'foreground_confirmation', lambda *args, **kwargs: pytest.fail('no TTY before root binding'))
    with pytest.raises(transports.ProviderError, match='different private state root'):
        grok_admission.approve(kernel, {'authorityId': 'private-one'}, prepared_path, confirmed=True)
    assert kernel.reservations == []
