"""Process-only CLI boundary for the packaged flat coding engine.

No provider, private HN or user configuration is imported for help/version.
Machine results are advisory until their exact candidate and checks are verified.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import importlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import sys

from . import __version__

ENGINE = Path(__file__).resolve().parent / '_engine'
SCHEMA = 'plzdo.local.cli-result.v2'
_CONTEXT = None


class BoundedOutput(io.StringIO):
    def write(self, text):
        if self.tell() + len(text) > 16 * 1024 * 1024:
            raise RuntimeError('ENGINE_OUTPUT_LIMIT')
        return super().write(text)


def _engine_module(name):
    from ._bootstrap import engine_module
    return engine_module(name)


def _result(command, state, payload=None, *, code=0, error=None):
    output = {'schema_version': SCHEMA, 'runtime_version': __version__,
              'command': command, 'state': state, 'exit_code': code,
              'apply_status': 'not_applied', 'publication_authority': False}
    if payload is not None:
        output['result'] = payload
    if error:
        output['error_code'] = error
    return output


def _doctor():
    required = ('workflow.py', 'contracts.py', 'ledger.py', 'host_paths.py')
    modules = {name: (ENGINE / name).is_file() for name in required}
    tools = {name: {'found': shutil.which(name) is not None,
                    'identity_verified': False}
             for name in ('git', 'ollama')}
    return {'os': platform.system(), 'macos_only': True,
            'python_supported': sys.version_info >= (3, 11),
            'engine_modules': modules, 'tools': tools,
            'provider_calls': 0, 'execution_authorized': False,
            'checks': 'discovery-only-not-live-acceptance',
            'isolation_status': 'ISOLATION_PROFILE_UNSUPPORTED', 'live_inference_supported': False}


def _preview_arguments(parser):
    parser.add_argument('--allow-managed-preview', action='store_true',
                        help='Explicitly enable a generated-artifact-only loopback preview')
    parser.add_argument('--preview-max-lifetime-seconds', type=int)
    parser.add_argument('--preview-max-sessions', type=int)


def _preview_authorization(options):
    lifetime, sessions = options.preview_max_lifetime_seconds, options.preview_max_sessions
    if not options.allow_managed_preview:
        if lifetime is not None or sessions is not None:
            raise RuntimeError('PREVIEW_ENABLE_REQUIRED')
        return None
    if lifetime is None or sessions is None:
        raise RuntimeError('PREVIEW_LIMITS_REQUIRED')
    return {'approved': True, 'bind': '127.0.0.1', 'source': 'exact-generated-artifact-allowlist-only',
            'requireStopBeforeFinalize': True, 'maxLifetimeSeconds': lifetime, 'maxSessionsPerRun': sessions}


def _contract_command(args, kernel):
    parser = argparse.ArgumentParser(prog='plzdo-local-code contract')
    commands = parser.add_subparsers(dest='operation', required=True)
    draft = commands.add_parser('draft')
    draft.add_argument('--id', required=True)
    draft.add_argument('--packet', type=Path, required=True, action='append')
    draft.add_argument('--expires-at', required=True)
    draft.add_argument('--max-calls', required=True, type=int)
    draft.add_argument('--max-runs', type=int, default=1)
    draft.add_argument('--engine', choices=('ollama',), action='append', default=[],
                       help='Explicit provider capability; omitted means none (e.g. compute handoff)')
    _preview_arguments(draft)
    approve = commands.add_parser('approve')
    approve.add_argument('--id', required=True)
    approve.add_argument('--expected-sha256', required=True)
    approve.add_argument('--confirm', required=True)
    parsed = parser.parse_args(args)
    contracts = _engine_module('contracts')
    root = kernel.state_root
    if parsed.operation == 'draft':
        workflow = _engine_module('workflow')
        strict_json = _engine_module('generate_edits').strict_json
        packets = [workflow.validate_task_packet(strict_json(p.read_bytes())) for p in parsed.packet]
        doc = contracts.draft_contract(parsed.id, packets, expires_at=parsed.expires_at,
            max_live_integration_calls=parsed.max_calls, allowed_engines=parsed.engine,
            max_runs=parsed.max_runs, preview_authorization=_preview_authorization(parsed))
        doc = contracts.save_draft(root, doc)
    else:
        doc = contracts.approve_contract(root, parsed.id,
            expected_payload_sha256=parsed.expected_sha256,
            approved_by='operator', confirmation=parsed.confirm)
    return doc


def _preview_command(args, kernel):
    """Publish one startup object immediately; completion is a separate receipt."""
    destination = sys.stdout

    class StartupOutput(io.TextIOBase):
        buffer = ''
        sent = False

        def write(self, text):
            self.buffer += text
            if len(self.buffer) > 65536:
                raise RuntimeError('PREVIEW_STARTUP_OUTPUT_LIMIT')
            if '\n' not in self.buffer:
                return len(text)
            line, remaining = self.buffer.split('\n', 1)
            if self.sent or remaining.strip():
                raise RuntimeError('PREVIEW_MULTIPLE_STARTUP_OBJECTS')
            value = json.loads(line)
            if (not isinstance(value, dict) or value.get('host') != '127.0.0.1'
                    or type(value.get('port')) is not int or not 1 <= value['port'] <= 65535
                    or type(value.get('ttl_seconds')) is not int or not 1 <= value['ttl_seconds'] <= 300
                    or not isinstance(value.get('session_id'), str)
                    or not isinstance(value.get('url'), str)
                    or not value['url'].startswith('http://127.0.0.1:' + str(value['port']) + '/')):
                raise RuntimeError('PREVIEW_STARTUP_INVALID')
            event = _result('preview', 'preview_running', value, code=None)
            event.update(final=False, closure_required=True)
            print(json.dumps(event, ensure_ascii=False), file=destination, flush=True)
            self.buffer, self.sent = '', True
            return len(text)

    parser = argparse.ArgumentParser(prog='plzdo-local-code preview')
    parser.add_argument('--run', required=True, type=Path)
    parser.add_argument('--ttl-seconds', default=300, type=int)
    options = parser.parse_args(args)
    sink = StartupOutput()
    try:
        with redirect_stdout(sink):
            kernel.preview(options.run, ttl_seconds=options.ttl_seconds)
        code = 0
        if not sink.sent:
            raise RuntimeError('PREVIEW_STARTUP_NOT_REPORTED')
        if sink.buffer.strip():
            raise RuntimeError('PREVIEW_UNEXPECTED_TRAILING_OUTPUT')
        return code
    except Exception:
        if not sink.sent:
            raise
        # Never produce a second stdout result after the startup lease. The
        # process status and stopped/finish-browser receipts determine closure.
        print(json.dumps({'command': 'preview', 'state': 'failed_after_start',
                          'closure_required': True}), file=sys.stderr, flush=True)
        return 1


def _delegation_command(args, kernel):
    parser = argparse.ArgumentParser(prog='local-coding delegation')
    commands = parser.add_subparsers(dest='operation', required=True)
    trust = commands.add_parser('trust-verifier', help='Explicit one-time operator configuration, no execution approval')
    trust.add_argument('--verifier', type=Path, required=True)
    trust.add_argument('--expected-sha256', required=True,
                       help='Reviewed canonical JSON descriptor SHA-256 (without a trailing newline)')
    trust.add_argument('--confirm', required=True)
    prepare = commands.add_parser('prepare', help='Save a non-authorizing request before creating its parent goal')
    prepare.add_argument('--packet', type=Path, required=True)
    prepare.add_argument('--parent-reference', type=Path, required=True)
    prepare.add_argument('--verifier', type=Path, required=True)
    prepare.add_argument('--expires-at', required=True)
    prepare.add_argument('--max-calls', required=True, type=int)
    prepare.add_argument('--max-runs', type=int, default=1)
    prepare.add_argument('--engine', choices=('ollama',), action='append', default=[])
    _preview_arguments(prepare)
    scope = commands.add_parser('prepare-scope', help='Prepare an opt-in root scope before external parent approval')
    scope.add_argument('--scope', type=Path, required=True)
    scope.add_argument('--parent-reference', type=Path, required=True)
    scope.add_argument('--verifier', type=Path, required=True)
    scope.add_argument('--expires-at', required=True)
    scope.add_argument('--max-calls', required=True, type=int)
    scope.add_argument('--max-total-runs', required=True, type=int)
    scope.add_argument('--max-children', required=True, type=int)
    scope.add_argument('--max-runs-per-child', default=1, type=int)
    scope.add_argument('--engine', choices=('ollama',), action='append', default=[])
    _preview_arguments(scope)
    adopt = commands.add_parser('adopt', help='Adopt the exact request after normal external parent approval')
    adopt.add_argument('--id', required=True)
    adopt.add_argument('--expected-sha256', required=True)
    options = parser.parse_args(args)
    authority = _engine_module('parent_authority')
    root = kernel.state_root
    if options.operation == 'trust-verifier':
        document = authority.trust_verifier(root, authority.read_input_json(options.verifier, maximum=1024 * 1024),
            expected_descriptor_sha256=options.expected_sha256, confirmation=options.confirm)
        return {'status': 'configured', 'configuration': document, 'execution_authorized': False,
                'provider_calls': 0, 'parent_approved': False}
    if options.operation in ('prepare', 'prepare-scope'):
        common = dict(
            parent_reference=authority.read_input_json(options.parent_reference, maximum=1024 * 1024),
            verifier=authority.read_input_json(options.verifier, maximum=1024 * 1024),
            expires_at=options.expires_at, max_live_integration_calls=options.max_calls,
            allowed_engines=options.engine,
            preview_authorization=_preview_authorization(options))
        if options.operation == 'prepare-scope':
            request = authority.prepare_scope_request(root, authority.read_input_json(options.scope),
                max_total_runs=options.max_total_runs, max_children=options.max_children,
                max_runs_per_child=options.max_runs_per_child, **common)
        else:
            request = authority.prepare_request(root, authority.read_input_json(options.packet),
                max_runs=options.max_runs, **common)
        return {'status': 'prepared', 'request': request, 'marker': authority.marker(request),
                'request_path': str(root / 'parent-requests' / (request['id'] + '.json')),
                'execution_authorized': False, 'provider_calls': 0}
    document = authority.adopt_request(root, options.id, expected_request_sha256=options.expected_sha256)
    return {'status': 'delegated', 'document': document, 'provider_calls': 0,
            'authority_basis': authority.AUTHORIZATION_BASIS, 'atomic_lease': False}


def _scope_command(args, kernel):
    parser = argparse.ArgumentParser(prog='local-coding scope')
    commands = parser.add_subparsers(dest='operation', required=True)
    draft = commands.add_parser('draft', help='Prepare explicit bounded child delegation, without approval')
    draft.add_argument('--id', required=True)
    draft.add_argument('--scope', type=Path, required=True)
    draft.add_argument('--expires-at', required=True)
    draft.add_argument('--max-calls', type=int, required=True)
    draft.add_argument('--max-total-runs', type=int, required=True)
    draft.add_argument('--max-children', type=int, required=True)
    draft.add_argument('--max-runs-per-child', type=int, default=1)
    draft.add_argument('--engine', choices=('ollama',), action='append', default=[])
    _preview_arguments(draft)
    approve = commands.add_parser('approve', help='Record one exact standalone root grant')
    approve.add_argument('--id', required=True)
    approve.add_argument('--expected-sha256', required=True)
    approve.add_argument('--confirm', required=True)
    admit = commands.add_parser('admit', help='Verify and bind a child within an existing root grant; no new approval')
    admit.add_argument('--id', required=True)
    admit.add_argument('--template', required=True)
    admit.add_argument('--packet', type=Path, required=True)
    options = parser.parse_args(args)
    authority = _engine_module('scope_authority')
    read = _engine_module('parent_authority').read_input_json
    root = kernel.state_root
    if options.operation == 'draft':
        scope = authority.normalize_scope(read(options.scope), options.id, bind_root=True)
        document = authority.draft_scope(options.id, scope, expires_at=options.expires_at,
            max_live_integration_calls=options.max_calls, allowed_engines=options.engine,
            max_total_runs=options.max_total_runs, max_children=options.max_children,
            max_runs_per_child=options.max_runs_per_child,
            preview_authorization=_preview_authorization(options))
        return authority.save_scope_draft(root, document)
    if options.operation == 'approve':
        return authority.approve_scope(root, options.id,
            expected_payload_sha256=options.expected_sha256, approved_by='operator', confirmation=options.confirm)
    packet = read(options.packet)
    if 'authorityId' not in packet:
        packet['authorityId'] = options.id
    entry = authority.admit_child(root, options.id, options.template, packet)
    return {'status': 'admitted', 'root_id': options.id, 'child': entry,
            'new_operator_approval': False, 'provider_calls': 0}


def _operation(command, args, kernel):
    parser = argparse.ArgumentParser(prog='plzdo-local-code ' + command)
    if command in ('validate', 'route', 'run', 'retry'):
        parser.add_argument('--packet', type=Path, required=True)
    if command in ('run', 'retry'):
        parser.add_argument('--name', required=True)
    if command == 'status':
        source = parser.add_mutually_exclusive_group(required=True)
        source.add_argument('--id')
        source.add_argument('--run', type=Path)
    if command == 'metrics':
        parser.add_argument('--run', type=Path, action='append', required=True)
        parser.add_argument('--output', type=Path, required=True)
    if command == 'finish-browser':
        parser.add_argument('--run', type=Path, required=True)
        parser.add_argument('--observations', type=Path, required=True)
    options = parser.parse_args(args)
    if command == 'finish-browser':
        return kernel.finish_browser(options.run, options.observations)
    if command == 'metrics':
        for root in options.run:
            if root.resolve() != root or not root.is_relative_to(kernel.state_root / 'runs'):
                raise RuntimeError('RUN_OUTSIDE_SELECTED_STATE')
        return _engine_module('workflow_metrics').export_runs(options.run, options.output)
    if command == 'status':
        if options.id:
            return kernel.status(options.id)
        root = options.run
        if root.resolve() != root or root.parent != kernel.state_root / 'runs':
            raise RuntimeError('RUN_OUTSIDE_SELECTED_STATE')
        packet = _engine_module('parent_authority').read_input_json(root / 'packet.json')
        kernel.status(packet['authorityId'])
        return _engine_module('workflow').read_result(root)
    packet = kernel.normalize(_engine_module('parent_authority').read_input_json(options.packet))
    if command == 'validate':
        return {'state': 'validated', 'packet': packet, 'provider_calls': 0, 'execution_authorized': False}
    if command == 'route':
        plan = kernel.policy.generation_plan(packet, ('ollama',))
        return {'state': 'route_only', 'plan': plan, 'provider_calls': 0, 'execution_authorized': False,
                'isolation_status': 'ISOLATION_PROFILE_UNSUPPORTED'}
    if packet.get('kind') == 'compute-analysis':
        kernel.approved_contract(packet)
        return {'state': 'handoff_required', 'target': 'codex-main', 'computed': False, 'provider_calls': 0}
    return _engine_module('workflow').run_pipeline(packet, options.name, kernel=kernel, resume=command == 'retry')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--state-root', type=Path)
    parser.add_argument('--json', action='store_true', help='Structured output (also the default)')
    parser.add_argument('command', choices=('doctor', 'contract', 'delegation', 'scope',
        'validate', 'route', 'run', 'retry', 'status', 'metrics', 'preview', 'finish-browser'))
    options, rest = parser.parse_known_args(argv)
    command, captured, code, payload = options.command, BoundedOutput(), 0, None
    try:
        help_only = any(value in {'-h', '--help'} for value in rest)
        kernel = None
        if command != 'doctor' and not help_only:
            if platform.system() != 'Darwin':
                raise RuntimeError('UNSUPPORTED_OS_MACOS_REQUIRED')
            if options.state_root is None:
                raise RuntimeError('EXPLICIT_STATE_ROOT_REQUIRED')
            from .api import Kernel
            kernel = Kernel(options.state_root)
        if command == 'preview':
            return _preview_command(rest, kernel)
        with redirect_stdout(captured):
            if command == 'doctor':
                if rest:
                    raise RuntimeError('DOCTOR_TAKES_NO_ARGUMENTS')
                payload = _doctor()
            elif command == 'contract':
                payload = _contract_command(rest, kernel)
            elif command == 'delegation':
                payload = _delegation_command(rest, kernel)
            elif command == 'scope':
                payload = _scope_command(rest, kernel)
            else:
                payload = _operation(command, rest, kernel)
        if captured.getvalue().strip():
            raise RuntimeError('UNEXPECTED_ENGINE_STDOUT')
        state = payload.get('state') or payload.get('status') or ('discovery_only' if command == 'doctor' else 'operation_completed')
        code = 1 if state in {'failed', 'blocked'} else 0
        output = _result(command, state, payload, code=code)
        if command in ('contract', 'scope') and state == 'draft':
            output['review_payload_sha256'] = kernel.payload_sha256(payload)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
        output = _result(command, 'help' if code == 0 else 'usage_error',
                         {'help': captured.getvalue()} if code == 0 else None, code=code)
    except Exception as exc:
        code = 1
        message = str(exc)
        safe_code = message if message.isupper() and len(message) < 120 else type(exc).__name__
        output = _result(command, 'failed', code=1, error=safe_code)
    print(json.dumps(output, ensure_ascii=False, allow_nan=False))
    return code
