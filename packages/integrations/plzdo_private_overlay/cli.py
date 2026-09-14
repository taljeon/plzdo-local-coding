"""Separate private CLI; all execution uses a fixed private Kernel from the start."""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import importlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import sysconfig

from . import __version__

RESULT_SCHEMA = 'plzdo.private-result.v1'
ENGINE_IDS = ('ollama', 'codex-openai', 'claude', 'grok-cli', 'agy')


def _load_runtime(prefix):
    """Load named installed distributions or the fixed two-repository source layout."""
    if 'local_coding' in sys.modules:
        return
    prefix = Path(prefix).resolve()
    roots = {prefix}
    variables = {'base': str(prefix), 'platbase': str(prefix), 'userbase': str(prefix)}
    for scheme in ('posix_prefix', 'posix_user', 'osx_framework_user'):
        if scheme in sysconfig.get_scheme_names():
            roots.add(Path(sysconfig.get_path('purelib', scheme=scheme, vars=variables)))
    # Source checkout: <runtime>/packages/integrations, with core at
    # <runtime>/../plzdo. Installed packages still use only their own prefix.
    if (prefix.name == 'integrations' and prefix.parent.name == 'packages'
            and (prefix / 'pyproject.toml').is_file() and (prefix / 'plzdo_private_overlay').is_dir()):
        runtime = prefix.parent.parent
        roots.update({runtime, runtime.parent / 'plzdo'})
    for name in ('plzdo_local', 'plzdo_local_code_adapter', 'local_coding'):
        packages = [root / name for root in roots if (root / name).exists() or (root / name).is_symlink()]
        if len(packages) != 1:
            raise ValueError('Exactly one pinned ' + name + ' distribution is required')
        package = packages[0]
        if (package.resolve(strict=True) != package or not package.is_dir()
                or not (package / '__init__.py').is_file() or (package / '__init__.py').is_symlink()):
            raise ValueError('Unsafe dependency package path: ' + name)
        spec = importlib.util.spec_from_file_location(name, package / '__init__.py',
                                                     submodule_search_locations=[str(package)])
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    importlib.import_module('local_coding._bootstrap').bootstrap_dependencies(package.parent)
    if any(getattr(sys.modules[name], '__version__', None) != '0.3.0'
           for name in ('plzdo_local', 'plzdo_local_code_adapter', 'local_coding')):
        raise ValueError('Private overlay requires both exact PlzDo 0.3.0 distributions')


def _authority_arguments(parser, *, scoped=False):
    parser.add_argument('--expires-at', required=True)
    parser.add_argument('--max-live-calls', type=int, required=True)
    parser.add_argument('--allow-engine', action='append', choices=ENGINE_IDS, required=True)
    if scoped:
        parser.add_argument('--max-total-runs', type=int, required=True)
        parser.add_argument('--max-children', type=int, required=True)
        parser.add_argument('--max-runs-per-child', type=int, default=1)
    else:
        parser.add_argument('--max-runs', type=int, default=1)
    parser.add_argument('--allow-managed-preview', action='store_true')
    parser.add_argument('--preview-max-lifetime-seconds', type=int)
    parser.add_argument('--preview-max-sessions', type=int)


def _authority_options(args, *, scoped=False):
    lifetime, sessions = args.preview_max_lifetime_seconds, args.preview_max_sessions
    preview = None
    if args.allow_managed_preview:
        if lifetime is None or sessions is None:
            raise ValueError('Explicit preview lifetime and session limits are required')
        preview = {'approved': True, 'bind': '127.0.0.1', 'source': 'exact-generated-artifact-allowlist-only',
                   'requireStopBeforeFinalize': True, 'maxLifetimeSeconds': lifetime, 'maxSessionsPerRun': sessions}
    elif lifetime is not None or sessions is not None:
        raise ValueError('Preview limits require --allow-managed-preview')
    options = {'expires_at': args.expires_at, 'max_live_integration_calls': args.max_live_calls,
               'allowed_engines': sorted(set(args.allow_engine)), 'preview_authorization': preview}
    if scoped:
        options.update(max_total_runs=args.max_total_runs, max_children=args.max_children,
                       max_runs_per_child=args.max_runs_per_child)
    else:
        options['max_runs'] = args.max_runs
    return options


def _draft_result(kernel, document):
    payload_hash = kernel.payload_sha256(document)
    return {'document': document, 'approval_payload_sha256': payload_hash,
            'required_confirmation': 'APPROVE ' + document['id'] + ' ' + payload_hash}


def _parser():
    parser = argparse.ArgumentParser(prog='plzdo-private', description=__doc__)
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--config', type=Path, help='Explicit closed private configuration')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('doctor', help='Read-only distribution and capability status; no provider probe')
    sub.add_parser('identity', help='Show fixed engine and private policy identities')
    schema = sub.add_parser('schema', help='Show this private composition concrete authority schema')
    schema.add_argument('--kind', choices=('exact', 'scope', 'parent-exact', 'parent-scope'), default='exact')
    draft = sub.add_parser('draft', help='Save a new unapproved private contract')
    draft.add_argument('--id', required=True)
    draft.add_argument('--packet', type=Path, action='append', required=True)
    _authority_arguments(draft)
    approve = sub.add_parser('approve', help='Approve the exact reviewed private draft')
    approve.add_argument('--id', required=True)
    approve.add_argument('--payload-sha256', required=True)
    approve.add_argument('--confirm', required=True, help='Exact APPROVE id payload-sha256 phrase shown by draft')
    trust = sub.add_parser('trust-verifier', help='Pin the fixed read-only PlzDo parent verifier; no parent approval')
    trust.add_argument('--verifier', type=Path, required=True)
    trust.add_argument('--descriptor-sha256', required=True)
    trust.add_argument('--confirm', required=True)
    for name, scoped in (('parent-prepare', False), ('parent-prepare-scope', True)):
        prepare_parent = sub.add_parser(name, help='Prepare exact private delegation bytes before parent approval')
        prepare_parent.add_argument('--scope' if scoped else '--packet', type=Path, required=True)
        prepare_parent.add_argument('--parent-reference', type=Path, required=True)
        prepare_parent.add_argument('--verifier', type=Path, required=True)
        _authority_arguments(prepare_parent, scoped=scoped)
    adopt = sub.add_parser('parent-adopt', help='Adopt the exact request after actual PlzDo parent approval')
    adopt.add_argument('--id', required=True)
    adopt.add_argument('--request-sha256', required=True)
    scope_draft = sub.add_parser('scope-draft', help='Draft one private root with bounded child templates')
    scope_draft.add_argument('--id', required=True)
    scope_draft.add_argument('--scope', type=Path, required=True)
    _authority_arguments(scope_draft, scoped=True)
    scope_approve = sub.add_parser('scope-approve', help='Approve the exact reviewed private root scope')
    scope_approve.add_argument('--id', required=True)
    scope_approve.add_argument('--payload-sha256', required=True)
    scope_approve.add_argument('--confirm', required=True)
    child = sub.add_parser('scope-admit', help='Bind a child within existing root authority; no independent budget')
    child.add_argument('--id', required=True)
    child.add_argument('--template', required=True)
    child.add_argument('--packet', type=Path, required=True)
    status = sub.add_parser('status')
    status.add_argument('--id', required=True)
    run = sub.add_parser('run', help='Use the shared pipeline under this private root')
    run.add_argument('--packet', type=Path, required=True)
    run.add_argument('--name', required=True)
    run.add_argument('--resume', action='store_true')
    preview = sub.add_parser('preview', help='Serve an approved generated preview in the foreground; Ctrl-C stops it')
    preview.add_argument('--name', required=True)
    preview.add_argument('--ttl-seconds', type=int, default=300)
    finish = sub.add_parser('finish-browser', help='Verify an actual observation after the owned preview has stopped')
    finish.add_argument('--name', required=True)
    finish.add_argument('--observation', type=Path, required=True)
    review = sub.add_parser('review', help='One explicitly allowed Codex design, Claude, or native AGY review')
    review.add_argument('--packet', type=Path, required=True)
    review.add_argument('--engine', choices=('codex-openai', 'claude', 'agy'), required=True)
    review.add_argument('--bundle', type=Path, required=True)
    review.add_argument('--id', required=True)
    review.add_argument('--evidence-dir', type=Path, required=True)
    prepare = sub.add_parser('grok-prepare', help='Save exact review bytes; no debit or send')
    prepare.add_argument('--packet', type=Path, required=True)
    prepare.add_argument('--bundle', type=Path, required=True)
    prepare.add_argument('--id', required=True)
    prepare.add_argument('--directory', type=Path, required=True)
    prepare.add_argument('--expires-at', required=True)
    approved = sub.add_parser('grok-approve', help='Foreground APPROVE; one global debit and preparation claim')
    approved.add_argument('--packet', type=Path, required=True)
    approved.add_argument('--prepared', type=Path, required=True)
    approved.add_argument('--confirm', action='store_true')
    send = sub.add_parser('grok-send', help='Foreground SEND; one child claim, no retries or refunds')
    send.add_argument('--admission', type=Path, required=True)
    send.add_argument('--evidence-dir', type=Path, required=True)
    send.add_argument('--confirm', action='store_true')
    imported = sub.add_parser('grok-import', help='Read a completed review against its durable dispatch and completion')
    imported.add_argument('--admission', type=Path, required=True)
    imported.add_argument('--report', type=Path, required=True)
    return parser


def _result(command, payload=None, *, error=None, code=0):
    return {'schemaVersion': RESULT_SCHEMA, 'overlayVersion': __version__, 'command': command,
            'status': 'blocked' if error else 'pending' if code == 3 else 'failed' if code else 'ok',
            'exitCode': code, 'result': payload, 'error': error,
            'apply_status': 'not_applied', 'publication_authority': False}


def main(argv=None, *, install_prefix=None):
    args = _parser().parse_args(argv)
    try:
        if install_prefix is not None:
            _load_runtime(install_prefix)
        from local_coding.api import canonical_bytes, strict_json
        from .orchestration import compose, load_config, run_private, configured_engines
        from .transports import _bounded_read, REVIEW_SCHEMA, REVIEW_INSTRUCTIONS, require_active_session
        from . import grok_admission
        if args.command == 'doctor':
            payload = {'candidate_dependencies': {'plzdo': '0.3.0', 'plzdo-local-runtime': '0.3.0'},
                       'release_artifact_pin': 'pending', 'private_hn': 'HN_BACKEND_PROTOCOL_UNSUPPORTED',
                       'ollama_trust': 'personal-local', 'ollama_isolation_verified': False,
                       'provider_calls': 0, 'execution_authorized': False}
        else:
            if args.config is None:
                raise ValueError('An explicit --config is required')
            config = load_config(args.config)
            kernel = compose(config)
            packet = strict_json(_bounded_read(args.packet)) if isinstance(getattr(args, 'packet', None), Path) else None
            if args.command == 'identity':
                from .engines import source_sha256
                selected = configured_engines(config)
                payload = {'private_source_sha256': source_sha256(), 'engines': {
                    name: {'engineId': identity.engine_id, 'roles': list(identity.roles),
                           'implementationSha256': identity.implementation_sha256}
                    for name, engine in selected.items() for identity in [engine.identity()]}}
                if 'agy' in selected:
                    from .agy_context import snapshot
                    payload['agy_ambient_context'] = snapshot(config['agyGlobalRulesSha256'])
            elif args.command == 'schema':
                payload = kernel.authority_schema(args.kind)
            elif args.command == 'draft':
                packets = [strict_json(_bounded_read(path)) for path in args.packet]
                payload = _draft_result(kernel, kernel.draft_contract(args.id, packets, **_authority_options(args)))
            elif args.command == 'approve':
                payload = kernel.approve_contract(args.id, expected_payload_sha256=args.payload_sha256,
                                                   confirmation=args.confirm)
            elif args.command == 'trust-verifier':
                document = kernel.trust_verifier(strict_json(_bounded_read(args.verifier)),
                    expected_descriptor_sha256=args.descriptor_sha256, confirmation=args.confirm)
                payload = {'status': 'configured', 'configuration': document,
                           'execution_authorized': False, 'parent_approved': False, 'provider_calls': 0}
            elif args.command in {'parent-prepare', 'parent-prepare-scope'}:
                scoped = args.command == 'parent-prepare-scope'
                options = _authority_options(args, scoped=scoped)
                options.update(parent_reference=strict_json(_bounded_read(args.parent_reference)),
                               verifier=strict_json(_bounded_read(args.verifier)))
                request = (kernel.prepare_scope_request(strict_json(_bounded_read(args.scope)), **options)
                           if scoped else kernel.prepare_request(packet, **options))
                payload = {'status': 'prepared', 'request': request, 'marker': kernel.request_marker(request),
                           'request_path': str(kernel.state_root / 'parent-requests' / (request['id'] + '.json')),
                           'execution_authorized': False, 'provider_calls': 0}
            elif args.command == 'parent-adopt':
                document = kernel.adopt_request(args.id, expected_request_sha256=args.request_sha256)
                payload = {'status': 'delegated', 'document': document, 'atomic_lease': False, 'provider_calls': 0}
            elif args.command == 'scope-draft':
                document = kernel.draft_scope(args.id, strict_json(_bounded_read(args.scope)),
                                               **_authority_options(args, scoped=True))
                payload = _draft_result(kernel, document)
            elif args.command == 'scope-approve':
                payload = kernel.approve_scope(args.id, expected_payload_sha256=args.payload_sha256,
                                                approved_by='operator', confirmation=args.confirm)
            elif args.command == 'scope-admit':
                entry = kernel.admit_child(args.id, args.template, packet)
                payload = {'status': 'admitted', 'root_id': args.id, 'child': entry,
                           'new_operator_approval': False, 'provider_calls': 0}
            elif args.command == 'status':
                payload = kernel.status(args.id)
            elif args.command == 'run':
                payload = run_private(kernel, packet, run_name=args.name, resume=args.resume)
            elif args.command == 'preview':
                if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', args.name) is None:
                    raise ValueError('Invalid private run name')
                # Foreground readiness belongs on stderr; stdout remains one
                # terminal result envelope after the owned listener closes.
                with redirect_stdout(sys.stderr):
                    payload = kernel.preview(kernel.state_root / 'runs' / args.name, ttl_seconds=args.ttl_seconds)
            elif args.command == 'finish-browser':
                if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', args.name) is None:
                    raise ValueError('Invalid private run name')
                payload = kernel.finish_browser(kernel.state_root / 'runs' / args.name, args.observation)
            elif args.command == 'review':
                require_active_session()
                if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', args.id) is None:
                    raise ValueError('Invalid private review ID')
                bundle = _bounded_read(args.bundle)
                prompt = canonical_bytes(REVIEW_INSTRUCTIONS + '\n\n' + bundle)
                schema = canonical_bytes(REVIEW_SCHEMA)
                role = 'design-review' if args.engine == 'codex-openai' else 'review'
                record = kernel.reserve_review(packet, args.engine, role,
                    operation_identity=grok_admission.digest([packet['authorityId'], args.engine, args.id]),
                    prompt_bytes=prompt, schema_bytes=schema, evidence_snapshot=None)
                result = kernel.dispatch_review(packet, record['reservation_id'], prompt, schema, args.evidence_dir)
                payload = {'reservation_id': record['reservation_id'], 'provider': args.engine,
                           'review': strict_json(result.payload_bytes), 'authority': 'advisory',
                           'source_of_truth': False, 'apply_status': 'not_applied'}
                if args.engine == 'agy':
                    payload['observed_model'] = result.evidence['observed_model']
                    payload['native_version'] = result.evidence['native_version']
                    payload['agy_context'] = {key: result.evidence['ambient_context'][key] for key in (
                        'schema', 'snapshotSha256', 'globalRulesSha256', 'globalRulesAdmission', 'contentsRecorded')}
                    payload['context_matches_after'] = result.evidence['context_matches_after']
                    payload['workspace_unchanged'] = result.evidence['workspace_unchanged']
            elif args.command == 'grok-prepare':
                document, binding = kernel.approved_contract(packet)
                payload = grok_admission.prepare(_bounded_read(args.bundle), directory=args.directory,
                    admission_id=args.id, authority_id=document['id'], packet_sha256=binding['packetSha256'],
                    state_root=Path(config['stateRoot']), policy_fingerprint=document['policyFingerprint'],
                    engine_implementation_sha256=document['execution']['enginePins']['grok-cli']['implementationSha256'],
                    expires_at=args.expires_at)
            elif args.command == 'grok-approve':
                payload = grok_admission.approve(kernel, packet, args.prepared, confirmed=args.confirm)
            elif args.command == 'grok-send':
                payload = grok_admission.send(kernel, args.admission, args.evidence_dir, confirmed=args.confirm)
            elif args.command == 'grok-import':
                payload = grok_admission.import_result(kernel, args.admission, args.report)
            else:
                raise ValueError('Unsupported private command')
        code = 0
        if args.command in {'run', 'finish-browser'}:
            code = 0 if payload.get('state') == 'candidate_ready' else 3 if payload.get('state') == 'awaiting_browser_validation' else 1
        print(json.dumps(_result(args.command, payload, code=code), ensure_ascii=False))
        return code
    except (ValueError, OSError, RuntimeError, KeyError, TypeError, ImportError) as exc:
        print(json.dumps(_result(args.command, error=type(exc).__name__ + ': ' + str(exc)[:1800], code=1), ensure_ascii=False))
        return 1
