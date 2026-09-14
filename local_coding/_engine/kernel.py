"""Source-composed authority kernel; all engines use the same locked ledger.

This is an in-process reuse API for trusted compositions, not an API accepting
arbitrary Python callbacks from task documents. One process fixes one composition.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from local_coding._bootstrap import engine_module
from pathlib import Path
import re
import sys

from composition import PUBLIC_POLICY, configure, engine, current_engine_pins
from engine_types import (Work, WorkResult, EngineFailure, require_cleanup,
                          no_start_cleanup, thaw, RETRYABLE_ENGINE_CODES)
from state_io import StateStore, canonical_bytes, strict_json, digest, require


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class RunContext:
    run_id: str
    root: Path


@dataclass(frozen=True)
class _Transaction:
    bindings: dict | None
    observation: dict | None
    terminal: bool


class Kernel:
    def __init__(self, state_root, *, policy=PUBLIC_POLICY, engines=None):
        if engines is None:
            require(policy == PUBLIC_POLICY, 'Private composition requires its fixed engines')
            engines = {'ollama': engine_module('ollama_engine').OllamaEngine()}
        configure(policy, engines, state_root)
        self.state_root, self.policy = Path(state_root).absolute(), policy
        # Import state-dependent legacy helpers only after fixing the root.
        self.contracts = engine_module('contracts')
        self.ledger = engine_module('ledger')
        self.workflow = engine_module('workflow')
        for name in ('workflow', 'workflow_core', 'workflow_artifacts', 'workflow_preview', 'workflow_browser'):
            module = sys.modules.get(name)
            if module is not None and hasattr(module, 'DIRECTORY'):
                require(module.DIRECTORY == self.state_root, 'PREIMPORTED_RUNTIME_STATE_MISMATCH')
        engine_module('host_paths').validate_state_root(self.state_root)

    def normalize(self, packet):
        return self.workflow.validate_task_packet(packet)

    def draft_contract(self, contract_id, packets, **options):
        normalized = [self.normalize(packet) for packet in packets]
        document = self.contracts.draft_contract(contract_id, normalized, **options)
        return self.contracts.save_draft(self.state_root, document)

    def approve_contract(self, contract_id, *, expected_payload_sha256, confirmation, approved_by='operator'):
        return self.contracts.approve_contract(self.state_root, contract_id,
            expected_payload_sha256=expected_payload_sha256, confirmation=confirmation, approved_by=approved_by)

    def payload_sha256(self, document):
        return self.contracts.payload_sha256(document)

    def authority_schema(self, kind):
        return self.contracts.authority_schema(kind)

    def trust_verifier(self, verifier, **options):
        return engine_module('parent_authority').trust_verifier(self.state_root, verifier, **options)

    def prepare_request(self, packet, **options):
        return engine_module('parent_authority').prepare_request(self.state_root, packet, **options)

    def prepare_scope_request(self, scope, **options):
        return engine_module('parent_authority').prepare_scope_request(self.state_root, scope, **options)

    def adopt_request(self, identifier, **options):
        return engine_module('parent_authority').adopt_request(self.state_root, identifier, **options)

    def request_marker(self, request):
        return engine_module('parent_authority').marker(request)

    def draft_scope(self, contract_id, scope, **options):
        authority = engine_module('scope_authority')
        normalized = authority.normalize_scope(scope, contract_id, bind_root=True)
        return authority.save_scope_draft(self.state_root, authority.draft_scope(contract_id, normalized, **options))

    def approve_scope(self, contract_id, **options):
        return engine_module('scope_authority').approve_scope(self.state_root, contract_id, **options)

    def admit_child(self, contract_id, template_id, packet):
        packet = strict_json(canonical_bytes(packet))
        if 'authorityId' not in packet:
            packet['authorityId'] = contract_id
        return engine_module('scope_authority').admit_child(self.state_root, contract_id, template_id, packet)

    def approved_contract(self, packet):
        return self.contracts.approved_contract(self.normalize(packet), self.state_root)

    def plan(self, packet):
        _, binding = self.approved_contract(packet)
        return tuple(dict(slot) for slot in binding['generationAttemptPlan'])

    def _read_receipt(self, path):
        path = Path(path)
        require(path.is_absolute() and path.resolve(strict=True) == path
                and path.is_relative_to(self.state_root), 'Receipt outside owned state')
        raw = engine_module('workflow_core')._read_check_evidence(path.parent, path.name, 16 * 1024 * 1024)
        return strict_json(raw), _sha(raw)

    def _verified_records(self, value):
        for record in value['records']:
            if record['kind'] == 'run':
                require(record['run_root'] == str(self.state_root / 'runs' / record['run_name']),
                        'Ledger run root differs from selected state')
            if record['kind'] in ('outcome', 'engine-result'):
                if record['kind'] == 'engine-result':
                    require(record['receipt_path'] == str(self.state_root / 'engine-receipts' /
                            (record['parent_reservation_id'] + '.json')), 'Engine receipt root mismatch')
                _, actual = self._read_receipt(record['receipt_path'])
                require(actual == record['receipt_sha256'], 'Immutable receipt changed')
        return value

    def _transaction(self, packet, callback, *, terminal=False):
        packet = strict_json(canonical_bytes(packet)) if terminal else self.normalize(packet)
        if not terminal:
            document, binding = self.approved_contract(packet)
        with StateStore(self.state_root) as store, store.locked():
            observations = []
            if terminal:
                document, value, raw, bindings = self.ledger.historical(store, packet['authorityId'])
                binding = (bindings if bindings is not None else document['execution']['taskBindings']).get(packet['id'])
                require(isinstance(binding, dict), 'Terminal packet is not bound')
                require(binding['packetSha256'] == self.contracts.packet_hash(packet), 'Terminal packet binding changed')
                observation = None  # Terminal _append copies the exact dispatch's observation.
            else:
                value, raw, bindings = self.ledger._current(store, document, binding, packet, observations=observations)
                observation = observations[-1] if observations else None
            self._verified_records(value)
            return callback(store, document, binding, value, raw, _Transaction(bindings, observation, terminal))

    def _append(self, store, document, binding, value, raw, bindings, packet, kind, **fields):
        observation = bindings.observation
        if bindings.terminal:
            dispatch = next((r for r in value['records'] if r['kind'] == 'dispatch'
                             and r['parent_reservation_id'] == fields.get('parent_reservation_id')), None)
            require(dispatch is not None, 'Terminal evidence has no matching dispatch')
            observation = dispatch['authority_observation']
        record = {'kind': kind, 'packet': packet['id'], 'packet_sha256': binding['packetSha256'],
                  'authority_observation': observation, **fields}
        return self.ledger.append_locked(store, document, value, raw, record,
                                         bindings=bindings.bindings, terminal=bindings.terminal)

    def status(self, contract_id):
        with StateStore(self.state_root) as store, store.locked():
            document, value, _, _ = self.ledger.historical(store, contract_id)
            self._verified_records(value)
        return {'document': document, 'ledger': value, 'summary': self.ledger.summary(value),
                'execution_authorized': False, 'inspection': 'historical-structure-and-evidence'}

    def begin_run(self, packet, run_name, *, resume=False):
        packet = self.normalize(packet)
        require(isinstance(run_name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', run_name),
                'Invalid bounded run name')
        root = self.state_root / 'runs' / run_name
        def begin(store, document, binding, value, raw, bindings):
            store.directory('runs', create=True)
            require(root.resolve(strict=False) == root, 'Run path changed')
            existing = next((r for r in value['records'] if r['kind'] == 'run' and r['run_name'] == run_name), None)
            if resume:
                require(existing is not None and existing['packet'] == packet['id'] and root.is_dir()
                        and existing['run_root'] == str(root), 'Resume requires the original exact run')
                return RunContext(existing['reservation_id'], root)
            require(existing is None and not root.exists(), 'Run name is already consumed')
            record = self._append(store, document, binding, value, raw, bindings, packet, 'run',
                                  run_name=run_name, run_root=str(root))
            return RunContext(record['reservation_id'], root)
        return self._transaction(packet, begin)

    def _call_fields(self, document, engine_id, role, operation_identity, prompt_bytes, schema_bytes,
                     evidence_snapshot, *, run_id=None, ordinal=None):
        # Data validation happens before debit; none of these bytes grant access.
        Work(role, prompt_bytes, schema_bytes, canonical_bytes({}), 10,
             self.state_root / 'engine-receipts', 'preflight')
        pin = document['execution']['enginePins'].get(engine_id)
        require(pin is not None and current_engine_pins((engine_id,))[engine_id] == pin,
                'Engine is unavailable or its implementation changed')
        return {'engine_id': engine_id, 'role': role, 'engine_sha256': pin['implementationSha256'],
                'operation_identity': operation_identity, 'prompt_sha256': _sha(prompt_bytes),
                'schema_sha256': _sha(schema_bytes), 'evidence_snapshot': evidence_snapshot,
                'run_id': run_id, 'ordinal': ordinal}

    def generate(self, packet, run_id, ordinal, prompt_bytes, schema_bytes, evidence_dir):
        packet = self.normalize(packet)
        def reserve(store, document, binding, value, raw, bindings):
            require(type(ordinal) is int and 1 <= ordinal <= len(binding['generationAttemptPlan']), 'Unknown generation slot')
            slot = binding['generationAttemptPlan'][ordinal - 1]
            run = self.ledger.record_by_id(value, run_id, packet['id'])
            require(run['kind'] == 'run', 'Generation requires a run reservation')
            expected = Path(run['run_root']) / (slot['engineId'] + '-' + str(ordinal)) / 'provider'
            require(Path(evidence_dir) == expected, 'Generation evidence destination mismatch')
            fields = self._call_fields(document, slot['engineId'], 'generate',
                digest([self.policy.namespace, document['id'], packet['id'], run_id, ordinal]),
                prompt_bytes, schema_bytes, None, run_id=run_id, ordinal=ordinal)
            return self._append(store, document, binding, value, raw, bindings, packet, 'generate', **fields)
        reservation = self._transaction(packet, reserve)
        return self._dispatch(packet, reservation['reservation_id'], prompt_bytes, schema_bytes, evidence_dir)

    def reserve_review(self, packet, engine_id, role, operation_identity, prompt_bytes, schema_bytes, evidence_snapshot=None):
        packet = self.normalize(packet)
        require(role in ('review', 'design-review'), 'Review cannot reserve generation')
        def reserve(store, document, binding, value, raw, bindings):
            fields = self._call_fields(document, engine_id, role, operation_identity, prompt_bytes, schema_bytes, evidence_snapshot)
            if engine_id in self.policy.admission_engines:
                self.ledger.validate_snapshot(evidence_snapshot, fields['prompt_sha256'], fields['schema_sha256'], fresh=True)
            return self._append(store, document, binding, value, raw, bindings, packet, 'review', **fields)
        return self._transaction(packet, reserve)

    def claim_send(self, packet, parent_reservation_id, admission_hash, prepared_id_digest,
                   prompt_bytes, schema_bytes, evidence_snapshot):
        packet = self.normalize(packet)
        def claim(store, document, binding, value, raw, bindings):
            parent = self.ledger.record_by_id(value, parent_reservation_id, packet['id'])
            require(parent['kind'] == 'review' and parent['prompt_sha256'] == _sha(prompt_bytes)
                    and parent['schema_sha256'] == _sha(schema_bytes)
                    and parent['evidence_snapshot'] == evidence_snapshot, 'Send input/admission drift')
            self.ledger.validate_snapshot(evidence_snapshot, _sha(prompt_bytes), _sha(schema_bytes), fresh=True)
            return self._append(store, document, binding, value, raw, bindings, packet, 'child-send',
                parent_reservation_id=parent_reservation_id, admission_sha256=admission_hash,
                prepared_id_digest=prepared_id_digest)
        return self._transaction(packet, claim)

    def dispatch_review(self, packet, reservation_id, prompt_bytes, schema_bytes, evidence_dir, *, child_claim_id=None):
        return self._dispatch(self.normalize(packet), reservation_id, prompt_bytes, schema_bytes,
                              evidence_dir, child_claim_id=child_claim_id, review_only=True)

    def _dispatch(self, packet, reservation_id, prompt_bytes, schema_bytes, evidence_dir, *, child_claim_id=None, review_only=False):
        def claim(store, document, binding, value, raw, bindings):
            parent = self.ledger.record_by_id(value, reservation_id, packet['id'])
            require(parent['kind'] in ('generate', 'review') and (not review_only or parent['kind'] == 'review')
                    and parent['prompt_sha256'] == _sha(prompt_bytes) and parent['schema_sha256'] == _sha(schema_bytes),
                    'Dispatch bytes or operation changed')
            if parent['engine_id'] in self.policy.admission_engines:
                self.ledger.validate_snapshot(parent['evidence_snapshot'], _sha(prompt_bytes), _sha(schema_bytes), fresh=True)
            destination = Path(evidence_dir)
            require(destination.is_absolute() and destination.resolve(strict=False) == destination
                    and destination.is_relative_to(self.state_root) and not destination.exists(),
                    'Engine evidence must be a new dedicated destination inside owned state')
            profile = engine_module('generation_profile').resolve_profile(packet['generation_profile'])
            remaining = int((self.contracts._timestamp(document['expiresAt']) - self.contracts._now()).total_seconds())
            timeout = min(remaining, profile['generation_deadline'] + profile['supervisor_grace'])
            require(timeout >= 10, 'Authority lifetime too short for dispatch')
            work = Work(parent['role'], prompt_bytes, schema_bytes, canonical_bytes(profile), timeout, destination, reservation_id)
            self._append(store, document, binding, value, raw, bindings, packet, 'dispatch',
                         parent_reservation_id=reservation_id, child_claim_id=child_claim_id)
            return parent, work
        parent, work = self._transaction(packet, claim)
        entered_engine = False
        result = None
        try:
            selected = engine(parent['engine_id'], parent['role'])
            entered_engine = True
            result = selected.execute(work)
            require(isinstance(result, WorkResult), 'Engine returned an untyped result')
            if result.identity != selected.identity() or result.identity.implementation_sha256 != parent['engine_sha256']:
                raise EngineFailure('ENGINE_IDENTITY_CHANGED', 'Returned engine identity differs from its approved pin',
                                    evidence=thaw(result.evidence), cleanup=thaw(result.cleanup))
            require_cleanup(result.cleanup)
        except BaseException as exc:
            returned = isinstance(result, WorkResult)
            failure = exc if isinstance(exc, EngineFailure) else EngineFailure('ENGINE_UNEXPECTED_FAILURE',
                'Engine did not return a validated result', evidence=thaw(result.evidence) if returned else {},
                cleanup=thaw(result.cleanup) if returned else ({} if entered_engine else no_start_cleanup()))
            receipt = {'schema': 'plzdo.engine-receipt.v2', 'reservation_id': reservation_id,
                'succeeded': False, 'payload_sha256': None, 'cleanup': thaw(failure.cleanup),
                'evidence': thaw(failure.evidence), 'error_code': failure.code, 'retryable': failure.retryable}
            self._record_engine_result(packet, receipt)
            raise failure from exc
        receipt = {'schema': 'plzdo.engine-receipt.v2', 'reservation_id': reservation_id,
            'succeeded': True, 'payload_sha256': _sha(result.payload_bytes), 'cleanup': thaw(result.cleanup),
            'evidence': thaw(result.evidence), 'error_code': None, 'retryable': False}
        self._record_engine_result(packet, receipt)
        return result

    def _record_engine_result(self, packet, receipt):
        def finish(store, document, binding, value, raw, bindings):
            store.directory('engine-receipts', create=True)
            name = receipt['reservation_id'] + '.json'
            require(store.read_bytes('engine-receipts', name, missing_ok=True) is None,
                    'Engine receipt already exists; dispatch cannot be repeated')
            store.write_json('engine-receipts', name, receipt, expected_bytes=None)
            encoded = store.read_bytes('engine-receipts', name)
            return self._append(store, document, binding, value, raw, bindings, packet, 'engine-result',
                parent_reservation_id=receipt['reservation_id'], receipt_path=str(self.state_root / 'engine-receipts' / name),
                receipt_sha256=_sha(encoded), payload_sha256=receipt['payload_sha256'],
                cleanup_sha256=digest(receipt['cleanup']), succeeded=receipt['succeeded'])
        return self._transaction(packet, finish, terminal=True)

    def complete_attempt(self, packet, run_id, ordinal, attempt_receipt_path):
        packet = strict_json(canonical_bytes(packet))
        def complete(store, document, binding, value, raw, bindings):
            parent = next((r for r in value['records'] if r['kind'] == 'generate'
                           and r['run_id'] == run_id and r['ordinal'] == ordinal and r['packet'] == packet['id']), None)
            require(parent is not None, 'No reserved generation slot for receipt')
            completions = [r for r in value['records'] if r['kind'] == 'engine-result'
                           and r['parent_reservation_id'] == parent['reservation_id']]
            require(len(completions) == 1, 'Attempt lacks durable engine completion')
            completion, _ = self._read_receipt(completions[0]['receipt_path'])
            attempt, receipt_sha = self._read_receipt(attempt_receipt_path)
            require(attempt.get('operation') == binding['generationAttemptPlan'][ordinal - 1]
                    and attempt.get('number') == ordinal and attempt.get('provider') == parent['engine_id'],
                    'Attempt receipt differs from reserved operation')
            old = next((r for r in reversed(value['records']) if r['kind'] == 'outcome'
                        and r['parent_reservation_id'] == parent['reservation_id']), None)
            if old and old['receipt_path'] == str(attempt_receipt_path):
                require(old['receipt_sha256'] == receipt_sha, 'Attempt receipt changed')
                return old
            run = self.ledger.record_by_id(value, run_id, packet['id'])
            stage = Path(run['run_root']) / (parent['engine_id'] + '-' + str(ordinal))
            require(attempt.get('candidate') == str(stage / 'candidate'), 'Attempt candidate binding changed')
            if old is not None:
                proof = attempt.get('browser_finalization')
                require(isinstance(proof, dict) and set(proof) == {
                    'schema', 'original_receipt', 'original_receipt_sha256',
                    'observations', 'observations_sha256', 'closure', 'closure_sha256'}
                    and proof['schema'] == 'plzdo.browser-attempt-final.v1'
                    and proof['original_receipt'] == old['receipt_path']
                    and proof['original_receipt_sha256'] == old['receipt_sha256'],
                    'Browser finalization lacks its immutable pending receipt')
                for key in ('observations', 'closure'):
                    require(Path(proof[key]).is_relative_to(Path(run['run_root']) / 'browser-previews'),
                            'Browser proof outside run-owned evidence')
                    _, observed = self._read_receipt(proof[key])
                    require(observed == proof[key + '_sha256'], 'Browser finalization evidence changed')
            disposition = 'blocked'
            cleanup = attempt.get('cleanup')
            try:
                require_cleanup(cleanup)
                require(digest(cleanup) == digest(completion['cleanup']), 'Attempt cleanup differs from engine receipt')
                safe_cleanup = True
            except (ValueError, EngineFailure):
                safe_cleanup = False
            if safe_cleanup and not attempt.get('fatal'):
                if attempt.get('passed') is True or attempt.get('status') == 'awaiting_browser_validation':
                    require(completion['succeeded'] is True, 'Failed engine cannot produce an accepted candidate')
                    self.workflow._require_check_execution_evidence(attempt['checks'], allow_browser_observations=old is not None)
                    require(attempt['checks']['scope']['passed'] is True, 'Check scope did not pass')
                    disposition = 'accepted' if attempt.get('passed') is True else 'pending'
                else:
                    code = attempt.get('error_code')
                    if completion['succeeded'] is False:
                        retry = completion['retryable'] is True and code == completion['error_code'] and code in RETRYABLE_ENGINE_CODES
                    else:
                        retry = code in RETRYABLE_ENGINE_CODES | {'EDIT_VALIDATION_ERROR', 'CHECK_FAILED', 'BROWSER_CHECK_FAILED'}
                    if retry:
                        if code in {'CHECK_FAILED', 'BROWSER_CHECK_FAILED'}:
                            self.workflow._require_check_execution_evidence(attempt['checks'], allow_browser_observations=old is not None)
                            require(attempt['checks']['scope']['passed'] is True, 'Failed checks changed candidate scope')
                        disposition = 'retry'
            return self._append(store, document, binding, value, raw, bindings, packet, 'outcome',
                parent_reservation_id=parent['reservation_id'], receipt_path=str(attempt_receipt_path),
                receipt_sha256=receipt_sha, disposition=disposition,
                supersedes=old['reservation_id'] if old is not None else None)
        return self._transaction(packet, complete, terminal=True)

    def preview(self, run_dir, *, ttl_seconds=300):
        return engine_module('workflow_browser').start_preview(run_dir, ttl_seconds, kernel=self)

    def finish_browser(self, run_dir, observation_path):
        return engine_module('workflow_browser').finish_browser(run_dir, observation_path, kernel=self)
