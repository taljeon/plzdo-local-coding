"""One locked append-only v2 ledger: reserve before dispatch, never refund.

The chain detects corruption, not an operator rewriting all local state. Engine
composition is trusted source; task input cannot instantiate an engine.
"""
from __future__ import annotations

import copy
import math
from pathlib import Path
import re
import time
import uuid

from composition import current_policy, current_state_root
from contracts import (SCHEMA_VERSION as EXACT, SCOPE_VERSION, PARENT_VERSIONS,
                       binding_for_packet, payload_sha256, validate_contract,
                       _now, _timestamp)
from state_io import StateStore, digest, require, strict_json

SCHEMA_VERSION = current_policy().namespace + '.ledger.v2'
_ID = re.compile(r'[a-f0-9]{32}\Z')
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z')
_BASE = {'kind', 'packet', 'packet_sha256', 'reservation_id', 'at', 'sequence',
         'previous_sha256', 'record_sha256', 'authority_observation'}
_CALL = {'engine_id', 'role', 'engine_sha256', 'operation_identity', 'prompt_sha256',
         'schema_sha256', 'evidence_snapshot', 'run_id', 'ordinal'}
_FIELDS = {
    'run': {'run_name', 'run_root'}, 'generate': _CALL, 'review': _CALL,
    'child-send': {'parent_reservation_id', 'admission_sha256', 'prepared_id_digest'},
    'dispatch': {'parent_reservation_id', 'child_claim_id'},
    'engine-result': {'parent_reservation_id', 'receipt_path', 'receipt_sha256',
                      'payload_sha256', 'cleanup_sha256', 'succeeded'},
    'outcome': {'parent_reservation_id', 'receipt_path', 'receipt_sha256', 'disposition', 'supersedes'},
}


def _is_sha256(value):
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def _genesis(document):
    return digest({'schemaVersion': SCHEMA_VERSION, 'contractId': document['id'],
                   'contractPayloadSha256': payload_sha256(document)})


def initial_ledger(document):
    return {'schemaVersion': SCHEMA_VERSION, 'contractId': document['id'],
            'contractPayloadSha256': payload_sha256(document), 'revision': 0,
            'records': [], 'headSha256': _genesis(document)}


def _record_hash(record):
    return digest({key: value for key, value in record.items() if key != 'record_sha256'})


def validate_snapshot(snapshot, prompt_sha, schema_sha, *, fresh=False):
    require(isinstance(snapshot, dict) and set(snapshot) == {
        'preparedIdDigest', 'inputSha256', 'schemaSha256', 'expiresAt', 'facts'},
        'Invalid prepared evidence snapshot fields')
    require(_is_sha256(snapshot['preparedIdDigest']) and snapshot['inputSha256'] == prompt_sha
            and snapshot['schemaSha256'] == schema_sha
            and isinstance(snapshot['facts'], dict) and set(snapshot['facts']) == {'confirmationVerified'}
            and snapshot['facts']['confirmationVerified'] is True, 'Prepared evidence binding mismatch')
    expires = _timestamp(snapshot['expiresAt'])
    if fresh:
        require(_now() < expires, 'Prepared evidence expired')
    return snapshot


def validate_ledger(value, document, *, bindings=None):
    require(isinstance(value, dict) and set(value) == {
        'schemaVersion', 'contractId', 'contractPayloadSha256', 'revision', 'records', 'headSha256'},
        'Corrupt reservation ledger fields')
    require(value['schemaVersion'] == SCHEMA_VERSION and value['contractId'] == document['id']
            and value['contractPayloadSha256'] == payload_sha256(document),
            'Ledger authority/namespace binding mismatch; legacy state cannot be imported')
    records = value['records']
    require(isinstance(records, list) and len(records) <= 30000
            and type(value['revision']) is int and value['revision'] == len(records), 'Corrupt ledger revision')
    if document['schemaVersion'] in (SCOPE_VERSION, PARENT_VERSIONS[1]):
        require(isinstance(bindings, dict), 'Scoped ledger needs verified child bindings')
    else:
        require(bindings is None, 'Exact ledger cannot replace approved bindings')
        bindings = document['execution']['taskBindings']
    head, by_id, runs, calls, children, dispatched, outcomes = _genesis(document), {}, {}, {}, {}, {}, {}
    names, operations, run_counts, slots, finished = set(), set(), {}, {}, set()
    for sequence, record in enumerate(records, 1):
        require(isinstance(record, dict) and record.get('kind') in _FIELDS, 'Unknown ledger record kind')
        kind, identifier = record['kind'], record.get('reservation_id')
        require(set(record) == _BASE | _FIELDS[kind], 'Corrupt ledger record fields')
        require(isinstance(identifier, str) and _ID.fullmatch(identifier) and identifier not in by_id,
                'Duplicate/invalid reservation identity')
        require(type(record['sequence']) is int and record['sequence'] == sequence
                and record['previous_sha256'] == head and record['record_sha256'] == _record_hash(record),
                'Corrupt ledger hash chain')
        require(type(record['at']) in (int, float) and math.isfinite(record['at']) and record['at'] > 0,
                'Corrupt ledger timestamp')
        packet_id = record['packet']
        require(isinstance(packet_id, str) and packet_id in bindings, 'Ledger packet is not bound')
        binding = bindings[packet_id]
        require(record['packet_sha256'] == binding['packetSha256'], 'Ledger packet drift')
        from parent_authority import validate_authority_observation
        validate_authority_observation(record['authority_observation'], document)
        if record['authority_observation'] is not None:
            require(_timestamp(record['authority_observation']['observedAt']).timestamp() <= record['at'],
                    'Parent observation postdates the ledger action')
        if kind == 'run':
            name, root = record['run_name'], record['run_root']
            require(isinstance(name, str) and _NAME.fullmatch(name) and name not in names,
                    'Duplicate/invalid run name')
            require(isinstance(root, str) and Path(root).is_absolute() and Path(root).name == name
                    and str(Path(root)) == root and '..' not in Path(root).parts
                    and root == str(current_state_root() / 'runs' / name), 'Invalid run root')
            names.add(name)
            runs[identifier] = record
            run_counts[packet_id] = run_counts.get(packet_id, 0) + 1
            require(run_counts[packet_id] <= binding['maxRuns'], 'Packet run budget exceeded')
        elif kind in ('generate', 'review'):
            engine, role = record['engine_id'], record['role']
            require({'engineId': engine, 'role': role} in binding['allowedOperations'],
                    'Operation exceeds approved capabilities')
            require(record['engine_sha256'] == document['execution']['enginePins'][engine]['implementationSha256'],
                    'Ledger engine identity mismatch')
            require(all(_is_sha256(record[key]) for key in ('operation_identity', 'prompt_sha256', 'schema_sha256'))
                    and record['operation_identity'] not in operations, 'Duplicate/invalid operation identity')
            operations.add(record['operation_identity'])
            if kind == 'generate':
                run_id, ordinal = record['run_id'], record['ordinal']
                require(run_id in runs and runs[run_id]['packet'] == packet_id
                        and type(ordinal) is int and 1 <= ordinal <= len(binding['generationAttemptPlan']),
                        'Generation run or slot is not approved')
                require(binding['generationAttemptPlan'][ordinal - 1] == {
                    'engineId': engine, 'role': role, 'ordinal': ordinal}, 'Generation plan mismatch')
                require((run_id, ordinal) not in slots and record['evidence_snapshot'] is None,
                        'Generation slot already consumed or contains review authority')
                if ordinal > 1:
                    previous = slots.get((run_id, ordinal - 1))
                    require(previous in outcomes and outcomes[previous]['disposition'] == 'retry',
                            'Previous slot has no verified retry outcome')
                slots[run_id, ordinal] = identifier
            else:
                require(role in ('review', 'design-review') and record['run_id'] is None
                        and record['ordinal'] is None, 'Invalid review operation')
                if engine in current_policy().admission_engines:
                    validate_snapshot(record['evidence_snapshot'], record['prompt_sha256'], record['schema_sha256'])
                    require(record['operation_identity'] == record['evidence_snapshot']['preparedIdDigest'],
                            'Preparation claim must bind its unique identity')
                else:
                    require(record['evidence_snapshot'] is None, 'Unexpected admission snapshot')
            calls[identifier] = record
        else:
            parent_id = record['parent_reservation_id']
            require(parent_id in calls and calls[parent_id]['packet'] == packet_id, 'Missing parent reservation')
            parent = calls[parent_id]
            if kind == 'child-send':
                require(parent['kind'] == 'review' and parent['engine_id'] in current_policy().admission_engines
                        and parent_id not in children and _is_sha256(record['admission_sha256'])
                        and record['prepared_id_digest'] == parent['operation_identity'],
                        'Child send binding or allowance mismatch')
                children[parent_id] = identifier
            elif kind == 'dispatch':
                require(parent_id not in dispatched, 'Reservation dispatch was already claimed')
                child = children.get(parent_id)
                require(record['child_claim_id'] == child and
                        (parent['engine_id'] not in current_policy().admission_engines or child is not None),
                        'Dispatch requires the exact child send claim')
                dispatched[parent_id] = record
            elif kind == 'engine-result':
                require(parent_id in dispatched and parent_id not in finished
                        and type(record['succeeded']) is bool and _is_sha256(record['receipt_sha256'])
                        and _is_sha256(record['cleanup_sha256'])
                        and ((_is_sha256(record['payload_sha256']) and record['succeeded'])
                             or (record['payload_sha256'] is None and not record['succeeded']))
                        and isinstance(record['receipt_path'], str)
                        and Path(record['receipt_path']).is_absolute()
                        and Path(record['receipt_path']).parts[-2:] == ('engine-receipts', parent_id + '.json'),
                        'Invalid or repeated engine completion')
                finished.add(parent_id)
            else:
                require(parent['kind'] == 'generate' and parent_id in dispatched, 'Outcome lacks dispatched generation')
                require(parent_id in finished, 'Outcome lacks a durable engine completion')
                require(record['disposition'] in {'retry', 'accepted', 'pending', 'blocked'}
                        and _is_sha256(record['receipt_sha256']), 'Invalid generation outcome')
                stage = Path(runs[parent['run_id']]['run_root']) / (parent['engine_id'] + '-' + str(parent['ordinal']))
                old = outcomes.get(parent_id)
                if old is None:
                    require(record['supersedes'] is None and record['receipt_path'] == str(stage / 'attempt.json'),
                            'Invalid first outcome receipt')
                else:
                    require(old['disposition'] == 'pending' and record['disposition'] in {'retry', 'accepted', 'blocked'}
                            and record['supersedes'] == old['reservation_id']
                            and record['receipt_path'] == str(stage / 'attempt.browser-final.json'),
                            'Outcome can only finalize one pending browser receipt')
                outcomes[parent_id] = record
            if kind in ('engine-result', 'outcome'):
                require(digest(record['authority_observation']) == digest(dispatched[parent_id]['authority_observation']),
                        'Terminal observation differs from its exact dispatch')
        by_id[identifier], head = record, record['record_sha256']
    require(len(calls) <= document['execution']['maxLiveIntegrationCalls'], 'Global engine call budget exceeded')
    if 'maxTotalRuns' in document['execution']:
        require(len(runs) <= document['execution']['maxTotalRuns'], 'Root run budget exceeded')
    require(value['headSha256'] == head, 'Corrupt ledger head')
    return value


def _current(store, document, binding=None, packet=None, *, observations=None):
    """Recheck fresh authority and source closure inside the existing root lock."""
    require(isinstance(document, dict), 'Expected concrete authority')
    kind, name = document.get('schemaVersion'), document['id'] + '.json'
    if kind in (SCOPE_VERSION, PARENT_VERSIONS[1]):
        from scope_authority import current_scope
        current, bindings = current_scope(store, document, binding=binding, packet=packet, observations=observations)
    else:
        if kind == PARENT_VERSIONS[0]:
            from parent_authority import current_delegated_contract
            current = current_delegated_contract(store, document, binding=binding, packet=packet, observations=observations)
        else:
            require(kind == EXACT, 'Unsupported concrete authority; no legacy budget import')
            validate_contract(document, require_approved=True)
            current = validate_contract(store.read_json('contracts', name), require_approved=True)
            require(current == document, 'Authority changed after load')
        bindings = None
        if packet is not None:
            actual = binding_for_packet(current, packet)
            require(binding is None or binding == actual, 'Supplied packet binding drift')
    raw = store.read_bytes('ledgers', name)
    return validate_ledger(strict_json(raw), current, bindings=bindings), raw, bindings


def historical(store, contract_id):
    """Read/finish existing evidence only; never validate a new-call grant."""
    from contracts import _identifier
    _identifier(contract_id)
    document = store.read_json('contracts', contract_id + '.json')
    require(isinstance(document, dict) and document.get('id') == contract_id, 'Historical authority id mismatch')
    kind = document.get('schemaVersion')
    if kind in PARENT_VERSIONS:
        from parent_authority import historical_delegated_contract
        historical_delegated_contract(store, document)
    elif kind == SCOPE_VERSION:
        from scope_authority import validate_scope
        validate_scope(document, check_freshness=False, historical=True)
    else:
        validate_contract(document, check_freshness=False)
    bindings = None
    if kind in (SCOPE_VERSION, PARENT_VERSIONS[1]):
        from scope_authority import scope_children
        bindings = {key: entry['binding'] for key, entry in scope_children(store, document, historical=True).items()}
    raw = store.read_bytes('ledgers', contract_id + '.json')
    value = validate_ledger(strict_json(raw), document, bindings=bindings)
    return document, value, raw, bindings


def append_locked(store, document, value, raw, record, *, bindings=None, terminal=False):
    require(not terminal or record.get('kind') in {'engine-result', 'outcome'},
            'Historical authority can only close a dispatched operation')
    record = copy.deepcopy(record)
    record.update(reservation_id=uuid.uuid4().hex, at=time.time(), sequence=value['revision'] + 1,
                  previous_sha256=value['headSha256'])
    record['record_sha256'] = _record_hash(record)
    updated = copy.deepcopy(value)
    updated['records'].append(record)
    updated['revision'] += 1
    updated['headSha256'] = record['record_sha256']
    validate_ledger(updated, document, bindings=bindings)
    if not terminal:
        require(_now() < _timestamp(document['expiresAt']), 'Authority expired before ledger commit')
    store.write_json('ledgers', document['id'] + '.json', updated, expected_bytes=raw)
    return record


def snapshot(state_root, document, binding=None, packet=None):
    with StateStore(state_root) as store, store.locked():
        value, _, _ = _current(store, document, binding, packet)
        return copy.deepcopy(value)


def get_record(state_root, document, binding, packet, reservation_id):
    value = snapshot(state_root, document, binding, packet)
    return record_by_id(value, reservation_id, packet['id'])


def record_by_id(value, identifier, packet_id):
    record = next((item for item in value['records'] if item['reservation_id'] == identifier), None)
    require(record is not None and record['packet'] == packet_id, 'Reservation evidence not found')
    return record


def summary(value):
    records = value['records']
    return {'revision': value['revision'], 'runs': sum(item['kind'] == 'run' for item in records),
            'engine_calls_consumed': sum(item['kind'] in ('generate', 'review') for item in records),
            'dispatch_claims': sum(item['kind'] == 'dispatch' for item in records),
            'child_send_claims': sum(item['kind'] == 'child-send' for item in records),
            'crash_refund': False}
