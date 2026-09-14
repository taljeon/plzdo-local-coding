"""Create bounded text artifacts in new, task-owned, Git-free candidates.

This module validates data and writes exact validated bytes. It never executes
generated code. Validation-pack semantics and sandboxed checks belong to the
controller. Ownership/output receipts are siblings of the initially empty
candidate, keeping evidence outside model-produced files.
"""
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import unicodedata

from json_codec import strict_json
from workflow_core import (ContractError, DIRECTORY, TASK_CATEGORIES, reject_secrets, require,
                           safe_path, validate_task_profile, ProposalError, proposal_require)
from host_paths import validate_state_root, ensure_state_root

MAX_FILE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 256 * 1024
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW


def _json_copy(value):
    """Round-trip strict JSON without accepting non-string keys or NaN."""
    def check_keys(item):
        if isinstance(item, dict):
            require(all(isinstance(key, str) for key in item), 'JSON object keys must be strings')
            for child in item.values():
                check_keys(child)
        elif isinstance(item, list):
            for child in item:
                check_keys(child)
        else:
            require(item is None or type(item) in (bool, int, float, str), 'Expected JSON-safe values')
    try:
        check_keys(value)
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')
        require(len(encoded) <= MAX_TOTAL_BYTES, 'Artifact input exceeds byte budget')
        return strict_json(encoded)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError('Artifact input is not bounded strict JSON') from exc


def _paths(values):
    require(isinstance(values, list) and 1 <= len(values) <= 8, 'One to eight artifact paths required')
    seen, components = set(), {}
    for value in values:
        safe_path(value)
        require(value not in seen, 'Duplicate artifact path')
        seen.add(value)
        for count in range(1, len(PurePosixPath(value).parts) + 1):
            prefix = '/'.join(PurePosixPath(value).parts[:count])
            folded = unicodedata.normalize('NFC', prefix).casefold()
            require(folded not in components or components[folded] == prefix,
                    'Artifact path casefold/Unicode collision')
            components[folded] = prefix
    require(not any(parent.as_posix() in seen for value in values
                    for parent in PurePosixPath(value).parents if parent != PurePosixPath('.')),
            'Artifact file/directory path collision')
    return list(values)


def validate_artifact_packet(raw):
    required = {'kind', 'id', 'objective', 'allowed_paths', 'authorityId', 'generation_profile'}
    optional = {'facts', 'design', 'checks', 'validation_packs', 'risk',
                'local_attempts', 'timeout_seconds', 'task_category'}
    require(isinstance(raw, dict) and required <= set(raw) and not set(raw) - required - optional,
            'Missing/unknown artifact packet fields; repository/base are unsupported')
    packet = _json_copy({**{'facts': {}, 'design': '', 'checks': [], 'validation_packs': [],
                          'risk': 'normal', 'local_attempts': 2,
                          'timeout_seconds': 180}, **raw})
    require(packet['kind'] == 'artifact-create', 'Expected artifact-create kind')
    if 'task_category' in packet:
        require(isinstance(packet['task_category'], str)
                and packet['task_category'] in TASK_CATEGORIES, 'Invalid task_category')
    packet['generation_profile'] = validate_task_profile(packet['generation_profile'])
    for key, maximum in (('id', 80), ('authorityId', 120)):
        require(isinstance(packet[key], str) and 1 <= len(packet[key]) <= maximum
                and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]*', packet[key]), 'Invalid ' + key)
    require(isinstance(packet['objective'], str) and 1 <= len(packet['objective']) <= 16000,
            'Artifact objective length invalid')
    require(isinstance(packet['facts'], dict) and isinstance(packet['design'], str), 'Expected facts object and design string')
    packet['allowed_paths'] = _paths(packet['allowed_paths'])
    require(packet['risk'] in ('normal', 'high'), 'Invalid artifact risk')
    for key, low, high in (('local_attempts', 1, 2), ('timeout_seconds', 10, 1800)):
        require(type(packet[key]) is int and low <= packet[key] <= high, 'Invalid ' + key)
    checks, packs = packet['checks'], packet['validation_packs']
    require(isinstance(checks, list) and len(checks) <= 8, 'Invalid checks list')
    for argv in checks:
        require(isinstance(argv, list) and 1 <= len(argv) <= 40, 'Checks must be argv arrays')
        require(all(isinstance(arg, str) and arg and len(arg) <= 4096
                    and not any(c in arg for c in ('\0', '\n', '\r')) for arg in argv), 'Invalid check argument')
        require(Path(argv[0]).name not in {'sh', 'bash', 'zsh', 'fish', 'dash', 'env', 'sudo', 'osascript'},
                'Shell/wrapper checks unsupported')
    require(isinstance(packs, list) and len(packs) <= 8
            and all(isinstance(pack, (str, dict)) for pack in packs), 'Invalid validation_packs list')
    require(checks or packs, 'At least one immutable check or validation pack is required')
    reject_secrets(json.dumps(packet, ensure_ascii=False))
    return packet


def artifact_schema(paths):
    paths = _paths(paths)
    return {'type': 'object', 'additionalProperties': False, 'required': ['files'],
            'properties': {'files': {'type': 'array', 'minItems': len(paths), 'maxItems': len(paths),
                'items': {'type': 'object', 'additionalProperties': False, 'required': ['path', 'content'],
                    'properties': {'path': {'type': 'string', 'enum': paths},
                                   'content': {'type': 'string', 'minLength': 1, 'maxLength': MAX_FILE_BYTES}}}}}}


def build_artifact_bundle(packet):
    packet = validate_artifact_packet(packet)
    # No local source, repository identity, auth path or HN file is included.
    bundle = {key: packet[key] for key in ('kind', 'id', 'objective', 'allowed_paths', 'facts', 'design',
                                         'checks', 'validation_packs')}
    bundle['capability'] = 'Create every allowed file exactly once as UTF-8/LF text with final newline; no tools or shell.'
    if 'task_category' in packet:
        bundle['task_category'] = packet['task_category']
    reject_secrets(json.dumps(bundle, ensure_ascii=False))
    return bundle


def _packet_hash(packet):
    return hashlib.sha256(json.dumps(packet, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _location(candidate):
    try:
        validate_state_root(DIRECTORY)
    except (OSError, ValueError) as exc:
        raise ContractError(str(exc)) from exc
    candidate = Path(candidate)
    require(candidate.is_absolute() and candidate.resolve() == candidate
            and candidate.is_relative_to(DIRECTORY) and candidate != DIRECTORY,
            'Artifact candidate must be canonical and task-owned under the configured state root')
    safe_path(candidate.relative_to(DIRECTORY).as_posix())
    return candidate


def _parent_fd(candidate, create=False):
    """Walk beneath the trusted workspace using no-follow directory handles."""
    if create:
        ensure_state_root(DIRECTORY)
    descriptor = os.open(DIRECTORY, DIRECTORY_FLAGS)
    try:
        for component in candidate.relative_to(DIRECTORY).parts[:-1]:
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _receipt_name(candidate, kind):
    return '.' + candidate.name + '.artifact-' + kind + '.json'


def _save_at(parent_fd, name, value):
    descriptor = os.open(name, CREATE_FLAGS, 0o600, dir_fd=parent_fd)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(json.dumps(value, ensure_ascii=False, sort_keys=True).encode() + b'\n')


def _load_at(parent_fd, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 16000,
                'Unsafe artifact ownership identity receipt')
        try:
            return strict_json(source.read(16001))
        except (ValueError, RecursionError) as exc:
            raise ContractError('Invalid artifact ownership/output identity receipt') from exc


def create_artifact_candidate(packet, stage_dir):
    packet = validate_artifact_packet(packet)
    candidate = _location(stage_dir)
    parent_fd = _parent_fd(candidate, create=True)
    try:
        for kind in ('owner', 'output'):
            try:
                os.stat(_receipt_name(candidate, kind), dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ContractError('Artifact ownership evidence already exists')
        try:
            os.mkdir(candidate.name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError as exc:
            raise ContractError('Artifact candidate already exists; use a fresh stage') from exc
        descriptor = os.open(candidate.name, DIRECTORY_FLAGS, dir_fd=parent_fd)
        try:
            info = os.fstat(descriptor)
            _save_at(parent_fd, _receipt_name(candidate, 'owner'), {
                'packet_sha256': _packet_hash(packet), 'candidate': str(candidate),
                'device': info.st_dev, 'inode': info.st_ino})
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)
    return candidate


def _owned_fd(packet, candidate):
    candidate = _location(candidate)
    parent_fd = _parent_fd(candidate)
    descriptor = None
    try:
        descriptor = os.open(candidate.name, DIRECTORY_FLAGS, dir_fd=parent_fd)
        owner = _load_at(parent_fd, _receipt_name(candidate, 'owner'))
        info = os.fstat(descriptor)
        require(isinstance(owner, dict) and owner.get('packet_sha256') == _packet_hash(packet)
                and owner.get('candidate') == str(candidate)
                and (owner.get('device'), owner.get('inode')) == (info.st_dev, info.st_ino),
                'Artifact candidate ownership/packet identity mismatch')
        return parent_fd, descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)
        raise


def validate_new_files(packet, payload):
    packet = validate_artifact_packet(packet)
    proposal_require(isinstance(payload, dict) and set(payload) == {'files'}, 'Payload must contain only files')
    files = payload['files']
    proposal_require(isinstance(files, list) and len(files) == len(packet['allowed_paths']), 'Every allowed artifact file is required')
    result, total = {}, 0
    for entry in files:
        proposal_require(isinstance(entry, dict) and set(entry) == {'path', 'content'}, 'File entry must contain only path and content')
        relative = safe_path(entry['path'])
        require(relative in packet['allowed_paths'] and relative not in result, 'Unallowed/duplicate artifact path')
        content = entry['content']
        proposal_require(isinstance(content, str) and content and content.endswith('\n')
                and '\r' not in content and '\0' not in content, 'Artifact must be nonempty UTF-8/LF text with final newline')
        try:
            data = content.encode('utf-8')
        except UnicodeError as exc:
            raise ProposalError('Artifact is not valid UTF-8 text') from exc
        total += len(data)
        proposal_require(len(data) <= MAX_FILE_BYTES and total <= MAX_TOTAL_BYTES, 'Artifact output exceeds byte budget')
        reject_secrets(content)
        try:
            if relative.lower().endswith('.py'):
                ast.parse(content, filename=relative)
            elif relative.lower().endswith('.json'):
                strict_json(content)
        except (ValueError, SyntaxError, RecursionError) as exc:
            raise ProposalError('Invalid artifact syntax: ' + relative) from exc
        result[relative] = data
    proposal_require(set(result) == set(packet['allowed_paths']), 'Artifact path set mismatch')
    return dict(sorted(result.items()))


def apply_new_files(packet, candidate, payload):
    packet = validate_artifact_packet(packet)
    files = validate_new_files(packet, payload)  # Validate entire payload before writes.
    candidate = _location(candidate)
    parent_fd, candidate_fd = _owned_fd(packet, candidate)
    try:
        require(not os.listdir(candidate_fd), 'Artifact candidate mutation/prepopulation; no overwrites')
        manifest = {path: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)} for path, data in files.items()}
        _save_at(parent_fd, _receipt_name(candidate, 'output'), manifest)
        for relative, data in files.items():
            directory_fd = os.dup(candidate_fd)
            try:
                parts = PurePosixPath(relative).parts
                for component in parts[:-1]:
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=directory_fd)
                    except FileExistsError:
                        pass
                    nested = os.open(component, DIRECTORY_FLAGS, dir_fd=directory_fd)
                    os.close(directory_fd)
                    directory_fd = nested
                descriptor = os.open(parts[-1], CREATE_FLAGS, 0o600, dir_fd=directory_fd)
                with os.fdopen(descriptor, 'wb') as output:
                    output.write(data)
            finally:
                os.close(directory_fd)
    finally:
        os.close(candidate_fd)
        os.close(parent_fd)
    scope = inspect_artifact_scope(packet, candidate)
    require(scope['passed'], 'Artifact scope/byte identity mismatch after creation')
    patch = ''.join(''.join(difflib.unified_diff([], data.decode('utf-8').splitlines(keepends=True),
                        fromfile='/dev/null', tofile='b/' + relative)) for relative, data in files.items())
    return {'changed_paths': sorted(files), 'patch': patch}


def inspect_artifact_scope(packet, candidate):
    packet = validate_artifact_packet(packet)
    candidate = _location(candidate)
    parent_fd, candidate_fd = _owned_fd(packet, candidate)
    files, violations = {}, []
    prefixes = {parent.as_posix() for path in packet['allowed_paths'] for parent in PurePosixPath(path).parents
                if parent != PurePosixPath('.')}
    def inspect(directory_fd, prefix=''):
        for name in sorted(os.listdir(directory_fd)):
            relative = prefix + name
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode) and relative in prefixes:
                nested = os.open(name, DIRECTORY_FLAGS, dir_fd=directory_fd)
                try:
                    inspect(nested, relative + '/')
                finally:
                    os.close(nested)
            elif (stat.S_ISREG(info.st_mode) and relative in packet['allowed_paths']
                  and info.st_nlink == 1 and info.st_size <= MAX_FILE_BYTES
                  and stat.S_IMODE(info.st_mode) == 0o600):
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
                with os.fdopen(descriptor, 'rb') as source:
                    data = source.read(MAX_FILE_BYTES + 1)
                files[relative] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
            else:
                violations.append(relative)
    try:
        inspect(candidate_fd)
        violations.extend(sorted(set(packet['allowed_paths']) - set(files)))
        try:
            expected = _load_at(parent_fd, _receipt_name(candidate, 'output'))
        except FileNotFoundError:
            expected = {}
        require(isinstance(expected, dict), 'Invalid artifact output identity receipt')
        if expected != files:
            violations.extend(path for path in set(expected) | set(files) if expected.get(path) != files.get(path))
    finally:
        os.close(candidate_fd)
        os.close(parent_fd)
    return {'passed': not violations, 'changed_paths': sorted(files), 'violations': sorted(set(violations)), 'snapshot': files}
