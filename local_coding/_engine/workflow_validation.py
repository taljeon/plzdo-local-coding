"""Frozen, bounded validation packs for read-only candidates and new artifacts.

The packet owns the assertions. Generated files cannot supply schemas, commands,
or executable test logic. Every subprocess is run in the existing Codex offline
sandbox; only scratch is writable, and candidate bytes are checked afterward.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time

from json_codec import strict_json
from run_bounded import run
from host_paths import SOURCE_DIRECTORY, runtime_commands, runtime_policy, clean_check_path, verify_trusted_file

# This legacy name denotes trusted code here, never evidence or candidates.
DIRECTORY = SOURCE_DIRECTORY
MAX_FILE_BYTES = 128 * 1024
MAX_TREE_BYTES = 100 * 1024 * 1024
MAX_PACKS = 8
MAX_PYTHON_RUNTIME_BYTES = 512 * 1024 * 1024
# Frozen builtin parsers can reject candidate data using these known errors.
# Any other error is infrastructure/unknown, never permission for another slot.
BENIGN_BUILTIN_ERRORS = frozenset({'JSONDecodeError', 'ValueError', 'SyntaxError',
                                  'UnicodeDecodeError', 'UnicodeEncodeError'})


def _require(condition, message):
    if not condition:
        from workflow_core import ContractError
        raise ContractError(message)


def _path(value):
    from workflow_core import safe_path
    return safe_path(value)


def _strings(values, *, maximum=40, length=2000):
    _require(isinstance(values, list) and len(values) <= maximum, 'Invalid validation string list')
    _require(all(isinstance(value, str) and value and len(value) <= length
                 and '\0' not in value for value in values), 'Invalid validation assertion')
    _require(len(values) == len(set(values)), 'Duplicate validation assertions')
    return list(values)


def _schema_tree(schema, depth=0):
    _require(depth <= 24, 'JSON schema exceeds the nesting limit')
    if isinstance(schema, dict):
        for key, value in schema.items():
            _require(isinstance(key, str), 'JSON schema keys must be strings')
            if key == '$ref':
                _require(isinstance(value, str) and value.startswith('#'),
                         'Remote/nonlocal JSON schema references are forbidden')
            _require(key not in {'$dynamicRef', '$recursiveRef', '$id'},
                     'Dynamic references and schema IDs are unsupported')
            if key == '$schema':
                _require(value in {'https://json-schema.org/draft/2020-12/schema',
                                   'https://json-schema.org/draft/2020-12/schema#'},
                         'Only JSON Schema draft 2020-12 is supported')
            _schema_tree(value, depth + 1)
    elif isinstance(schema, list):
        for value in schema:
            _schema_tree(value, depth + 1)


def validate_packs(packs, allowed_paths):
    """Normalize host-owned assertions before they are bound into packet hashes."""
    _require(isinstance(packs, list) and len(packs) <= MAX_PACKS, 'Invalid validation packs')
    _require(isinstance(allowed_paths, list) and len(allowed_paths) <= 8,
             'Validation requires an exact allowed path list')
    allowed = {_path(value) for value in allowed_paths}
    result = []
    for pack in packs:
        _require(isinstance(pack, dict), 'Validation pack must be an object')
        kind = pack.get('type')
        if kind == 'python-syntax':
            _require(set(pack) == {'type', 'paths'}, 'Invalid python-syntax fields')
            paths = _strings(pack['paths'], maximum=8, length=240)
            _require(paths, 'Python syntax pack must contain paths')
            for path in paths:
                _require(_path(path) in allowed and path.endswith('.py'), 'Unallowed Python validation path')
            normalized = {'type': kind, 'paths': paths}
        elif kind == 'json-schema':
            _require(set(pack) == {'type', 'path', 'schema'}, 'Invalid json-schema fields')
            _require(_path(pack['path']) in allowed and pack['path'].endswith('.json'),
                     'Unallowed JSON validation path')
            _require(isinstance(pack['schema'], dict), 'Schema must be a frozen host object')
            try:
                serialized = json.dumps(pack['schema'], allow_nan=False, ensure_ascii=False)
            except (TypeError, ValueError) as exc:
                _require(False, 'Schema must contain JSON values: ' + type(exc).__name__)
            _require(len(serialized.encode()) <= 32768, 'JSON schema exceeds byte limit')
            schema = json.loads(serialized)
            _schema_tree(schema)
            try:
                from jsonschema import Draft202012Validator
            except ImportError as exc:
                _require(False, 'jsonschema runtime is unavailable; validation cannot be skipped')
            try:
                Draft202012Validator.check_schema(schema)
            except Exception as exc:
                _require(False, 'Invalid host JSON schema: ' + type(exc).__name__)
            normalized = {'type': kind, 'path': pack['path'], 'schema': schema}
        elif kind == 'text':
            _require({'type', 'path'} <= set(pack) <= {'type', 'path', 'required', 'forbidden'},
                     'Invalid text validation fields')
            _require(_path(pack['path']) in allowed, 'Unallowed text validation path')
            required, forbidden = _strings(pack.get('required', [])), _strings(pack.get('forbidden', []))
            _require(required or forbidden, 'Text pack needs at least one assertion')
            _require(not set(required) & set(forbidden), 'Conflicting text assertions')
            normalized = {'type': kind, 'path': pack['path'], 'required': required, 'forbidden': forbidden}
        elif kind == 'html-browser':
            _require({'type', 'path'} <= set(pack) <= {'type', 'path', 'expected_text', 'clicks', 'widths', 'driver'},
                     'Invalid html-browser fields')
            _require(_path(pack['path']) in allowed and pack['path'].endswith(('.html', '.htm')),
                     'Unallowed HTML validation path')
            expected = _strings(pack.get('expected_text', []), maximum=20, length=500)
            widths = pack.get('widths', [390, 1280])
            _require(isinstance(widths, list) and 1 <= len(widths) <= 3
                     and all(type(value) is int and 320 <= value <= 1920 for value in widths)
                     and len(widths) == len(set(widths)), 'Invalid browser viewport widths')
            clicks = pack.get('clicks', [])
            _require(isinstance(clicks, list) and len(clicks) <= 8, 'Invalid browser click assertions')
            normalized_clicks = []
            for click in clicks:
                _require(isinstance(click, dict) and set(click) == {'selector', 'expect_text'},
                         'Invalid browser click fields')
                _strings([click['selector']], maximum=1, length=200)
                _strings([click['expect_text']], maximum=1, length=500)
                _require(click['expect_text'] not in expected,
                         'Click expectation must become visible, not be required initially')
                normalized_clicks.append(dict(click))
            normalized = {'type': kind, 'path': pack['path'], 'expected_text': expected,
                          'clicks': normalized_clicks, 'widths': list(widths)}
            if 'driver' in pack:
                _require(pack['driver'] in ('native', 'managed'), 'Invalid browser validation driver')
                # Preserve already-bound legacy hashes when no driver was supplied.
                normalized['driver'] = pack['driver']
        else:
            _require(False, 'Unknown validation pack type')
        result.append(normalized)
    return result


def _read_text(root, relative):
    # Child helper uses this path check without importing any candidate modules.
    _require(isinstance(relative, str) and relative and not PurePosixPath(relative).is_absolute()
             and not any(part in {'', '.', '..'} for part in relative.split('/')),
             'Unsafe validation file path')
    target = Path(root)
    for part in PurePosixPath(relative).parts:
        target = target / part
        _require(not target.is_symlink(), 'Symlink validation files are forbidden')
    _require(target.is_file() and stat.S_ISREG(target.stat().st_mode)
             and target.stat().st_size <= MAX_FILE_BYTES, 'Missing or oversized validation file')
    data = target.read_bytes()
    _require(len(data) <= MAX_FILE_BYTES, 'Validation file exceeded byte limit')
    text = data.decode('utf-8')
    _require('\0' not in text, 'Binary validation files are unsupported')
    return text


def _run_builtin(pack, candidate):
    kind, failures = pack['type'], []
    if kind == 'python-syntax':
        for relative in pack['paths']:
            try:
                ast.parse(_read_text(candidate, relative), filename=relative)
            except (SyntaxError, ValueError, UnicodeError) as exc:
                failures.append({'path': relative, 'reason': type(exc).__name__})
    elif kind == 'text':
        text = _read_text(candidate, pack['path'])
        failures += [{'reason': 'required-text-missing', 'text': value}
                     for value in pack['required'] if value not in text]
        failures += [{'reason': 'forbidden-text-present', 'text': value}
                     for value in pack['forbidden'] if value in text]
    elif kind == 'json-schema':
        from jsonschema import Draft202012Validator
        _schema_tree(pack['schema'])
        value = strict_json(_read_text(candidate, pack['path']))
        # Remote/dynamic refs were rejected above; no model-provided schemas are loaded.
        validator = Draft202012Validator(pack['schema'])
        for error in validator.iter_errors(value):
            failures.append({'reason': 'schema-mismatch', 'instance_path': list(error.absolute_path),
                             'schema_path': list(error.absolute_schema_path)})
            if len(failures) == 20:
                break
    else:
        raise ValueError('Unsupported builtin pack')
    return {'passed': not failures, 'type': kind, 'failures': failures, 'executed': True}


def _tree_snapshot(candidate):
    root, result, total = Path(candidate), {}, 0
    _require(root.is_dir() and root.resolve() == root, 'Validation candidate must be canonical')
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in sorted(directories + files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            _path(relative)
            info = path.lstat()
            _require(not stat.S_ISLNK(info.st_mode), 'Validation candidate contains symlink')
            if stat.S_ISDIR(info.st_mode):
                continue
            _require(stat.S_ISREG(info.st_mode), 'Validation candidate contains special file')
            total += info.st_size
            _require(total <= MAX_TREE_BYTES, 'Validation candidate exceeds snapshot limit')
            result[relative] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                                'mode': stat.S_IMODE(info.st_mode)}
    return result


def _readonly_entry(path):
    return {'path': {'type': 'path', 'path': str(Path(path).resolve(strict=True))}, 'access': 'read'}


def _python_runtime_plan():
    """Select only explicitly pinned files from one self-contained Python prefix."""
    try:
        policy = runtime_policy()
    except (OSError, ValueError) as exc:
        _require(False, 'Python runtime identity was not admitted: ' + type(exc).__name__)
    executables = {item['command']: item for item in policy['executables']}
    binary = executables.get('python3') or executables.get('python')
    if binary is None:
        return None
    executable = Path(binary['path'])
    _require(executable.parent.name == 'bin' and re.fullmatch(r'python(?:3(?:\.\d+)?)?', executable.name),
             'Python runtime requires a relocatable prefix/bin/python layout')
    prefix = executable.parent.parent
    for path in (prefix / 'pyvenv.cfg', prefix / 'bin/pyvenv.cfg'):
        _require(not path.exists() and not path.is_symlink(),
                 'Python virtual-environment references are forbidden in frozen runtime')
    files = [item for item in policy['executables'] + policy['read_files']
             if Path(item['path']).is_relative_to(prefix)]
    _require(sum(Path(item['path']).stat().st_size for item in files) <= MAX_PYTHON_RUNTIME_BYTES,
             'Frozen Python runtime exceeds the declared staging byte limit')
    names = {Path(item['path']).relative_to(prefix).as_posix() for item in files}
    _require(not any(PurePosixPath(name).name == 'pyvenv.cfg' for name in names),
             'Python virtual-environment references are forbidden in frozen runtime')
    versions = {PurePosixPath(name).parts[1] for name in names
                if len(PurePosixPath(name).parts) >= 3 and PurePosixPath(name).parts[0] == 'lib'
                and re.fullmatch(r'python3\.\d+', PurePosixPath(name).parts[1])}
    _require(len(versions) == 1, 'Python runtime requires one complete lib/pythonX.Y standard library')
    version = next(iter(versions))
    required = {f'lib/{version}/' + name for name in ('os.py', 'codecs.py', 'encodings/__init__.py')}
    _require(required <= names, 'Python runtime standard library is incomplete')
    _require(executable.name in ('python', 'python3', version), 'Python executable and standard library versions differ')
    return {'prefix': prefix, 'executable': executable, 'version': version, 'files': files}


def _frozen_copy(runtime, name, source, expected_hash, mode):
    """Copy through owned directory descriptors; no source modes are changed."""
    _path(name)
    _require(source.resolve(strict=True) == source, 'Trusted runtime source must be canonical')
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    directory_fd = os.open(runtime, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    target_fd = None
    try:
        before = os.fstat(source_fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_uid in {0, os.getuid()} and not before.st_mode & 0o022
                 and 0 <= before.st_size <= 512 * 1024 * 1024, 'Unsafe trusted runtime source')
        for component in PurePosixPath(name).parts[:-1]:
            try:
                os.mkdir(component, mode=0o700, dir_fd=directory_fd)
            except FileExistsError:
                pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child
        target_fd = os.open(PurePosixPath(name).name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        checksum, size = hashlib.sha256(), 0
        while chunk := os.read(source_fd, 1024 * 1024):
            size += len(chunk)
            _require(size <= before.st_size, 'Trusted runtime source grew while staging')
            checksum.update(chunk)
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(target_fd, remaining)
                _require(written > 0, 'Frozen runtime write did not progress')
                remaining = remaining[written:]
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        _require(identity(before) == identity(os.fstat(source_fd)) == identity(source.lstat())
                 and size == before.st_size and checksum.hexdigest() == expected_hash,
                 'Trusted runtime source identity or bytes changed while staging')
        os.fchmod(target_fd, mode)
        return {'name': name, 'source': str(source), 'sha256': expected_hash, 'bytes': size, 'mode': mode}
    finally:
        if target_fd is not None:
            os.close(target_fd)
        os.close(directory_fd)
        os.close(source_fd)


def _stage_runtime(evidence, *, browser=False, python=False, check_files=()):
    """Give Python a listable import directory containing only trusted helpers."""
    runtime = evidence / 'runtime'
    runtime.mkdir(mode=0o700)
    receipt = []
    names = ('workflow_validation.py', 'workflow_core.py', 'run_bounded.py', 'host_paths.py',
             'json_codec.py', 'engine_types.py', 'provider_common.py')
    if browser:
        names += ('browser_check.cjs',)
    for name in names:
        source = SOURCE_DIRECTORY / name
        _require(source.is_file() and not source.is_symlink(), 'Invalid trusted validation source')
        receipt.append(_frozen_copy(runtime, name, source, hashlib.sha256(source.read_bytes()).hexdigest(), 0o400))
    plan = _python_runtime_plan() if python else None
    if plan:
        _require(os.pathsep not in str(runtime), 'Frozen Python paths cannot contain PATH separators')
        for item in plan['files']:
            source = Path(item['path'])
            name = 'python/' + source.relative_to(plan['prefix']).as_posix()
            mode = 0o500 if source == plan['executable'] else 0o400
            receipt.append(_frozen_copy(runtime, name, source, item['sha256'], mode))
    if check_files:
        declared = {item['path']: item['sha256'] for item in runtime_policy()['read_files']}
        _require(len(check_files) <= 16 * 39 and all(
            set(item) == {'path', 'sha256'} and declared.get(item['path']) == item['sha256']
            for item in check_files), 'Runtime identity: custom check files were not admitted')
        copied = {item['source']: item['sha256'] for item in receipt}
        _require(sum(item['bytes'] for item in receipt) + sum(Path(item['path']).stat().st_size
                 for item in check_files if item['path'] not in copied) <= MAX_PYTHON_RUNTIME_BYTES,
                 'Frozen custom check runtime exceeds the declared staging byte limit')
        for index, item in enumerate(check_files, 1):
            if item['path'] in copied:
                _require(copied[item['path']] == item['sha256'], 'Runtime identity: custom check file pin differs')
                continue
            source = Path(item['path'])
            name = f'check-files/{index}/{source.name}'
            receipt.append(_frozen_copy(runtime, name, source, item['sha256'], 0o400))
    for directory, _, _ in os.walk(runtime, topdown=False, followlinks=False):
        Path(directory).chmod(0o500)
    with (evidence / 'runtime-receipt.json').open('x', encoding='utf-8') as output:
        json.dump({'runtime': str(runtime), 'files': receipt}, output, indent=2)
        output.write('\n')
    _verify_runtime(runtime, receipt)
    return runtime, receipt


def _verify_runtime(runtime, receipt):
    try:
        _verify_runtime_contents(runtime, receipt)
    except (OSError, ValueError) as exc:
        _require(False, 'Runtime identity: frozen validation closure changed: ' + str(exc))


def _verify_runtime_contents(runtime, receipt):
    _require(not runtime.is_symlink() and runtime.is_dir() and runtime.resolve() == runtime
             and stat.S_IMODE(runtime.stat().st_mode) == 0o500, 'Trusted validation runtime changed')
    expected_files = {item['name'] for item in receipt}
    expected_dirs = {parent.as_posix() for name in expected_files for parent in PurePosixPath(name).parents
                     if parent != PurePosixPath('.')}
    actual_files, actual_dirs = set(), set()
    for directory, directories, files in os.walk(runtime, followlinks=False):
        for name in directories:
            path = Path(directory) / name
            _require(not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) == 0o500,
                     'Trusted validation runtime directory changed')
            actual_dirs.add(path.relative_to(runtime).as_posix())
        actual_files.update((Path(directory) / name).relative_to(runtime).as_posix() for name in files)
    _require(actual_files == expected_files and actual_dirs == expected_dirs,
             'Trusted validation runtime files or directories changed')
    for item in receipt:
        _path(item['name'])
        path = runtime / item['name']
        _require(item.get('mode', 0o400) in (0o400, 0o500), 'Invalid frozen runtime mode')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                     and stat.S_IMODE(before.st_mode) == item.get('mode', 0o400)
                     and before.st_size == item['bytes'], 'Trusted validation runtime changed')
            checksum, size = hashlib.sha256(), 0
            while chunk := os.read(descriptor, 1024 * 1024):
                size += len(chunk)
                _require(size <= before.st_size, 'Frozen runtime grew during verification')
                checksum.update(chunk)
            identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            _require(identity(before) == identity(os.fstat(descriptor)) == identity(path.lstat())
                     and size == before.st_size and checksum.hexdigest() == item['sha256'],
                     'Trusted validation runtime changed')
        finally:
            os.close(descriptor)


def _staged_python(runtime, receipt):
    executables = [runtime / item['name'] for item in receipt
                   if item['name'].startswith('python/bin/') and item.get('mode') == 0o500]
    if not executables:
        return None
    versions = {PurePosixPath(item['name']).parts[2] for item in receipt
                if item['name'].startswith('python/lib/python') and len(PurePosixPath(item['name']).parts) >= 4}
    _require(len(executables) == len(versions) == 1, 'Frozen Python identity is incomplete')
    prefix = runtime / 'python'
    return executables[0], prefix, prefix / 'lib' / next(iter(versions)) / 'site-packages'


def _state(candidate, allowed_paths, scratch, spec_path, runtime, browser=False, *, runtime_executable=None,
           frozen_python=False):
    from workflow_core import build_permission_state
    state = build_permission_state(candidate, allowed_paths, scratch, readonly=True,
                                   runtime_executable=runtime_executable)
    entries = state['permissionProfile']['file_system']['entries']
    if frozen_python:
        # The frozen prefix is complete. Original runtime files and other
        # configured runtimes must not become an external import fallback.
        entries[:] = [entry for entry in entries if not (entry['access'] == 'read'
            and entry['path']['type'] == 'path' and entry['path']['path'] != str(candidate))]
    # Python FileFinder needs directory metadata. An exact staged helper closure
    # supplies that without revealing the source workspace or prior evidence.
    for path in (runtime, spec_path):
        entries.append(_readonly_entry(path))
    # Browser code, when needed, is in the same hash-verified helper closure.
    # Its dependencies are exact files admitted by the host runtime policy.
    return state


def _is_python_executable(path):
    return path is not None and re.fullmatch(r'python(?:3(?:\.\d+)?)?', Path(path).name) is not None


def _custom_python_file_refs(argv, policy):
    """Admit only whole file operands in a plain, explicitly pinned script form."""
    declared = {item['path']: item for item in policy['read_files']}
    refs = [{'argv_index': index, **declared[value]} for index, value in enumerate(argv)
            if index > 0 and value in declared]
    if not refs:
        return []
    index = 1
    while index < len(argv) and argv[index] in {
            '-B', '-b', '-bb', '-d', '-E', '-i', '-I', '-O', '-OO', '-P', '-q',
            '-s', '-S', '-u', '-v', '-vv', '-x'}:
        index += 1
    if index < len(argv) and argv[index] == '--':
        index += 1
    _require(index < len(argv) and index in {item['argv_index'] for item in refs},
             'Runtime identity: custom file mapping requires a pinned script; code/module/option contexts are unsupported')
    return refs


def _custom_python_files(prepared_commands):
    if not any(_is_python_executable(executable) for _, executable in prepared_commands):
        return []
    try:
        policy = runtime_policy()
    except (OSError, ValueError) as exc:
        _require(False, 'Runtime identity: custom Python file policy was not admitted: ' + type(exc).__name__)
    files = {}
    for argv, executable in prepared_commands:
        if _is_python_executable(executable):
            for item in _custom_python_file_refs(argv, policy):
                files[item['path']] = {'path': item['path'], 'sha256': item['sha256']}
    return list(files.values())


def _custom_python_command(argv, runtime, receipt):
    """Replace the pinned interpreter and exact file operands, preserving other tokens."""
    staged = _staged_python(runtime, receipt)
    _require(staged is not None, 'Runtime identity: custom Python requires a frozen prefix')
    executable = staged[0]
    pin = next(item for item in receipt if item['name'] == executable.relative_to(runtime).as_posix())
    _require(argv[0] == pin['source'], 'Runtime identity: custom Python executable differs from frozen source')
    try:
        policy = runtime_policy()
    except (OSError, ValueError) as exc:
        _require(False, 'Runtime identity: custom Python policy changed after staging: ' + type(exc).__name__)
    selected = next((item for command in ('python3', 'python') for item in policy['executables']
                     if item['command'] == command), None)
    _require(selected is not None and selected['path'] == pin['source'] and selected['sha256'] == pin['sha256'],
             'Runtime identity: custom Python binding changed after staging')
    prefix = Path(pin['source']).parent.parent
    expected = {item['path']: item['sha256'] for item in policy['executables'] + policy['read_files']
                if Path(item['path']).is_relative_to(prefix)}
    frozen = {item['source']: item['sha256'] for item in receipt if item['name'].startswith('python/')}
    _require(expected == frozen, 'Runtime identity: custom Python closure differs from its policy')
    executed = [str(executable), *argv[1:]]
    frozen_files = {item['source']: item for item in receipt}
    reads, file_arguments = [], []
    for item in _custom_python_file_refs(argv, policy):
        frozen_file = frozen_files.get(item['path'])
        _require(frozen_file is not None and frozen_file['sha256'] == item['sha256'],
                 'Runtime identity: custom check file differs from its frozen source')
        target = str(runtime / frozen_file['name'])
        executed[item['argv_index']] = target
        reads.append({'path': item['path'], 'sha256': item['sha256']})
        file_arguments.append({'argv_index': item['argv_index'], 'source_path': item['path'],
                               'source_sha256': item['sha256'], 'staged_path': target})
    mapping = {'source_executable': pin['source'], 'source_sha256': pin['sha256'],
               'staged_executable': str(executable),
               'runtime_policy_path': os.environ.get('LOCAL_CODING_RUNTIME_POLICY'),
               'runtime_policy_sha256': os.environ.get('LOCAL_CODING_RUNTIME_POLICY_SHA256'),
               'file_arguments': file_arguments}
    return executed, reads, mapping


def _verify_command_reads(reads):
    try:
        for item in reads:
            verify_trusted_file(item['path'], item['sha256'])
    except (OSError, ValueError) as exc:
        _require(False, 'Runtime identity: declared checker/data file changed: ' + type(exc).__name__)


def _validate_commands(checks):
    _require(isinstance(checks, list) and len(checks) <= 16, 'Invalid artifact check commands')
    result = []
    for argv in checks:
        _require(isinstance(argv, list) and 1 <= len(argv) <= 40
                 and all(isinstance(arg, str) and arg and len(arg) <= 4096
                         and not any(c in arg for c in ('\0', '\n', '\r')) for arg in argv),
                 'Artifact checks require bounded argv arrays')
        _require(Path(argv[0]).name not in {'sh', 'bash', 'zsh', 'fish', 'dash', 'env', 'sudo', 'osascript'},
                 'Shell/wrapper artifact checks are unsupported')
        result.append(list(argv))
    return result


def _validate_browser_report(report, pack, scratch):
    """A successful browser claim must include the requested render evidence."""
    if report.get('passed') is not True:
        return
    _require(report.get('external_resources') == [] and report.get('console_errors') == []
             and report.get('page_errors') == [], 'Browser report contains errors or blocked resources')
    viewports = report.get('viewports')
    _require(isinstance(viewports, list) and len(viewports) == len(pack['widths']),
             'Browser report is missing requested viewports')
    for width, viewport in zip(pack['widths'], viewports):
        _require(isinstance(viewport, dict) and viewport.get('width') == width
                 and viewport.get('passed') is True, 'Browser viewport did not pass')
        layout = viewport.get('layout', {})
        _require(layout.get('horizontal_overflow') is False and layout.get('body_present') is True,
                 'Browser layout evidence is incomplete')
        _require(viewport.get('expected_text') == [{'text': text, 'visible': True} for text in pack['expected_text']],
                 'Browser visible-text evidence is incomplete')
        _require(viewport.get('clicks') == [{**click, 'before_visible': False, 'after_visible': True,
                                           'passed': True} for click in pack['clicks']],
                 'Browser interaction evidence is incomplete')
        raw = viewport.get('screenshot')
        _require(isinstance(raw, str), 'Browser screenshot path is missing')
        image = Path(raw)
        _require(image.is_absolute() and image.resolve() == image and image.is_relative_to(scratch)
                 and image.is_file() and not image.is_symlink() and image.stat().st_size <= 16 * 1024 * 1024,
                 'Browser screenshot must be a bounded task-owned file')
        with image.open('rb') as stream:
            _require(stream.read(8) == b'\x89PNG\r\n\x1a\n', 'Browser screenshot is not a PNG')


def _execute(packet, candidate, evidence_dir, *, artifact):
    from workflow_core import snapshot, prepare_check_command, check_execution_receipt
    candidate, evidence = Path(candidate), Path(evidence_dir)
    _require(candidate.is_absolute() and candidate.resolve() == candidate, 'Candidate must be canonical')
    _require(evidence.is_absolute() and evidence.resolve() == evidence
             and not evidence.is_relative_to(candidate), 'Validation evidence must be outside candidate')
    packs = validate_packs(packet.get('validation_packs', []), packet['allowed_paths'])
    commands = _validate_commands(packet.get('checks', []) + packet.get('regression_checks', [])) if artifact else []
    prepared_commands = [prepare_check_command(argv) for argv in commands]
    custom_python = any(_is_python_executable(executable) for _, executable in prepared_commands)
    check_files = _custom_python_files(prepared_commands)
    timeout = packet.get('timeout_seconds', 180)
    _require(type(timeout) is int and 1 <= timeout <= 1800, 'Invalid validation timeout')
    take_snapshot = _tree_snapshot if artifact else snapshot
    before = take_snapshot(candidate)
    allowed = set(packet['allowed_paths'])
    initial_violations = sorted(set(before) - allowed) if artifact else []
    missing = sorted(allowed - set(before)) if artifact else []
    evidence.mkdir(parents=True, exist_ok=False)
    scratch = evidence / 'scratch'
    scratch.mkdir()
    try:
        runtime, runtime_receipt = _stage_runtime(evidence, browser=any(
            pack['type'] == 'html-browser' and pack.get('driver') != 'managed' for pack in packs),
            python=custom_python or any(pack['type'] in ('python-syntax', 'json-schema', 'text') for pack in packs),
            check_files=check_files)
    except (OSError, ValueError) as exc:
        _require(False, 'Runtime identity: frozen validation staging failed: ' + str(exc))
    staged_python = _staged_python(runtime, runtime_receipt)
    records, pending_browser, deadline = [], [], time.monotonic() + timeout
    jobs = [('command', argv) for argv in commands] + [('pack', pack) for pack in packs]
    if initial_violations or missing:
        jobs = []
    for index, (job_type, value) in enumerate(jobs, 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if job_type == 'pack' and value['type'] == 'html-browser' and value.get('driver') == 'managed':
            pending_browser.append({'pack_index': index - len(commands) - 1, 'pack': value})
            records.append({'argv': [], 'return_code': None, 'duration_seconds': None,
                            'evidence_dir': str(evidence), 'kind': 'html-browser',
                            'executed': False, 'status': 'awaiting_browser_validation',
                            'required_pack': value})
            # Required handoff, never a skipped success and never a native launch.
            continue
        spec_path = evidence / ('spec-' + str(index) + '.json')
        browser = job_type == 'pack' and value['type'] == 'html-browser'
        spec = {'candidate': str(candidate), 'pack': value if job_type == 'pack' else None,
                'scratch': str(scratch / ('pack-' + str(index)))}
        browser_node = None
        if browser:
            try:
                browser_node, playwright, chrome = runtime_commands(('node', 'playwright', 'chrome'))
            except (OSError, ValueError) as exc:
                _require(False, 'Browser runtime identity was not admitted: ' + type(exc).__name__)
            _require(all((browser_node, playwright, chrome)),
                     'Native browser runtime identity requires explicit byte-pinned node, playwright and chrome bindings')
            spec['runtime'] = {'playwright': str(playwright), 'chrome': str(chrome)}
        with spec_path.open('x', encoding='utf-8') as stream:
            json.dump(spec, stream, ensure_ascii=False, allow_nan=False)
        Path(spec['scratch']).mkdir()
        runtime_executable = None
        python_environment = []
        command_reads, command_mapping = [], None
        frozen_python = False
        if job_type == 'command':
            argv, runtime_executable = prepared_commands[index - 1]
            if _is_python_executable(runtime_executable):
                argv, command_reads, command_mapping = _custom_python_command(argv, runtime, runtime_receipt)
                command_mapping['declared_executable'] = value[0]
                runtime_executable, frozen_python = argv[0], True
        elif browser:
            argv = [str(browser_node), str(runtime / 'browser_check.cjs'), str(spec_path)]
            runtime_executable = str(browser_node)
        else:
            if staged_python:
                executable, prefix, packages = staged_python
                python_environment = ['PYTHONHOME=' + str(prefix), 'PYTHONPATH=' + str(packages),
                                      'PYTHONNOUSERSITE=1']
                switches = ['-B', '-S']
            else:
                executable, switches = Path(sys.executable).resolve(strict=True), ['-B']
            argv = [str(executable), *switches, str(runtime / 'workflow_validation.py'), '--builtin', str(spec_path)]
            runtime_executable = str(executable)
        state = _state(candidate, packet['allowed_paths'], scratch, spec_path, runtime, browser,
                       runtime_executable=runtime_executable, frozen_python=frozen_python or bool(python_environment))
        environment = ['/usr/bin/env', '-i',
                       'PATH=' + clean_check_path(),
                       'TMPDIR=' + str(scratch), 'TMP=' + str(scratch), 'TEMP=' + str(scratch),
                       'XDG_CONFIG_HOME=' + str(scratch / 'config'), 'XDG_CACHE_HOME=' + str(scratch / 'cache'),
                       'PYTHONDONTWRITEBYTECODE=1', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD=1',
                       'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null',
                       'CARGO_TARGET_DIR=' + str(scratch / 'cargo'), *python_environment]
        command = ['codex', 'sandbox', '--sandbox-state-json', json.dumps(state), '--', *environment, *argv]
        process_evidence = evidence / ('check-' + str(index))
        _verify_runtime(runtime, runtime_receipt)
        _verify_command_reads(command_reads)
        summary = run(command, candidate, process_evidence, remaining, pipe_output=True,
                      env_allowlist={'PATH', 'HOME', 'CODEX_HOME', 'USER', 'LOGNAME', 'SHELL', 'LANG', 'TERM'})
        _verify_runtime(runtime, runtime_receipt)
        _verify_command_reads(command_reads)
        record = {'argv': argv, 'return_code': summary['return_code'],
                  'duration_seconds': summary['duration_seconds'], 'evidence_dir': str(process_evidence),
                  'kind': value['type'] if job_type == 'pack' else 'command', 'executed': True,
                  'execution_receipt': check_execution_receipt(summary, process_evidence)}
        if command_mapping is not None:
            record['python_runtime'] = command_mapping
        if job_type == 'pack':
            try:
                output = process_evidence / 'events.jsonl'
                _require(output.stat().st_size <= 2 * 1024 * 1024, 'Validation report too large')
                report = strict_json(output.read_text())
                _require(isinstance(report, dict) and type(report.get('passed')) is bool
                         and report.get('executed') is True, 'Invalid validation report')
                if browser:
                    _validate_browser_report(report, value, Path(spec['scratch']))
                record['report'] = report
                if report.get('error') and report['error'] not in BENIGN_BUILTIN_ERRORS:
                    record['execution_receipt']['passed'] = False
                    record['execution_receipt']['diagnostic_codes'].append('CHECK_BUILTIN_INFRASTRUCTURE_FAILED')
                    record['execution_receipt']['diagnostic_codes'].sort()
                if report['passed'] is not True:
                    record['return_code'] = record['return_code'] or 1
            except (OSError, ValueError, UnicodeError) as exc:
                record['return_code'] = record['return_code'] or 1
                record['report_error'] = type(exc).__name__
        records.append(record)
        if record['return_code'] != 0 or not record['execution_receipt']['passed']:
            break
    after = take_snapshot(candidate)
    mutation = sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
    if artifact:
        missing = sorted(allowed - set(after))
    scope = {'passed': not mutation and not initial_violations and not missing,
             'changed_paths': mutation, 'violations': sorted(set(mutation) | set(initial_violations)),
             'missing_paths': missing}
    non_browser_passed = len(records) == len(commands) + len(packs) and scope['passed'] and all(
        (row.get('status') == 'awaiting_browser_validation' and row['executed'] is False)
        or (row['executed'] is True and row['return_code'] == 0
            and row['execution_receipt']['passed']) for row in records)
    result = {'passed': non_browser_passed and not pending_browser,
              'checks': records, 'scope': scope, 'runtime_receipt': str(evidence / 'runtime-receipt.json')}
    if artifact:
        whitespace = []
        for relative in sorted(allowed & set(after)):
            text = _read_text(candidate, relative)
            for line_number, line in enumerate(text.splitlines(), 1):
                if line.endswith((' ', '\t')):
                    whitespace.append({'path': relative, 'line': line_number, 'reason': 'trailing-whitespace'})
            if not text.endswith('\n') or '\r' in text:
                whitespace.append({'path': relative, 'reason': 'expected-LF-final-newline'})
        result['diff_check'] = {'passed': not whitespace, 'kind': 'artifact-text-format', 'issues': whitespace}
        result['missing_required_changed_paths'] = missing
        non_browser_passed = non_browser_passed and not whitespace and bool(commands or packs)
        result['passed'] = non_browser_passed and not pending_browser
    result['pending_browser'] = pending_browser if non_browser_passed else []
    if result['pending_browser']:
        result['status'] = 'awaiting_browser_validation'
    with (evidence / 'validation.json').open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    return result


def run_validation_packs(packet, candidate, evidence_dir):
    return _execute(packet, candidate, evidence_dir, artifact=False)


def run_artifact_checks(packet, candidate, evidence_dir):
    """Check exact new artifacts without invoking Git or writing candidate files."""
    return _execute(packet, candidate, evidence_dir, artifact=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--builtin', type=Path, required=True)
    args = parser.parse_args()
    try:
        _require(args.builtin.is_file() and not args.builtin.is_symlink()
                 and args.builtin.stat().st_size <= 65536, 'Invalid builtin validation specification')
        spec = strict_json(args.builtin.read_text())
        result = _run_builtin(spec['pack'], Path(spec['candidate']))
    except Exception as exc:
        result = {'passed': False, 'executed': True, 'error': type(exc).__name__, 'reason': str(exc)[:1000]}
    print(json.dumps(result, ensure_ascii=False, allow_nan=False), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
