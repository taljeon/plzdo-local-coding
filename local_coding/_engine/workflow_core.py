"""Small, explicit task packets and isolated candidate verification.

Capability: existing UTF-8/LF files only, at most eight editable files. No file
creation/deletion, symlinks, submodules, dependency installation or real apply.
Commits containing credential-like paths, including .env.example, are rejected
before checkout; a separately sanitized commit is required for those projects.
Only .py edits receive an AST check; other languages rely on supplied checks.
Candidate tests run read-only, offline and with a clean environment. Projects
whose checks require in-tree build writes need a separately reviewed extension.
"""
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time

from run_bounded import run
from provider_common import ContractError, require
from host_paths import (SOURCE_DIRECTORY, state_root, validate_state_root, ensure_state_root,
                        runtime_command, runtime_read_entries, clean_check_path)

DIRECTORY = state_root()
MAX_FILE_BYTES = 128 * 1024
MAX_BUNDLE_BYTES = 512 * 1024
MAX_TREE_BYTES = 100 * 1024 * 1024
TASK_CATEGORIES = frozenset({'product-development', 'coding-test', 'unresolved'})
FORBIDDEN_PARTS = {'.git', '.env', '.ssh', '.aws', '.azure', '.gnupg', '.codex',
                   '.claude', '.grok', 'credentials', 'keychains', 'browser-profiles'}
SECRET_PATTERNS = (
    re.compile(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----'),
    re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{24,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,})\b'),
    re.compile(r'''(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*["'][^"'\n]{12,}["']'''),
)


class ProposalError(ContractError):
    """Known structured output validation failure, after closed generation."""


def proposal_require(condition, message):
    if not condition:
        raise ProposalError(message)


class CheckExecutionError(ContractError):
    """The checker did not execute reliably; this never permits provider fallback."""


def safe_path(value):
    require(isinstance(value, str) and value and len(value) <= 240, 'Invalid relative path')
    parts = value.split('/')
    require(not PurePosixPath(value).is_absolute() and value == value.strip()
            and not any(p in {'', '.', '..'} for p in parts)
            and not any(c in value for c in ('\\', ':', '\0'))
            and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'Unsafe relative path')
    require(not any(p.lower() in FORBIDDEN_PARTS or p.lower().startswith('.env')
                    or p.lower().endswith(('.pem', '.key', '.p12', '.pfx', '.keychain-db'))
                    or p.lower() in {'id_rsa', 'id_ed25519', 'auth.json', 'credentials.json'}
                    for p in parts), 'Sensitive/authentication path is forbidden')
    return value


def reject_secrets(text):
    require(isinstance(text, str), 'Text must be a string')
    require(not any(pattern.search(text) for pattern in SECRET_PATTERNS),
            'Possible secret detected; manually sanitize the selected input')


def _git(repository, *args):
    # Packet validation precedes the provider sandbox. Never inherit caller Git
    # overrides, replacements, grafts, credential helpers or lazy remote fetch.
    # Candidate cloning alone uses the explicit local file transport; no other
    # operation may implicitly fetch even from a configured local promisor.
    env = {'PATH': os.defpath, 'LANG': 'C', 'LC_ALL': 'C',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
           'GIT_GRAFT_FILE': '/dev/null', 'GIT_NO_LAZY_FETCH': '1',
           'GIT_ATTR_NOSYSTEM': '1',
           'GIT_ALLOW_PROTOCOL': 'file' if args and args[0] == 'clone' else ''}
    transport = ['-c', 'protocol.file.allow=always'] if args and args[0] == 'clone' else []
    result = subprocess.run(['git', '--no-replace-objects', '-c', 'protocol.allow=never',
                             '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                             '-c', 'core.pager=cat', '-c', 'log.showSignature=false',
                             *transport, *args], cwd=repository, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    require(result.returncode == 0, 'Git operation failed: ' + result.stderr.decode(errors='replace')[:600])
    return result.stdout


def _regular_file(root, relative):
    safe_path(relative)
    target = root
    for part in PurePosixPath(relative).parts:
        target = target / part
        require(not target.is_symlink(), 'Symlink paths are unsupported')
    require(target.is_file() and stat.S_ISREG(target.stat().st_mode), 'Existing regular file required')
    require(target.stat().st_size <= MAX_FILE_BYTES, 'Selected file exceeds byte limit')
    return target


def validate_task_profile(value):
    from generation_profile import HUIHUI_PROFILE_ID, resolve_profile
    try:
        profile = resolve_profile(value)
    except ValueError as exc:
        raise ContractError('Invalid or changed generation profile') from exc
    require(profile['id'] == HUIHUI_PROFILE_ID, 'Explicit pinned Hui generation profile required')
    return profile


def validate_packet(packet):
    require(isinstance(packet, dict), 'Packet must be an object')
    required = {'id', 'repository', 'base_revision', 'objective', 'allowed_paths', 'checks', 'authorityId', 'generation_profile'}
    optional = {'context_files', 'required_changed_paths', 'regression_checks',
                'risk', 'local_attempts', 'timeout_seconds', 'kind', 'design', 'validation_packs',
                'task_category'}
    require(required <= set(packet) and not set(packet) - required - optional, 'Missing/unknown packet fields')
    result = {**{'context_files': [], 'required_changed_paths': [], 'regression_checks': [],
                 'risk': 'normal', 'local_attempts': 2,
                 'timeout_seconds': 180}, **packet}
    # Category is explicit; a filesystem path is never an intent classifier.
    if 'task_category' in result:
        require(isinstance(result['task_category'], str)
                and result['task_category'] in TASK_CATEGORIES, 'Invalid task_category')
    require(result.get('kind', 'repo-edit') == 'repo-edit', 'Expected repo-edit kind')
    result['generation_profile'] = validate_task_profile(result['generation_profile'])
    if 'design' in result:
        require(isinstance(result['design'], str) and len(result['design']) <= 16000, 'Invalid design contract')
        reject_secrets(result['design'])
    if 'validation_packs' in result:
        require(isinstance(result['validation_packs'], list) and len(result['validation_packs']) <= 8, 'Invalid validation packs')
    require(isinstance(result['id'], str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}', result['id']), 'Invalid task id')
    require(isinstance(result['authorityId'], str)
            and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,119}', result['authorityId']), 'Invalid authority id')
    require(isinstance(result['repository'], str), 'Repository must be an absolute path')
    repository = Path(result['repository'])
    require(repository.is_absolute() and repository.is_dir()
            and str(repository.resolve()) == str(repository), 'Repository must be a canonical directory')
    require(_git(repository, 'rev-parse', '--show-toplevel').decode().strip() == str(repository), 'Repository must be its Git root')
    revision = result['base_revision']
    require(isinstance(revision, str) and re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', revision), 'Exact full Git commit required')
    require(_git(repository, 'rev-parse', '--verify', revision + '^{commit}').decode().strip() == revision, 'Commit unavailable')
    require(isinstance(result['objective'], str) and 1 <= len(result['objective']) <= 16000, 'Objective length invalid')
    reject_secrets(result['objective'])
    for key, maximum, minimum in (('allowed_paths', 8, 1), ('context_files', 8, 0)):
        values = result[key]
        require(isinstance(values, list) and minimum <= len(values) <= maximum, 'Invalid ' + key)
        for value in values:
            safe_path(value)
        require(len(set(values)) == len(values), 'Duplicate paths')
        result[key] = list(values)
    require(not set(result['allowed_paths']) & set(result['context_files']), 'Context files must be read-only')
    mandatory = result['required_changed_paths']
    require(isinstance(mandatory, list) and len(mandatory) <= 8, 'Invalid required_changed_paths')
    for value in mandatory:
        safe_path(value)
    require(len(set(mandatory)) == len(mandatory) and set(mandatory) <= set(result['allowed_paths']),
            'Required changed paths must be a unique subset of allowed_paths')
    result['required_changed_paths'] = list(mandatory)
    require(result['risk'] in ('normal', 'high'), 'Invalid risk')
    for key, lower, upper in (('local_attempts', 1, 2), ('timeout_seconds', 10, 1800)):
        require(type(result[key]) is int and lower <= result[key] <= upper, 'Invalid ' + key)
    for key, minimum in (('checks', 1), ('regression_checks', 0)):
        checks = result[key]
        require(isinstance(checks, list) and minimum <= len(checks) <= 8, 'Invalid ' + key + ' argv arrays')
        for argv in checks:
            require(isinstance(argv, list) and 1 <= len(argv) <= 40, 'Checks must be argv arrays, not shell strings')
            require(all(isinstance(arg, str) and arg and len(arg) <= 4096
                        and not any(c in arg for c in ('\0', '\n', '\r')) for arg in argv), 'Invalid check argument')
            require(Path(argv[0]).name not in {'sh', 'bash', 'zsh', 'fish', 'dash', 'env', 'sudo', 'osascript'}, 'Shell/wrapper checks unsupported')
        result[key] = [list(args) for args in checks]
    selected_bytes = 0
    for relative in result['allowed_paths'] + result['context_files']:
        entry = _git(repository, 'ls-tree', '-z', revision, '--', relative).split(b'\t')[0]
        require(entry.startswith((b'100644 blob ', b'100755 blob ')), 'Selected path must be an existing committed file')
        size = int(_git(repository, 'cat-file', '-s', revision + ':' + relative))
        require(size <= MAX_FILE_BYTES, 'Selected file exceeds byte limit')
        selected_bytes += size
    require(selected_bytes <= MAX_BUNDLE_BYTES, 'Selected bundle exceeds byte limit')
    return result


def create_candidate(packet, stage_dir):
    """Clone without shared objects or source config; never writes original refs."""
    try:
        validate_state_root(DIRECTORY)
    except ValueError as exc:
        raise ContractError(str(exc)) from exc
    stage = Path(stage_dir)
    require(stage.is_absolute() and stage.resolve() == stage
            and stage.is_relative_to(DIRECTORY) and stage != DIRECTORY,
            'Stage must be a new canonical directory under the configured state root')
    require(not stage.exists(), 'Stage already exists; use a fresh attempt directory')
    repository = Path(packet['repository'])
    # Fail before checkout if a tree could expose secrets/symlinks to test code.
    entries = _git(repository, 'ls-tree', '-r', '-z', packet['base_revision']).split(b'\0')
    for entry in filter(None, entries):
        metadata, path = entry.split(b'\t', 1)
        require(metadata.startswith((b'100644 blob ', b'100755 blob ')), 'Symlinks/submodules unsupported')
        safe_path(path.decode('utf-8'))
    ensure_state_root(DIRECTORY)
    stage.parent.mkdir(parents=True, exist_ok=True)
    _git(DIRECTORY, 'clone', '--no-local', '--no-hardlinks', '--no-checkout', '--template=', '--', str(repository), str(stage))
    _git(stage, 'checkout', '--detach', packet['base_revision'])
    require(_git(stage, 'rev-parse', 'HEAD').decode().strip() == packet['base_revision'], 'Candidate revision mismatch')
    require(not _git(stage, 'status', '--porcelain'), 'Candidate not clean')
    snapshot(stage)
    return stage


def build_bundle(packet, candidate):
    files, context, total = {}, {}, 0
    for key, destination in (('allowed_paths', files), ('context_files', context)):
        for relative in packet[key]:
            data = _regular_file(Path(candidate), relative).read_bytes()
            total += len(data)
            require(total <= MAX_BUNDLE_BYTES, 'Bundle exceeds byte limit')
            try:
                text = data.decode('utf-8')
            except UnicodeError as exc:
                raise ContractError('Selected files must be UTF-8 text') from exc
            require('\0' not in text, 'Binary files unsupported')
            reject_secrets(text)
            destination[relative] = text
    bundle = {'id': packet['id'], 'objective': packet['objective'],
            'allowed_paths': packet['allowed_paths'], 'checks': packet['checks'],
            'regression_checks': packet.get('regression_checks', []),
            'required_changed_paths': packet.get('required_changed_paths', []),
            'files': files, 'read_only_context': context,
            'capability': 'existing-file exact-anchor edits only; no added/deleted paths'}
    for key in ('design', 'validation_packs', 'generation_profile', 'task_category'):
        if key in packet:
            bundle[key] = packet[key]
    reject_secrets(json.dumps(bundle, ensure_ascii=False))
    return bundle


def validate_edits(originals, payload):
    proposal_require(isinstance(payload, dict) and set(payload) == {'edits'}, 'Payload must contain only edits')
    edits = payload['edits']
    proposal_require(isinstance(edits, list) and 1 <= len(edits) <= 8, 'One to eight edits required')
    changed, patch = {}, []
    for edit in edits:
        proposal_require(isinstance(edit, dict) and set(edit) == {'path', 'old_text', 'new_text'}, 'Invalid edit keys')
        relative = safe_path(edit['path'])
        require(relative in originals and relative not in changed, 'Unallowed or duplicate edited file')
        old, new, original = edit['old_text'], edit['new_text'], originals[relative]
        proposal_require(isinstance(old, str) and isinstance(new, str) and old and old != new, 'Nonempty non-noop anchor required')
        proposal_require(len(old.encode()) <= MAX_FILE_BYTES and len(new.encode()) <= MAX_FILE_BYTES, 'Edit too large')
        start = original.find(old)
        proposal_require(start >= 0 and original.find(old, start + 1) < 0, 'Anchor must occur exactly once')
        updated = original[:start] + new + original[start + len(old):]
        proposal_require(len(updated.encode()) <= MAX_FILE_BYTES and '\0' not in updated
                and '\r' not in original + updated and original.endswith('\n') and updated.endswith('\n'),
                'Edits must preserve bounded UTF-8 LF text and final newline')
        reject_secrets(updated)
        if relative.endswith('.py'):
            try:
                ast.parse(updated, filename=relative)
            except (SyntaxError, ValueError) as exc:
                raise ProposalError('Invalid Python syntax: ' + relative) from exc
        changed[relative] = updated
        patch.extend(difflib.unified_diff(original.splitlines(keepends=True), updated.splitlines(keepends=True),
                                        fromfile='a/' + relative, tofile='b/' + relative))
    return changed, ''.join(patch)


def validate_and_apply(packet, candidate, payload):
    """Apply validated bytes, never execute model commands or generated scripts."""
    candidate = Path(candidate)
    require(candidate.resolve() != Path(packet['repository']).resolve(), 'Cannot apply edits to original repository')
    bundle = build_bundle(packet, candidate)
    changed, patch = validate_edits(bundle['files'], payload)
    # Validate the complete proposal before any write and recheck file identity.
    for relative in changed:
        require(_regular_file(candidate, relative).read_text() == bundle['files'][relative], 'Candidate changed during validation')
    for relative, content in changed.items():
        target = _regular_file(candidate, relative)
        descriptor = os.open(target, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='') as output:
            output.write(content)
    return {'changed_paths': sorted(changed), 'patch': patch}


def snapshot(candidate):
    root, result, total = Path(candidate), {}, 0
    require(root.is_dir() and root.resolve() == root, 'Candidate root must be canonical')
    for directory, directories, files in os.walk(root, followlinks=False):
        if Path(directory) == root and '.git' in directories:
            directories.remove('.git')
        for name in sorted(directories + files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            safe_path(relative)
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode), 'Candidate contains symlink')
            if stat.S_ISDIR(info.st_mode):
                continue
            require(stat.S_ISREG(info.st_mode), 'Candidate contains special file')
            total += info.st_size
            require(total <= MAX_TREE_BYTES, 'Candidate exceeds snapshot budget')
            result[relative] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'mode': stat.S_IMODE(info.st_mode)}
    return result


def inspect_scope(candidate, before, allowed_paths):
    after = snapshot(candidate)
    changed = sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
    violations = [path for path in changed if path not in allowed_paths or path not in before or path not in after
                  or before[path]['mode'] != after[path]['mode']]
    return {'passed': not violations, 'changed_paths': changed, 'violations': violations}


def prepare_check_command(argv):
    """Host-only Node admission; ordinary/staged Python checks need no helper."""
    try:
        configured = runtime_command(Path(argv[0]).name)
    except (OSError, ValueError) as exc:
        raise ContractError('Runtime identity: check command was not admitted') from exc
    if configured is not None:
        require(argv[0] in (configured.name, str(configured), Path(argv[0]).name)
                and (not Path(argv[0]).is_absolute() or Path(argv[0]) == configured),
                'Runtime command path differs from its explicit binding')
        return [str(configured), *argv[1:]], str(configured)
    if Path(argv[0]).name not in ('node', 'nodejs'):
        return list(argv), None
    from node_runtime_policy import prepare_node_command
    try:
        return prepare_node_command(argv)
    except (OSError, ValueError) as exc:
        raise ContractError('Node runtime identity: check command was not admitted') from exc


def build_permission_state(candidate, allowed_paths, scratch, readonly=True, *, runtime_executable=None):
    candidate, scratch = Path(candidate).resolve(strict=True), Path(scratch).resolve(strict=True)
    require(not scratch.is_relative_to(candidate) and scratch != candidate, 'Scratch must be outside candidate')
    entries = [
        {'path': {'type': 'special', 'value': {'kind': 'root'}}, 'access': 'deny'},
        {'path': {'type': 'special', 'value': {'kind': 'minimal'}}, 'access': 'read'},
    ]
    for pattern in ('/tmp/**', '/private/tmp/**', '/var/tmp/**', '/private/var/tmp/**', '/var/folders/**', '/private/var/folders/**'):
        entries.append({'path': {'type': 'glob_pattern', 'pattern': pattern}, 'access': 'deny'})
    entries.append({'path': {'type': 'path', 'path': str(candidate)}, 'access': 'read'})
    entries.append({'path': {'type': 'path', 'path': str(candidate / '.git')}, 'access': 'deny'})
    entries.append({'path': {'type': 'path', 'path': str(scratch)}, 'access': 'write'})
    if not readonly:
        for relative in allowed_paths:
            entries.append({'path': {'type': 'path', 'path': str(_regular_file(candidate, relative))}, 'access': 'write'})
    if runtime_executable is not None:
        from node_runtime_policy import node_readonly_entries
        try:
            entries.extend(node_readonly_entries(runtime_executable))
        except (OSError, ValueError) as exc:
            raise ContractError('Node runtime identity: library reads were not admitted') from exc
    try:
        entries.extend(runtime_read_entries(forbidden_roots=(candidate, scratch, DIRECTORY, SOURCE_DIRECTORY)))
    except (OSError, ValueError) as exc:
        raise ContractError('Runtime identity: exact file reads were not admitted') from exc
    return {'permissionProfile': {'type': 'managed', 'file_system': {'type': 'restricted', 'entries': entries},
                                  'network': 'restricted'}, 'sandboxCwd': candidate.as_uri()}


def _read_check_evidence(directory, name, limit):
    """Read only the host-captured receipt files, never candidate-selected paths."""
    root = Path(directory)
    require(root.is_absolute() and root.resolve() == root, 'Unsafe check evidence directory')
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                    and before.st_nlink == 1 and not before.st_mode & 0o022
                    and 0 <= before.st_size <= limit, 'Unsafe or oversized check evidence file')
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(len(data) == before.st_size and identity(before) == identity(after) == identity(current),
                'Check evidence changed during inspection')
        return data
    finally:
        os.close(directory_fd)


_CHECK_DENIAL_LINES = (
    # Conservative, anchored exception/launcher diagnostics. Ordinary prose on
    # stdout is deliberately ignored; stderr text is observation, not attestation.
    re.compile(r'^(?:PermissionError|OSError): \[Errno (?:1|13)\] (?:Operation not permitted|Permission denied)(?:: .*)?$'),
    re.compile(r'^sandbox-exec: (?:sandbox_apply|execvp\(\) of [^\r\n]+): (?:Operation not permitted|Permission denied)$'),
    re.compile(r'^(?:Error|error): (?:[^\r\n]+: )?(?:Operation not permitted \(os error 1\)|Permission denied \(os error 13\))$'),
    re.compile(r'^(?:bwrap|bubblewrap): [^\r\n]+: (?:Operation not permitted|Permission denied)$'),
)

_CHECK_BOOTSTRAP_LINES = (
    re.compile(r'^Fatal Python error: (?:init_fs_encoding|init_import_site|init_sys_streams): [^\r\n]+$'),
)


def check_execution_receipt(summary, evidence_dir):
    """Keep process faults separate from a completed check's ordinary exit 1.

The process summary is emitted by run_bounded, not by generated code. A bounded
stderr denial observation can only tighten admission. It never grants authority
or asserts that arbitrary output is a trusted sandbox attestation.
"""
    fields = ('return_code', 'child_exit_code', 'timed_out', 'supervisor_stop', 'stop_reason', 'error')
    process = {key: summary.get(key) for key in fields}
    diagnostics = []
    complete = (all(key in summary for key in fields)
                and type(process['return_code']) is int
                and (process['child_exit_code'] is None or type(process['child_exit_code']) is int)
                and type(process['timed_out']) is bool and type(process['supervisor_stop']) is bool
                and isinstance(process['stop_reason'], str) and len(process['stop_reason']) <= 100
                and (process['error'] is None or isinstance(process['error'], str)))
    if not complete:
        diagnostics.append('CHECK_PROCESS_RECEIPT_INCOMPLETE')
    if process['error'] is not None or process['stop_reason'] == 'execution-error':
        diagnostics.append('CHECK_EXECUTION_ERROR')
    if process['timed_out'] is True or process['stop_reason'] == 'timeout':
        diagnostics.append('CHECK_TIMEOUT')
    if process['supervisor_stop'] is True:
        diagnostics.append('CHECK_SUPERVISOR_STOP')
    if complete and (process['stop_reason'] != 'process-exited' or process['child_exit_code'] is None):
        diagnostics.append('CHECK_DID_NOT_COMPLETE_NORMALLY')
    from engine_types import EngineFailure, require_cleanup
    try:
        require_cleanup(summary.get('cleanup'))
    except (EngineFailure, ValueError, TypeError):
        diagnostics.append('CHECK_PROCESS_CLEANUP_UNPROVEN')
    hashes = {}
    try:
        from json_codec import strict_json
        captured_summary = _read_check_evidence(evidence_dir, 'summary.json', 256 * 1024)
        require(strict_json(captured_summary) == summary, 'Check process summary evidence mismatch')
        captured_stderr = _read_check_evidence(evidence_dir, 'stderr.log', 1024 * 1024)
        hashes = {'summary_sha256': hashlib.sha256(captured_summary).hexdigest(),
                  'stderr_sha256': hashlib.sha256(captured_stderr).hexdigest()}
        if process['return_code'] != 0:
            lines = captured_stderr.decode('utf-8', 'replace').splitlines()
            if any(pattern.fullmatch(line) for line in lines for pattern in _CHECK_DENIAL_LINES):
                diagnostics.append('CHECK_PERMISSION_OR_SANDBOX_DENIAL')
            if any(pattern.fullmatch(line) for line in lines for pattern in _CHECK_BOOTSTRAP_LINES):
                diagnostics.append('CHECK_INTERPRETER_BOOTSTRAP_FAILED')
    except (OSError, ValueError) as exc:
        diagnostics.append('CHECK_EXECUTION_EVIDENCE_UNAVAILABLE')
        hashes['evidence_error_type'] = type(exc).__name__
    return {'schema': 'check-execution-receipt.v1', 'passed': not diagnostics,
            'process': process, 'diagnostic_codes': sorted(set(diagnostics)), **hashes,
            'basis': 'host process summary and bounded stderr observations; child text is not attestation'}


def run_checks(packet, candidate, evidence_dir):
    """Execute operator-specified checks under an offline read-only sandbox."""
    candidate, evidence = Path(candidate), Path(evidence_dir)
    evidence.mkdir(parents=True, exist_ok=False)
    scratch = evidence / 'scratch'
    scratch.mkdir()
    before, records, frozen = snapshot(candidate), [], None
    environment = ['/usr/bin/env', '-i', 'PATH=' + clean_check_path(),
                   'TMPDIR=' + str(scratch), 'TMP=' + str(scratch), 'TEMP=' + str(scratch),
                   'PYTHONDONTWRITEBYTECODE=1', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD=1',
                   'GIT_CONFIG_NOSYSTEM=1', 'GIT_CONFIG_GLOBAL=/dev/null', 'CARGO_TARGET_DIR=' + str(scratch / 'cargo')]
    checks = packet['checks'] + packet.get('regression_checks', [])
    deadline = time.monotonic() + packet['timeout_seconds']
    for index, argv in enumerate(checks):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        executed, runtime_executable = prepare_check_command(argv)
        python_environment = []
        if runtime_executable is not None and re.fullmatch(r'python(?:3(?:\.\d+)?)?', Path(runtime_executable).name):
            # Reuse the existing exact-file frozen prefix. Never grant the source
            # interpreter directory just to make FileFinder startup work.
            from workflow_validation import (_python_runtime_plan, _stage_runtime, _staged_python,
                                             _state, _verify_runtime)
            try:
                plan = _python_runtime_plan()
                require(plan is not None and str(plan['executable']) == executed[0],
                        'Python check executable differs from its selected explicit runtime policy')
                if frozen is None:
                    runtime, receipt = _stage_runtime(evidence, python=True)
                    staged = _staged_python(runtime, receipt)
                    require(staged is not None, 'Frozen Python check runtime is missing')
                    frozen = (runtime, receipt, staged)
                runtime, receipt, (executable, prefix, packages) = frozen
                spec = evidence / ('command-' + str(index + 1) + '.json')
                with spec.open('x', encoding='utf-8') as out:
                    json.dump({'kind': 'operator-python-check', 'argv': argv}, out)
                executed = [str(executable), '-S', *executed[1:]]
                python_environment = ['PYTHONHOME=' + str(prefix), 'PYTHONPATH=' + str(packages),
                                      'PYTHONNOUSERSITE=1']
                state = _state(candidate, packet['allowed_paths'], scratch, spec, runtime,
                               runtime_executable=str(executable), frozen_python=True)
                _verify_runtime(runtime, receipt)
            except (OSError, ValueError) as exc:
                raise CheckExecutionError('Frozen Python check runtime preparation failed') from exc
        else:
            state = build_permission_state(candidate, packet['allowed_paths'], scratch, readonly=True,
                                           runtime_executable=runtime_executable)
        command = ['codex', 'sandbox', '--sandbox-state-json', json.dumps(state), '--',
                   *environment, *python_environment, *executed]
        process_evidence = evidence / ('check-' + str(index + 1))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CheckExecutionError('Check preparation exceeded its execution deadline')
        try:
            summary = run(command, candidate, process_evidence, remaining, pipe_output=True)
        finally:
            if frozen is not None:
                try:
                    _verify_runtime(frozen[0], frozen[1])
                except (OSError, ValueError) as exc:
                    raise CheckExecutionError('Frozen Python check runtime changed during execution') from exc
        records.append({'argv': executed, 'return_code': summary['return_code'], 'duration_seconds': summary['duration_seconds'],
                        'evidence_dir': str(process_evidence),
                        'execution_receipt': check_execution_receipt(summary, process_evidence)})
        if summary['return_code'] != 0 or not records[-1]['execution_receipt']['passed']:
            break
    scope = inspect_scope(candidate, before, [])
    actual_changed = _git(candidate, 'diff', '--name-only', '-z', packet['base_revision']).decode().split('\0')
    missing = sorted(set(packet.get('required_changed_paths', [])) - set(actual_changed))
    try:
        _git(candidate, 'diff', '--check', packet['base_revision'])
        diff_check = {'passed': True}
    except ContractError as exc:
        diff_check = {'passed': False, 'error': str(exc)}
    return {'passed': len(records) == len(checks) and all(row['return_code'] == 0
                      and row['execution_receipt']['passed'] for row in records)
                      and scope['passed'] and not missing and diff_check['passed'],
            'checks': records, 'scope': scope, 'diff_check': diff_check, 'missing_required_changed_paths': missing}
