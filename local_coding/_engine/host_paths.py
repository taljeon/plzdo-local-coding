"""Explicit host configuration; importing this module does not open private state.

Runtime policies are operator-owned, byte-pinned inputs. They can grant only
individual verified files, never a directory, glob, write, or network exception.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

SOURCE_DIRECTORY = Path(__file__).absolute().parent
MAX_RUNTIME_FILE_BYTES = 512 * 1024 * 1024
SENSITIVE_RUNTIME_PARTS = frozenset({
    '.aws', '.azure', '.ssh', '.gnupg', '.kube', '.docker', '.config', '.codex',
    '.claude', '.grok', '.gemini', '.git', 'credentials', 'keychains',
    'browser-profiles', 'profiles', 'user data', 'auth.json', 'credentials.json', '.netrc',
    '.npmrc', '.pypirc', '.git-credentials', '.gitconfig', '.boto', '.s3cfg',
    '.vault-token', '.yarnrc', '.yarnrc.yml', '.curlrc', '.wgetrc', 'token.json',
    'tokens.json', 'cookies', 'cookies.sqlite', 'logins.json', 'login data',
    'web data', 'local state', 'history', 'key4.db', 'cert9.db', 'preferences',
    'secure preferences', 'config.json', 'config.toml', 'config.yaml', 'config.yml',
    'settings.json',
})
PERMISSION_SOURCE_FILES = (
    'composition.py', 'kernel.py', 'contracts.py', 'scope_authority.py', 'parent_authority.py',
    'ledger.py', 'state_io.py', 'engine_types.py', 'json_codec.py', 'provider_common.py',
    'host_paths.py', 'workflow.py', 'workflow_core.py', 'workflow_validation.py',
    'workflow_artifacts.py', 'workflow_browser.py', 'workflow_preview.py',
    'workflow_metrics.py', 'run_bounded.py', 'node_runtime_policy.py', 'browser_check.cjs',
    'generate_edits.py', 'generate_stream.py', 'generation_health.py',
    'generation_profile.py', 'local_model.py', 'ollama_engine.py', 'workflow_routing.py',
    'runtime-policies/node-24.10.0-darwin-arm64.json',
)
PACKAGE_POLICY_SOURCE_FILES = (
    '__init__.py', '__main__.py', '_bootstrap.py', 'api.py', 'cli.py',
    'schemas/authority-common.schema.json', 'schemas/standalone-contract.schema.json',
    'schemas/scoped-task.schema.json', 'schemas/parent-delegation.schema.json',
    'schemas/parent-scoped-contract.schema.json', 'schemas/result.schema.json',
)
LAUNCHER_SOURCE_FILES = ('plzdo-local-code', 'plzdo_runtime_entry.py')


class HostPathError(ValueError):
    pass


def _require(value, message):
    if not value:
        raise HostPathError(message)


def state_root():
    """Derive a path only; validation/creation happen at an operation boundary."""
    raw = os.environ.get('LOCAL_CODING_STATE_ROOT',
                         str(Path.home() / 'Library/Application Support/LocalCoding'))
    _require(isinstance(raw, str) and raw == os.path.normpath(raw) and Path(raw).is_absolute(),
             'State root must be a canonical absolute path')
    return Path(raw)


def _canonical(path):
    raw = os.fspath(path)
    result = Path(raw)
    _require(result.is_absolute() and raw == os.path.normpath(raw)
             and not any(char in raw for char in ('\0', '\n', '\r', '*', '?', '[', ']')),
             'Path must be an exact canonical absolute path')
    _require(result.resolve() == result, 'Symlink or noncanonical path is forbidden')
    return result


def validate_state_root(path=None):
    root = _canonical(state_root() if path is None else path)
    source = SOURCE_DIRECTORY.resolve()
    if source.name == '_engine':
        source = source.parent
    _require(root != Path(root.anchor) and len(root.parts) >= 3,
             'State root must be a dedicated private directory')
    _require(not root.is_relative_to(source) and not source.is_relative_to(root),
             'State root must not overlap installed source')
    _require(root != Path.home(), 'Home itself cannot be the state root')
    if root.exists():
        info = root.lstat()
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                 and not (info.st_mode & 0o077), 'State root must be an owned private directory')
    return root


def ensure_state_root(path=None):
    """Create missing components without following links or replacing anything."""
    root = validate_state_root(path)
    descriptor = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in root.parts[1:]:
            try:
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        _require(info.st_uid == os.getuid() and not (info.st_mode & 0o077),
                 'State root must be an owned private directory')
    finally:
        os.close(descriptor)
    return validate_state_root(root)


def validate_model_slot_path(path):
    """Check an exact grant-pinned shared lock without creating state or files.

The engine opens each parent with O_NOFOLLOW as well. Sharing this lock shares
only an Ollama lease, never approval, evidence or reservation-ledger state.
"""
    target = _canonical(path)
    _require(target.name == '.local-model.lock', 'Shared model slot needs the exact lock filename')
    _require(target.parent.is_dir(), 'Shared model slot parent must already exist')
    parent = target.parent.lstat()
    _require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid()
             and not (parent.st_mode & 0o022), 'Shared model slot parent must be owned and non-writable by others')
    if target.exists():
        info = target.lstat()
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                 and info.st_nlink == 1 and not (info.st_mode & 0o022),
                 'Shared model slot must be an owned regular file')
    return target


def ollama_models_root():
    return Path(os.environ.get('LOCAL_CODING_OLLAMA_MODELS', str(Path.home() / '.ollama/models')))


def _reject_sensitive_runtime_path(path):
    """Lexical preflight precedes even path resolution or file identity reads."""
    _require(isinstance(path, (str, os.PathLike)), 'Invalid trusted runtime path')
    parts = tuple(part.casefold() for part in Path(path).parts)
    _require(not any(part in SENSITIVE_RUNTIME_PARTS or part.startswith('.env')
                     or part.startswith(('id_rsa', 'id_ed25519', 'id_ecdsa'))
                     or part.endswith(('.pem', '.key', '.p12', '.pfx', '.keychain-db'))
                     for part in parts), 'Sensitive credential/auth/config runtime path is forbidden')
    joined = '/'.join(parts)
    _require(not any(fragment in joined for fragment in (
        '/library/application support/google/chrome/',
        '/library/application support/microsoft edge/',
        '/library/application support/bravesoftware/brave-browser/',
        '/library/application support/chromium/',
        '/library/application support/firefox/', '/library/safari/',
        '/library/containers/com.apple.safari/',
    )), 'Sensitive browser state runtime path is forbidden')


def verify_trusted_file(path, sha256, *, executable=False):
    _reject_sensitive_runtime_path(path)
    target = _canonical(path)
    _require(isinstance(sha256, str) and re.fullmatch('[0-9a-f]{64}', sha256),
             'Trusted runtime file needs an exact SHA256')
    descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    digest = hashlib.sha256()
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_uid in {0, os.getuid()} and not (before.st_mode & 0o022)
                 and 0 <= before.st_size <= MAX_RUNTIME_FILE_BYTES,
                 'Trusted runtime must be an owned bounded regular file')
        _require(not executable or (before.st_size > 0 and before.st_mode & 0o111),
                 'Trusted executable is empty or not executable')
        size = 0
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            _require(size <= before.st_size, 'Trusted runtime changed during verification')
            digest.update(chunk)
        after = os.fstat(source.fileno())
        current = target.lstat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    _require(identity(before) == identity(after) == identity(current)
             and digest.hexdigest() == sha256, 'Trusted runtime file identity or hash changed')
    return target


def _unique(items):
    result = {}
    for key, value in items:
        _require(key not in result, 'Duplicate runtime policy key')
        result[key] = value
    return result


def runtime_policy():
    """No policy means no additional reads; it never means automatic discovery."""
    raw = os.environ.get('LOCAL_CODING_RUNTIME_POLICY')
    digest = os.environ.get('LOCAL_CODING_RUNTIME_POLICY_SHA256')
    if raw is None and digest is None:
        return {'schema': 'local-coding-runtime.v1', 'executables': [], 'read_files': []}
    _require(raw is not None and digest is not None, 'Runtime policy requires a path and SHA256')
    target = verify_trusted_file(raw, digest)
    _require(target.stat().st_size <= 1024 * 1024, 'Runtime policy exceeds byte limit')
    encoded = target.read_bytes()
    _require(hashlib.sha256(encoded).hexdigest() == digest, 'Runtime policy changed while reading')
    value = json.loads(encoded, object_pairs_hook=_unique)
    _require(type(value) is dict and set(value) == {'schema', 'executables', 'read_files'}
             and value['schema'] == 'local-coding-runtime.v1', 'Invalid runtime policy schema')
    _require(type(value['executables']) is list and len(value['executables']) <= 16
             and type(value['read_files']) is list and len(value['read_files']) <= 8192,
             'Runtime policy exceeds entry bounds')
    commands, paths, files = set(), set(), []
    for executable, entries in ((True, value['executables']), (False, value['read_files'])):
        for item in entries:
            fields = {'command', 'path', 'sha256'} if executable else {'path', 'sha256'}
            _require(type(item) is dict and set(item) == fields
                     and all(isinstance(item[key], str) for key in fields), 'Invalid runtime policy file binding')
            if executable:
                command = item['command']
                _require(isinstance(command, str) and re.fullmatch('[A-Za-z0-9_.+-]{1,80}', command)
                         and command not in commands, 'Invalid or duplicate runtime command')
                commands.add(command)
            _reject_sensitive_runtime_path(item['path'])
            path = Path(item['path'])
            source_root = SOURCE_DIRECTORY.parent if SOURCE_DIRECTORY.name == '_engine' else SOURCE_DIRECTORY
            _require(not path.is_relative_to(state_root()) and not path.is_relative_to(source_root),
                     'Runtime files must not expose private state or installed source')
            files.append((item, executable and item.get('command') != 'playwright'))
    # Reject every forbidden entry before opening or hashing any runtime file.
    for item, executable in files:
        target = verify_trusted_file(item['path'], item['sha256'], executable=executable)
        _require(str(target) not in paths, 'Duplicate runtime file path')
        paths.add(str(target))
    return value


def runtime_policy_fingerprint():
    """Bind approvals to the exact verified policy bytes, including its absence."""
    names = ('LOCAL_CODING_RUNTIME_POLICY', 'LOCAL_CODING_RUNTIME_POLICY_SHA256')
    configured = tuple(os.environ.get(name) for name in names)
    runtime_policy()
    _require(configured == tuple(os.environ.get(name) for name in names),
             'Runtime policy configuration changed during validation')
    return configured[1]


def _launcher_directory():
    """Exact source, --target, prefix, or user-prefix script location; no PATH scan."""
    parent = SOURCE_DIRECTORY.parent.parent
    candidates = [parent / 'bin']
    if (parent.name == 'site-packages' and re.fullmatch(r'python(?:3(?:\.\d+)?)?', parent.parent.name)
            and parent.parent.parent.name in {'lib', 'lib64'}):
        candidates.append(parent.parent.parent.parent / 'bin')
    found = [path for path in candidates if all((path / name).is_file() for name in LAUNCHER_SOURCE_FILES)]
    _require(len(found) == 1 and found[0].resolve(strict=True) == found[0],
             'Exactly one fixed runtime launcher directory is required')
    return found[0]


def permission_policy_fingerprint():
    """Fingerprint the closed source set that defines execution/check grants."""
    closure = {}
    files = [(name, SOURCE_DIRECTORY / name) for name in PERMISSION_SOURCE_FILES]
    files += [('package/' + name, SOURCE_DIRECTORY.parent / name) for name in PACKAGE_POLICY_SOURCE_FILES]
    launcher = _launcher_directory()
    files += [('launcher/' + name, launcher / name) for name in LAUNCHER_SOURCE_FILES]
    for name, path in files:
        _require(path.resolve(strict=True) == path, 'Permission policy source path changed')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as source:
            before = os.fstat(source.fileno())
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                     and 0 < before.st_size <= 1024 * 1024, 'Invalid permission policy source')
            data = source.read(1024 * 1024 + 1)
            after = os.fstat(source.fileno())
            current = path.lstat()
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        _require(len(data) == before.st_size and identity(before) == identity(after) == identity(current),
                 'Permission policy source changed during fingerprinting')
        closure[name] = hashlib.sha256(data).hexdigest()
    encoded = json.dumps(closure, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def runtime_command(command):
    return runtime_commands((command,))[0]


def runtime_commands(commands):
    bindings = {item['command']: Path(item['path']) for item in runtime_policy()['executables']}
    return tuple(bindings.get(command) for command in commands)


def runtime_read_entries(*, forbidden_roots=()):
    value = runtime_policy()
    entries = []
    for item in value['executables'] + value['read_files']:
        path = Path(item['path'])
        _require(not any(path.is_relative_to(Path(root).resolve()) for root in forbidden_roots),
                 'Trusted runtime files must be outside candidate and scratch')
        entries.append({'path': {'type': 'path', 'path': str(path)}, 'access': 'read'})
    return entries


def clean_check_path():
    # PATH resolution grants no directory reads. Non-system runtimes still need
    # pinned file permissions; candidate paths and the invoking PATH are absent.
    return '/usr/bin:/bin:/usr/sbin:/sbin'
