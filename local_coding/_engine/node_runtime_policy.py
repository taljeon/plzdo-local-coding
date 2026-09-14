"""Host-only, byte-pinned exact library reads for one approved Node runtime.

No process is launched here. Unknown runtimes receive no additional grants.
The manifest is immutable policy input, not a discovery or auto-refresh source.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat

DIRECTORY = Path(__file__).resolve().parent
MANIFEST_PATH = DIRECTORY / 'runtime-policies/node-24.10.0-darwin-arm64.json'
MANIFEST_SHA256 = '4547e2a3bf57cd985c652e372cbc5de77175196193be4d16c90bce02ed4e8fb6'
PINNED_NODE = Path('/opt/homebrew/Cellar/node/24.10.0/bin/node')
COMMAND_ALIASES = ('node', '/opt/homebrew/bin/node', str(PINNED_NODE))
OPT_ROOT = Path('/opt/homebrew/opt')
CELLAR_ROOT = Path('/opt/homebrew/Cellar')
CLEAN_CHECK_PATH = '/Library/Frameworks/Python.framework/Versions/3.12/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin'
MAX_RUNTIME_BYTES = 256 * 1024 * 1024


class NodeRuntimePolicyError(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise NodeRuntimePolicyError('Node runtime identity: ' + message)


def _unique(pairs):
    value = {}
    for key, item in pairs:
        _require(key not in value, 'duplicate manifest key')
        value[key] = item
    return value


def _read_manifest():
    _require(MANIFEST_PATH.resolve(strict=True) == MANIFEST_PATH and not MANIFEST_PATH.is_symlink(),
             'manifest path changed')
    descriptor = os.open(MANIFEST_PATH, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 65536,
                 'manifest must be a bounded regular file')
        data = source.read(65537)
    _require(len(data) <= 65536 and hashlib.sha256(data).hexdigest() == MANIFEST_SHA256,
             'approved manifest hash changed')
    manifest = json.loads(data, object_pairs_hook=_unique)
    _require(type(manifest) is dict and set(manifest) == {'schema', 'node', 'libraries', 'policy'},
             'manifest schema changed')
    _require(manifest['schema'] == 'hn-node-exact-library-reads.v1', 'unsupported manifest schema')
    node, libraries = manifest['node'], manifest['libraries']
    _require(type(node) is dict and set(node) == {'path', 'sha256', 'version', 'command_aliases'}
             and node['path'] == str(PINNED_NODE) and node['version'] == '24.10.0'
             and node['command_aliases'] == list(COMMAND_ALIASES), 'Node executable binding changed')
    _require(type(libraries) is list and len(libraries) == 16, 'exactly sixteen approved aliases are required')
    expected_policy = {'matching_node_only': True, 'exact_file_read_only': True,
                       'directory_read': False, 'network_change': False, 'write_change': False, 'auto_refresh': False}
    _require(type(manifest['policy']) is dict and set(manifest['policy']) == set(expected_policy)
             and all(type(manifest['policy'][key]) is bool and manifest['policy'][key] is value
                     for key, value in expected_policy.items()), 'permission policy changed')
    _require(type(node['sha256']) is str and re.fullmatch('[0-9a-f]{64}', node['sha256']), 'invalid Node hash')
    aliases = set()
    for library in libraries:
        _require(type(library) is dict and set(library) == {'alias', 'target', 'sha256'}, 'invalid alias binding')
        _require(all(type(library[key]) is str for key in library), 'alias fields must be strings')
        alias, target = Path(library['alias']), Path(library['target'])
        _require(alias.is_absolute() and target.is_absolute() and alias.is_relative_to(OPT_ROOT)
                 and target.is_relative_to(CELLAR_ROOT) and '..' not in alias.parts + target.parts
                 and alias.suffix == '.dylib' and target.suffix == '.dylib'
                 and not any(char in library['alias'] + library['target'] for char in '*?[]\0\n\r'),
                 'only exact approved library files may be granted')
        _require(library['alias'] not in aliases and re.fullmatch('[0-9a-f]{64}', library['sha256']),
                 'duplicate alias or invalid library hash')
        aliases.add(library['alias'])
    return manifest


def _verify_file(path, expected_hash):
    _require(path.is_absolute() and path.resolve(strict=True) == path and not path.is_symlink(), 'canonical target changed')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    digest = hashlib.sha256()
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        _require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_RUNTIME_BYTES,
                 'runtime target must be a bounded regular file')
        read_bytes = 0
        while chunk := source.read(1024 * 1024):
            read_bytes += len(chunk)
            _require(read_bytes <= before.st_size and read_bytes <= MAX_RUNTIME_BYTES, 'runtime target grew during verification')
            digest.update(chunk)
        after = os.fstat(source.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    _require(identity(before) == identity(after) and digest.hexdigest() == expected_hash, 'runtime target hash changed')


def prepare_node_command(argv, *, check_path=None):
    """Resolve approved Node commands using only the fixed check PATH."""
    original = argv[0]
    _require(original in COMMAND_ALIASES, 'unapproved Node command path')
    manifest = _read_manifest()
    resolved = shutil.which('node', path=CLEAN_CHECK_PATH if check_path is None else check_path) if original == 'node' else original
    _require(resolved is not None and resolved in COMMAND_ALIASES, 'Node was not found at an approved check-PATH alias')
    _require(Path(resolved).resolve(strict=True) == PINNED_NODE, 'Node alias target changed')
    _verify_file(PINNED_NODE, manifest['node']['sha256'])
    return [str(PINNED_NODE), *argv[1:]], str(PINNED_NODE)


def node_readonly_entries(runtime_executable):
    """Validate every binding before returning sixteen literal exact-file reads."""
    if runtime_executable is None or str(runtime_executable) not in COMMAND_ALIASES:
        return []
    try:
        command, _ = prepare_node_command([str(runtime_executable)])
        manifest = _read_manifest()
        for library in manifest['libraries']:
            alias, target = Path(library['alias']), Path(library['target'])
            _require(alias.resolve(strict=True) == target, 'library alias target changed')
            _verify_file(target, library['sha256'])
            _require(alias.resolve(strict=True) == target, 'library alias changed during verification')
        _require(command[0] == str(PINNED_NODE), 'unexpected executed Node path')
        # Deliberately retain aliases: resolving these policy paths would lose
        # the /opt alias reads that the loader actually needs.
        return [{'path': {'type': 'path', 'path': library['alias']}, 'access': 'read'}
                for library in manifest['libraries']]
    except (OSError, ValueError) as exc:
        if isinstance(exc, NodeRuntimePolicyError):
            raise
        raise NodeRuntimePolicyError('Node runtime identity: pinned runtime is unavailable') from exc
