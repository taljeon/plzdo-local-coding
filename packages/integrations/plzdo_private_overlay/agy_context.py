"""Fixed native AGY ambient-input audit; no credential reads or config writes.

The operator admits one exact generic GEMINI.md, or its absence. Other
customizations must be absent/empty. This is input evidence, not an OS sandbox.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import pwd
import re
import stat

from local_coding.api import canonical_bytes, strict_json

from .transports import ProviderError, _bounded_read


CONTEXT_POLICY = 'plzdo.agy-native-context.v1'
GLOBAL_ROOTS = ('.gemini', '.gemini/config', '.gemini/antigravity-cli', '.gemini/antigravity')
EMPTY_DIRECTORIES = ('hooks', 'skills', 'agents', 'plugins', 'rules', 'workflows',
                     'commands', 'extensions')
EMPTY_FILES = ('GEMINI.md', 'AGENTS.md', '.env', 'keybindings.json', 'trustedFolders.json')
EMPTY_JSON = {'mcp_config.json': 'mcpServers', 'hooks.json': 'hooks', 'plugins.json': 'plugins'}
WORKSPACE_NAMES = ('GEMINI.md', 'AGENTS.md', '.env', '.agents', '.agent', '.gemini', '.git')


def account_home():
    """Use the OS account, never a caller-selected profile or alternate HOME."""
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    if (not home.is_absolute() or home.resolve(strict=True) != home
            or os.environ.get('HOME') != str(home)):
        raise ProviderError('AGY requires the unchanged current-user home')
    _safe_directory(home)
    return home


def reject_environment_overrides():
    prefixes = ('AGY_', 'ANTIGRAVITY_', 'JETSKI_', 'GEMINI_', 'GOOGLE_', 'GCLOUD_', 'CLOUDSDK_',
                'DYLD_', 'LD_')
    names = {'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy',
             'SSL_CERT_FILE', 'SSL_CERT_DIR', 'NODE_EXTRA_CA_CERTS', 'GRPC_DEFAULT_SSL_ROOTS_FILE_PATH'}
    if any(value and (name.startswith(prefixes) or name in names) for name, value in os.environ.items()):
        raise ProviderError('AGY provider, account, endpoint, or loader override present')


def validate_rules_pin(value):
    if value is not None and (not isinstance(value, str) or re.fullmatch(r'[a-f0-9]{64}', value) is None):
        raise ProviderError('agyGlobalRulesSha256 must be an exact SHA-256 or explicit null for absence')


def _identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': stat.S_IMODE(info.st_mode),
            'uid': info.st_uid, 'size': info.st_size, 'mtimeNs': info.st_mtime_ns,
            'ctimeNs': info.st_ctime_ns, 'linkCount': info.st_nlink}


def _safe_directory(path):
    info = path.lstat()
    if (path.resolve(strict=True) != path or not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022):
        raise ProviderError('Unsafe AGY ambient configuration directory')
    return info


def _parents(path, anchor):
    # Do not enumerate a home/config store or read account/session contents.
    _safe_directory(anchor)
    current = anchor
    for part in path.relative_to(anchor).parts[:-1]:
        current /= part
        if current.exists() or current.is_symlink():
            _safe_directory(current)


def _file(path, anchor, *, empty_only=False, absent_only=False):
    _parents(path, anchor)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return {'present': False}, None
    if absent_only:
        raise ProviderError('AGY global rules are unexpected or differ from the admitted hash')
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid not in {0, os.getuid()} or before.st_mode & 0o022):
        raise ProviderError('Unsafe AGY ambient configuration file')
    if empty_only:
        if before.st_size != 0:
            raise ProviderError('AGY additional ambient context must be absent or empty')
        # Empty-only sources may contain credentials or unadmitted instructions.
        # Verify the empty descriptor without reading even one content byte.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            if _identity(before) != _identity(os.fstat(fd)):
                raise ProviderError('AGY empty ambient file changed while checking')
            data = b''
        finally:
            os.close(fd)
    else:
        data = _bounded_read(path, limit=64 * 1024).encode('utf-8')
    after = path.lstat()
    if _identity(before) != _identity(after):
        raise ProviderError('AGY ambient configuration changed while reading')
    return {'present': True, 'kind': 'file', **_identity(after),
            'sha256': hashlib.sha256(data).hexdigest()}, data


def _empty_directory(path, anchor):
    _parents(path, anchor)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return {'present': False}
    _safe_directory(path)
    with os.scandir(path) as entries:
        if next(entries, None) is not None:
            raise ProviderError('AGY extra-context or executable customization directory is not empty')
    after = path.lstat()
    if _identity(before) != _identity(after):
        raise ProviderError('AGY customization directory changed while checking')
    return {'present': True, 'kind': 'empty-directory', **_identity(after)}


def _settings(data, *, home, native_cli=False):
    if data is None or not data.strip():
        return
    value = strict_json(data)
    allowed = {'selectedAuthType', 'theme'} | ({'model', 'trustedWorkspaces'} if native_cli else set())
    if not isinstance(value, dict) or set(value) - allowed:
        raise ProviderError('AGY settings contain an unsupported ambient capability')
    if 'selectedAuthType' in value and value['selectedAuthType'] != 'oauth-personal':
        raise ProviderError('AGY requires its normal personal account authentication')
    if 'theme' in value and (not isinstance(value['theme'], str)
            or re.fullmatch(r'[A-Za-z0-9 _-]{1,64}', value['theme']) is None):
        raise ProviderError('Unsupported AGY visual setting')
    if 'model' in value and value['model'] not in {
            'Gemini 3.8 Flash (High)', 'Gemini 3.8 Flash (Medium)', 'Gemini 3.8 Flash (Low)'}:
        raise ProviderError('Unsupported native AGY model display setting')
    if 'trustedWorkspaces' in value and value['trustedWorkspaces'] not in ([], [str(home)]):
        raise ProviderError('AGY native trust records must be empty or exactly the current-user home')


def snapshot(global_rules_sha256):
    """Return bounded metadata only; contents never enter returned evidence."""
    validate_rules_pin(global_rules_sha256)
    reject_environment_overrides()
    home = account_home()
    rows = {}
    for root in GLOBAL_ROOTS:
        for name in EMPTY_DIRECTORIES:
            relative = root + '/' + name
            rows[relative] = _empty_directory(home / relative, home)
        for name in ('settings.json', *EMPTY_JSON, *EMPTY_FILES):
            relative = root + '/' + name
            global_rules = relative == '.gemini/GEMINI.md'
            row, data = _file(home / relative, home,
                empty_only=name in EMPTY_FILES and not global_rules,
                absent_only=global_rules and global_rules_sha256 is None)
            rows[relative] = row
            if relative == '.gemini/GEMINI.md':
                if (global_rules_sha256 is None and data is not None) or (
                        global_rules_sha256 is not None and row.get('sha256') != global_rules_sha256):
                    raise ProviderError('AGY global rules are unexpected or differ from the admitted hash')
                if data is not None and re.search(r'(?m)(?:^|\s)@\S+', data.decode('utf-8')):
                    raise ProviderError('AGY global rules contain an unbound file reference')
            elif name == 'settings.json':
                _settings(data, home=home, native_cli=relative == '.gemini/antigravity-cli/settings.json')
            elif name in EMPTY_JSON:
                if data is not None and data.strip() and strict_json(data) not in ({}, {EMPTY_JSON[name]: {}}):
                    raise ProviderError('AGY executable or MCP configuration is not empty')
            elif data:
                raise ProviderError('AGY additional ambient context must be absent or empty')
    digest = hashlib.sha256(canonical_bytes(rows)).hexdigest()
    return {'schema': CONTEXT_POLICY, 'snapshotSha256': digest, 'sources': rows,
            'globalRulesSha256': global_rules_sha256,
            'globalRulesAdmission': 'absent' if global_rules_sha256 is None else 'operator-admitted-generic-context',
            'contentsRecorded': False, 'credentialStoresRead': False, 'snapshotAtomic': False,
            'nativeHostMetadata': 'pinned-binary-default', 'nativeProject': 'fresh-new-project',
            'nativeModelSetting': 'display-only-overridden-by-explicit-model',
            'nativeTrustAdmission': 'empty-or-existing-current-home-record; not-an-added-workspace',
            'nativeTrustSemantics': 'personal-native-context; serialized-key-semantics-not-fully-documented'}


def workspace_snapshot(root):
    """An empty owned workspace plus no ancestor-discovered context."""
    root = Path(root)
    info = _safe_directory(root)
    if info.st_uid != os.getuid() or info.st_mode & 0o077 or root.is_relative_to(account_home()):
        raise ProviderError('AGY workspace must be owned and private')
    with os.scandir(root) as entries:
        if next(entries, None) is not None:
            raise ProviderError('AGY owned workspace changed or is not empty')
    for parent in root.parents:
        for name in WORKSPACE_NAMES:
            path = parent / name
            if path.exists() or path.is_symlink():
                raise ProviderError('AGY workspace ancestor has additional context')
    if _identity(info) != _identity(root.lstat()):
        raise ProviderError('AGY workspace changed while checking')
    return {'empty': True, **_identity(info)}
