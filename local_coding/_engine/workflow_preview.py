"""Short-lived loopback previews of caller-approved, frozen artifact bytes.

The caller verifies concrete Kernel authority and candidate checks before invoking this
module. The server checks artifact ownership, packet identity and exact bytes;
it never serves a repository, reads files on requests, or evaluates model code.
"""
if __name__ == '__main__':
    raise SystemExit('INTERNAL_HELPER_REQUIRES_KERNEL')

from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import signal
import stat
import threading
import uuid
from urllib.parse import quote

from generate_edits import strict_json
from workflow_core import ContractError, DIRECTORY, reject_secrets, require, safe_path
from host_paths import validate_state_root

MAX_FILE_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 256 * 1024
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
MIME_TYPES = {'.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
              '.js': 'text/javascript; charset=utf-8', '.md': 'text/plain; charset=utf-8',
              '.json': 'application/json; charset=utf-8', '.txt': 'text/plain; charset=utf-8'}
SECURITY_HEADERS = {
    'Content-Security-Policy': "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-src 'none'; object-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox allow-scripts",
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), display-capture=(), payment=()',
    'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store, max-age=0',
    'Pragma': 'no-cache', 'Expires': '0', 'Cross-Origin-Opener-Policy': 'same-origin',
}


def _canonical(path):
    try:
        validate_state_root(DIRECTORY)
    except (OSError, ValueError) as exc:
        raise ContractError(str(exc)) from exc
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path and path.is_relative_to(DIRECTORY)
            and path != DIRECTORY, 'Preview path must be canonical and task-owned under the configured state root')
    safe_path(path.relative_to(DIRECTORY).as_posix())
    return path


def _parent_fd(path, create=False):
    descriptor = os.open(DIRECTORY, DIRECTORY_FLAGS)
    try:
        for component in path.relative_to(DIRECTORY).parts[:-1]:
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


def _read_at(parent_fd, name, limit):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
                'Preview scope contains an unsafe or oversized file')
        data = source.read(limit + 1)
        require(len(data) <= limit, 'Preview file grew beyond byte limit')
        return data


def _freeze(candidate, allowed_paths, packet_sha256=None):
    candidate = _canonical(candidate)
    require(isinstance(allowed_paths, list) and 1 <= len(allowed_paths) <= 8, 'Expected one to eight approved preview paths')
    for relative in allowed_paths:
        safe_path(relative)
        require(Path(relative).suffix.lower() in MIME_TYPES and not any(c in relative for c in '%?#'),
                'Preview file type or URL characters are unsupported')
    require(len(set(allowed_paths)) == len(allowed_paths), 'Duplicate preview paths')
    parent_fd = _parent_fd(candidate)
    candidate_fd = None
    try:
        candidate_fd = os.open(candidate.name, DIRECTORY_FLAGS, dir_fd=parent_fd)
        owner = strict_json(_read_at(parent_fd, '.' + candidate.name + '.artifact-owner.json', 16000))
        manifest = strict_json(_read_at(parent_fd, '.' + candidate.name + '.artifact-output.json', 16000))
        info = os.fstat(candidate_fd)
        require(isinstance(owner, dict) and owner.get('candidate') == str(candidate)
                and (owner.get('device'), owner.get('inode')) == (info.st_dev, info.st_ino)
                and isinstance(owner.get('packet_sha256'), str)
                and re.fullmatch('[0-9a-f]{64}', owner['packet_sha256']), 'Preview artifact ownership identity mismatch')
        require(packet_sha256 is None or owner['packet_sha256'] == packet_sha256, 'Preview packet identity mismatch')
        require(isinstance(manifest, dict) and set(manifest) == set(allowed_paths), 'Preview approved artifact scope mismatch')
        prefixes = {p.as_posix() for path in allowed_paths for p in PurePosixPath(path).parents if p != PurePosixPath('.')}
        assets = {}
        def visit(directory_fd, prefix=''):
            for name in sorted(os.listdir(directory_fd)):
                relative = prefix + name
                entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(entry.st_mode) and relative in prefixes:
                    nested = os.open(name, DIRECTORY_FLAGS, dir_fd=directory_fd)
                    try:
                        visit(nested, relative + '/')
                    finally:
                        os.close(nested)
                    continue
                require(relative in manifest and stat.S_ISREG(entry.st_mode), 'Unexpected preview path or symlink')
                data = _read_at(directory_fd, name, MAX_FILE_BYTES)
                require(manifest[relative] == {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)},
                        'Preview artifact byte identity mismatch')
                try:
                    reject_secrets(data.decode('utf-8'))
                except UnicodeError as exc:
                    raise ContractError('Preview requires UTF-8 text artifacts') from exc
                assets[relative] = data
        visit(candidate_fd)
        require(set(assets) == set(allowed_paths) and sum(map(len, assets.values())) <= MAX_TOTAL_BYTES,
                'Preview scope or total byte limit mismatch')
        return assets, owner
    finally:
        if candidate_fd is not None:
            os.close(candidate_fd)
        os.close(parent_fd)


def safe_assets(candidate, allowed_paths):
    """Return approved frozen file bytes; later requests never revisit disk."""
    return _freeze(candidate, allowed_paths)[0]


def _response(method, target, headers, assets, nonce, host):
    """Pure request policy, shared by the real HTTP handler and offline tests."""
    supplied = {}
    for name, value in headers:
        supplied.setdefault(name.lower(), []).append(value)
    response_headers = dict(SECURITY_HEADERS)
    status, body, mime = 404, b'', 'text/plain; charset=utf-8'
    if supplied.get('host') != [host]:
        status = 400
    elif ('origin' in supplied and supplied['origin'] != ['http://' + host]) or (
          'sec-fetch-site' in supplied and supplied['sec-fetch-site'] not in (['same-origin'], ['none'])):
        status = 403
    elif method not in ('GET', 'HEAD'):
        status = 405
        response_headers['Allow'] = 'GET, HEAD'
    elif '?' not in target and '#' not in target and '\\' not in target:
        # Comparing canonical encoded URLs rejects traversal, double encoding,
        # encoded slashes, directory requests and all unapproved subpaths.
        routes = {'/' + nonce + '/' + quote(relative, safe='/'): relative for relative in assets}
        relative = routes.get(target)
        if relative is not None:
            status, body, mime = 200, assets[relative], MIME_TYPES[Path(relative).suffix.lower()]
    response_headers.update({'Content-Type': mime, 'Content-Length': str(len(body)), 'Connection': 'close'})
    return status, response_headers, b'' if method == 'HEAD' else body


class _PreviewStopped(BaseException):
    def __init__(self, reason):
        self.reason = reason


class _PreviewServer(HTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(0.5)
        return connection, address


def _handler(assets, nonce):
    frozen = dict(assets)
    class Handler(BaseHTTPRequestHandler):
        server_version = 'HNPreview'
        sys_version = ''
        def log_message(self, *args):
            pass
        def _handle(self):
            host = '127.0.0.1:' + str(self.server.server_address[1])
            status, headers, body = _response(self.command, self.path, self.headers.items(), frozen, nonce, host)
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.close_connection = True
            if body:
                self.wfile.write(body)
        do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_TRACE = do_CONNECT = _handle
        def send_error(self, code, message=None, explain=None):
            self.send_response(code)
            for name, value in {**SECURITY_HEADERS, 'Content-Length': '0', 'Connection': 'close'}.items():
                self.send_header(name, value)
            self.end_headers()
            self.close_connection = True
    return Handler


def _save(evidence_fd, filename, value):
    descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=evidence_fd)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(json.dumps(value, ensure_ascii=False, indent=2).encode() + b'\n')


def serve_preview(candidate, allowed_paths, evidence_dir, packet_sha256, ttl_seconds=300, *, expires_at=None):
    """Run one foreground loopback preview for at most 300 seconds."""
    require(type(ttl_seconds) is int and 1 <= ttl_seconds <= 300, 'Preview TTL must be 1..300 seconds')
    require(isinstance(packet_sha256, str) and re.fullmatch('[0-9a-f]{64}', packet_sha256), 'Invalid approved packet SHA256')
    require(threading.current_thread() is threading.main_thread(), 'Preview must run in the foreground main thread')
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'Preview cannot replace an existing process timer')
    if expires_at is not None:
        from contracts import _timestamp
        expiry = _timestamp(expires_at)
    else:
        expiry = None
    candidate, evidence = _canonical(candidate), _canonical(evidence_dir)
    require(not evidence.is_relative_to(candidate), 'Preview evidence must be outside candidate')
    assets, _ = _freeze(candidate, allowed_paths, packet_sha256)
    parent_fd = _parent_fd(evidence, create=True)
    try:
        os.mkdir(evidence.name, mode=0o700, dir_fd=parent_fd)
        evidence_fd = os.open(evidence.name, DIRECTORY_FLAGS, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    server, reason, alarm_reason = None, 'error', 'ttl-expired'
    session_id, nonce = uuid.uuid4().hex, secrets.token_urlsafe(24)
    old_handlers = {}
    def stop(signum, frame):
        raise _PreviewStopped({signal.SIGALRM: alarm_reason, signal.SIGINT: 'interrupt', signal.SIGTERM: 'terminated'}[signum])
    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
            old_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, stop)
        # Freezing files and preparing durable evidence may take time. Carry the
        # caller's absolute approval deadline through that work, rather than
        # starting a fresh full TTL after it has already expired.
        timer_seconds = ttl_seconds
        if expiry is not None:
            remaining = (expiry - datetime.now(timezone.utc)).total_seconds()
            require(remaining > 0, 'Preview authorization expired before server startup')
            if remaining < timer_seconds:
                timer_seconds, alarm_reason = remaining, 'authorization-expired'
        signal.setitimer(signal.ITIMER_REAL, timer_seconds)
        server = _PreviewServer(('127.0.0.1', 0), _handler(assets, nonce))
        server.timeout = 0.2
        base_url = 'http://127.0.0.1:' + str(server.server_address[1])
        paths = sorted(assets)
        entry = 'index.html' if 'index.html' in assets else next((path for path in paths if path.endswith('.html')), paths[0])
        preview = {'pid': os.getpid(), 'session_id': session_id, 'host': '127.0.0.1',
                   'port': server.server_address[1], 'base_url': base_url,
                   'nonce_prefix': '/' + nonce + '/', 'url': base_url + '/' + nonce + '/' + quote(entry, safe='/'),
                   'packet_sha256': packet_sha256, 'ttl_seconds': ttl_seconds,
                   'started_at': datetime.now(timezone.utc).isoformat(),
                   'urls': {path: base_url + '/' + nonce + '/' + quote(path, safe='/') for path in paths},
                   'files': {path: {'sha256': hashlib.sha256(assets[path]).hexdigest(),
                                    'bytes': len(assets[path])} for path in paths}}
        if expires_at is not None:
            preview['authorization_expires_at'] = expires_at
        _save(evidence_fd, 'preview.json', preview)
        print(json.dumps(preview, ensure_ascii=False), flush=True)
        while True:
            server.handle_request()
    except _PreviewStopped as stopped:
        reason = stopped.reason
    except KeyboardInterrupt:
        reason = 'interrupt'
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        server_closed = server is None
        try:
            if server is not None:
                server.server_close()
                server_closed = True
        finally:
            for signum, previous in old_handlers.items():
                signal.signal(signum, previous)
            try:
                _save(evidence_fd, 'stopped.json', {'pid': os.getpid(), 'session_id': session_id,
                      'reason': reason, 'stopped_at': datetime.now(timezone.utc).isoformat(),
                      'server_closed': server_closed})
            finally:
                os.close(evidence_fd)
    return {'session_id': session_id, 'reason': reason}

