"""Small FD-anchored state store; no imports or paths outside the public engine.

The private state directory is an operator trust boundary, not protection against
arbitrary code already running as that operator. Atomic replacement plus a stable
advisory lock serializes cooperating processes. Corrupt or missing durable state
is never interpreted as an empty budget.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import uuid


MAX_BYTES = 8 * 1024 * 1024
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,180}\Z")


class StateError(ValueError):
    """State/authority failure; callers must stop without provider fallback."""


def require(condition, message):
    if not condition:
        raise StateError(message)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(value):
        raise StateError("Non-finite JSON number")

    def finite_float(value):
        parsed = float(value)
        require(math.isfinite(parsed), "Non-finite JSON number")
        return parsed

    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8", "strict")
        require(isinstance(data, str) and len(data.encode("utf-8")) <= MAX_BYTES,
                "Invalid or oversized JSON state")
        return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant,
                          parse_float=finite_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise StateError("Invalid JSON state") from exc


def canonical_bytes(value):
    try:
        result = json.dumps(value, ensure_ascii=False, allow_nan=False,
                            sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise StateError("Value is not canonical JSON") from exc
    require(len(result) <= MAX_BYTES, "State exceeds byte budget")
    # Reject JSON's conversion of non-string mapping keys and tuple containers.
    require(strict_json(result) == value, "Value changes through JSON encoding")
    return result


def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _name(name):
    require(isinstance(name, str) and _NAME.fullmatch(name)
            and name not in (".", ".."), "Unsafe state entry name")
    return name


def _file_info(fd, *, maximum=MAX_BYTES):
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.getuid() and not (info.st_mode & 0o077)
            and info.st_size <= maximum, "Unsafe state file")
    return info


def _directory_info(fd):
    info = os.fstat(fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and not (info.st_mode & 0o077), "State directory must be private and operator-owned")
    return info


def _identity(info):
    return info.st_dev, info.st_ino


def _absolute_directory(path, *, create=False):
    """Open every absolute path component with O_NOFOLLOW, including ancestors."""
    path = Path(path)
    require(path.is_absolute() and str(path) != "/" and ".." not in path.parts,
            "State root must be an explicit absolute directory")
    source = Path(__file__).absolute().parent.parent
    require(path != source and source not in path.parents and path not in source.parents,
            "State must be separate from installed source")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for number, part in enumerate(path.parts[1:]):
            last = number == len(path.parts) - 2
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=fd)
            except FileNotFoundError:
                if not (create and last):
                    raise
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    # A concurrent first setup may have created the leaf. Open
                    # it without following links and apply the same checks below.
                    pass
                os.fsync(fd)
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=fd)
            os.close(fd)
            fd = next_fd
        _directory_info(fd)
        result, fd = fd, None
        return result
    except OSError as exc:
        raise StateError("Unsafe or unavailable state directory") from exc
    finally:
        if fd is not None:
            os.close(fd)


class StateStore:
    """All filenames are single components beneath a held private root FD."""

    def __init__(self, root, *, create=False):
        self.root = Path(root)
        self.fd = _absolute_directory(self.root, create=create)
        self.identity = _identity(os.fstat(self.fd))
        self._children = {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        for fd in self._children.values():
            os.close(fd)
        os.close(self.fd)

    def check_identity(self):
        current = _absolute_directory(self.root)
        try:
            require(_identity(os.fstat(current)) == self.identity, "State root changed")
        finally:
            os.close(current)
        _directory_info(self.fd)
        for name, fd in self._children.items():
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            require(stat.S_ISDIR(info.st_mode)
                    and _identity(info) == _identity(os.fstat(fd)), "State directory changed")
            _directory_info(fd)

    def directory(self, name, *, create=False):
        _name(name)
        if name not in self._children:
            try:
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=self.fd)
            except FileNotFoundError:
                if not create:
                    raise StateError("Required state directory is missing")
                os.mkdir(name, 0o700, dir_fd=self.fd)
                os.fsync(self.fd)
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=self.fd)
            except OSError as exc:
                raise StateError("Unsafe state directory") from exc
            try:
                _directory_info(fd)
            except BaseException:
                os.close(fd)
                raise
            self._children[name] = fd
        return self._children[name]

    @contextmanager
    def locked(self):
        lock_name = ".authority.lock"
        try:
            try:
                fd = os.open(lock_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
                             0o600, dir_fd=self.fd)
            except FileExistsError:
                # Separating exclusive creation from opening the existing lock
                # avoids Darwin's concurrent O_CREAT|O_NOFOLLOW ENOENT race.
                fd = os.open(lock_name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        except OSError as exc:
            raise StateError("Unsafe authority lock") from exc
        try:
            _file_info(fd, maximum=0)
            fcntl.flock(fd, fcntl.LOCK_EX)
            self.check_identity()
            current = os.stat(lock_name, dir_fd=self.fd, follow_symlinks=False)
            require(_identity(current) == _identity(os.fstat(fd)), "Authority lock changed")
            os.fsync(self.fd)
            yield self
            self.check_identity()
        finally:
            os.close(fd)

    def read_bytes(self, directory, name, *, missing_ok=False):
        parent = self.directory(directory)
        _name(name)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError:
            if missing_ok:
                return None
            raise StateError("Required state file is missing")
        except OSError as exc:
            raise StateError("Unsafe state file") from exc
        try:
            before = _file_info(fd)
            data = bytearray()
            while len(data) <= MAX_BYTES:
                block = os.read(fd, min(65536, MAX_BYTES + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            after = _file_info(fd)
            require(len(data) == before.st_size == after.st_size
                    and (before.st_mtime_ns, before.st_ctime_ns)
                    == (after.st_mtime_ns, after.st_ctime_ns), "State file changed during read")
            entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
            require(_identity(entry) == _identity(after), "State file replaced during read")
            return bytes(data)
        finally:
            os.close(fd)

    def read_json(self, directory, name):
        return strict_json(self.read_bytes(directory, name))

    def write_json(self, directory, name, value, *, expected_bytes):
        """CAS publish under locked(); expected_bytes=None means exclusive create."""
        encoded = canonical_bytes(value) + b"\n"
        require(len(encoded) <= MAX_BYTES, "State exceeds byte budget")
        parent = self.directory(directory)
        _name(name)
        self.check_identity()
        require(self.read_bytes(directory, name, missing_ok=True) == expected_bytes,
                "State changed before atomic write")
        temporary = ".pending-" + uuid.uuid4().hex
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        published = False
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            self.check_identity()
            require(self.read_bytes(directory, name, missing_ok=True) == expected_bytes,
                    "State changed during atomic write")
            if expected_bytes is None:
                # link() publishes without overwriting even under an uncooperative writer.
                os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent,
                        follow_symlinks=False)
                os.unlink(temporary, dir_fd=parent)
            else:
                os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
            published = True
            os.fsync(parent)
        finally:
            if not published:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
