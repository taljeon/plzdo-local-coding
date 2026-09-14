"""Generic, process-verified delegation from an operator-owned parent record.

Prepare is non-authorizing. Adoption records the parent's actual approval pins,
then the existing ledger is the sole budget. A fixed isolated Python verifier
reads the parent; it must never call this runtime while its state lock is held.
These local snapshots are not a signed identity or an atomic cancellation lease.
"""
import copy
import hashlib
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time

import contracts
from state_io import StateError, StateStore, canonical_bytes, digest, require, strict_json


REQUEST_VERSION = "plzdo.parent-request.v2"
CONTRACT_VERSION = contracts.POLICY.schema_version("parent-exact")
SCOPE_REQUEST_VERSION = "plzdo.parent-scope-request.v2"
SCOPE_CONTRACT_VERSION = contracts.POLICY.schema_version("parent-scope")
INPUT_VERSION = "plzdo.parent-verifier-input.v2"
RESULT_VERSION = "plzdo.parent-verifier.v2"
TRUST_VERSION = "plzdo.parent-verifier-trust.v2"
AUTHORIZATION_BASIS = "operator-owned-local-record-snapshot"
MAX_INPUT = 4 * 1024 * 1024
MAX_OUTPUT = 64 * 1024
VERIFIER_TIMEOUT = 15
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
               "PYTHONDONTWRITEBYTECODE": "1"}
_DIRECTORY_FIELDS = {"path", "device", "inode"}
_FILE_FIELDS = _DIRECTORY_FIELDS | {"sha256"}
_REQUEST_FIELDS = {"schemaVersion", "id", "preparedAt", "expiresAt", "runtimeState",
                   "policyFingerprint", "parentReference", "verifier", "packet", "execution",
                   "requestSha256"}
_PARENT_PINS = ("parentApprovalHash", "parentCreatedAt", "parentApprovedAt")


def _same(left, right):
    return canonical_bytes(left) == canonical_bytes(right)


def _path(value):
    require(isinstance(value, str) and value == os.path.normpath(value)
            and Path(value).is_absolute() and value != "/"
            and not any(c in value for c in ("\0", "\n", "\r")), "Unsafe parent/verifier path")
    path = Path(value)
    try:
        require(path.resolve(strict=True) == path, "Parent/verifier symlink or path changed")
    except OSError as exc:
        raise StateError("Parent/verifier path unavailable") from exc
    return path


def _identity_shape(value, *, file=False, current_path=True):
    require(isinstance(value, dict) and set(value) == (_FILE_FIELDS if file else _DIRECTORY_FIELDS),
            "Invalid parent/verifier identity fields")
    if current_path:
        _path(value["path"])
    else:
        path = value["path"]
        require(isinstance(path, str) and 1 < len(path) <= 4096 and Path(path).is_absolute()
                and path == os.path.normpath(path) and str(Path(path)) == path and path != "/"
                and not any(c in path for c in ("\0", "\n", "\r")), "Invalid historical pinned path")
    for key in ("device", "inode"):
        require(type(value[key]) is int and value[key] >= 0, "Invalid parent/verifier inode identity")
    if file:
        require(isinstance(value["sha256"], str) and contracts.SHA256.fullmatch(value["sha256"]),
                "Invalid verifier file digest")


def directory_identity(path):
    path = _path(os.fspath(path))
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
                    and not info.st_mode & 0o022, "Unsafe parent/verifier directory")
            current = path.lstat()
            require((info.st_dev, info.st_ino) == (current.st_dev, current.st_ino),
                    "Parent/verifier directory changed during inspection")
            return {"path": str(path), "device": info.st_dev, "inode": info.st_ino}
        finally:
            os.close(fd)
    except OSError as exc:
        raise StateError("Parent/verifier directory unavailable") from exc


def _file_snapshot(path, *, maximum=8 * 1024 * 1024):
    path = _path(os.fspath(path))
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_uid in (0, os.getuid()) and not before.st_mode & 0o022
                    and before.st_size <= maximum, "Unsafe bounded verifier file")
            data = bytearray()
            while len(data) <= maximum:
                block = os.read(fd, min(65536, maximum + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            after, current = os.fstat(fd), path.lstat()
            identity = lambda v: (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
            require(len(data) == before.st_size and identity(before) == identity(after) == identity(current),
                    "Verifier file changed during inspection")
            return ({"path": str(path), "device": before.st_dev, "inode": before.st_ino,
                     "sha256": hashlib.sha256(data).hexdigest()}, bytes(data))
        finally:
            os.close(fd)
    except OSError as exc:
        raise StateError("Verifier file unavailable") from exc


def file_identity(path, *, maximum=8 * 1024 * 1024):
    return _file_snapshot(path, maximum=maximum)[0]


def read_input_json(path, *, maximum=MAX_INPUT):
    """Bound allocation before reading untrusted CLI input, with no-follow pins."""
    return strict_json(_file_snapshot(path, maximum=maximum)[1])


def _verify_directory(value):
    _identity_shape(value)
    require(directory_identity(value["path"]) == value, "Parent/verifier directory identity changed")


def _verify_file(value, maximum=8 * 1024 * 1024):
    _identity_shape(value, file=True)
    require(file_identity(value["path"], maximum=maximum) == value, "Verifier file pin changed")


def _verify_closure(verifier):
    require(isinstance(verifier, dict) and set(verifier) == {
        "python", "entrypoint", "config", "codeRoots", "codeFiles"}, "Invalid fixed verifier fields")
    _verify_file(verifier["python"], 128 * 1024 * 1024)
    _verify_file(verifier["entrypoint"])
    _verify_file(verifier["config"], 1024 * 1024)
    roots, files = verifier["codeRoots"], verifier["codeFiles"]
    require(isinstance(roots, list) and 0 < len(roots) <= 16,
            "Verifier needs bounded code roots")
    require(isinstance(files, list) and 0 < len(files) <= 1024,
            "Verifier needs bounded code closure")
    for root in roots:
        _verify_directory(root)
    root_paths = [item["path"] for item in roots]
    require(root_paths == sorted(set(root_paths)), "Verifier code roots must be unique and sorted")
    for item in files:
        _verify_file(item)
    file_paths = [item["path"] for item in files]
    require(file_paths == sorted(set(file_paths)), "Verifier code files must be unique and sorted")
    observed, entries = set(), 0
    for item in roots:
        for root, directories, filenames in os.walk(item["path"], followlinks=False):
            entries += len(directories) + len(filenames)
            require(entries <= 8192, "Verifier closure exceeds entry budget")
            directory_identity(root)
            for name in directories:
                directory_identity(str(Path(root) / name))
            for name in filenames:
                path = Path(root) / name
                require(not path.is_symlink() and path.is_file(), "Unsafe verifier closure entry")
                observed.add(str(path))
    expected = {path for path in file_paths if any(Path(root) in Path(path).parents for root in root_paths)}
    require(observed == expected, "Verifier code closure added or removed files")
    _fixed_adapter(verifier)


def _fixed_adapter(verifier):
    """Trust the installed/source public dependency, never caller-selected code."""
    try:
        import plzdo_local
        from plzdo_local_code_adapter import codec
        adapter_root = Path(codec.__file__).resolve().parent
        core_package = Path(plzdo_local.__file__).resolve().parent
        core_root = core_package if (core_package / "_bundled").is_dir() else core_package.parent
        config = codec.validate_config(read_input_json(verifier["config"]["path"], maximum=1024 * 1024))
        interpreter = file_identity(Path(sys.executable).resolve(), maximum=128 * 1024 * 1024)
        require(verifier["python"] == interpreter and config["corePython"] == interpreter,
                "Parent verifier must use this fixed trusted interpreter")
        require(config["coreRoot"] == codec.root_pin(core_root), "Parent core must be the installed dependency")
        require(verifier["entrypoint"] == codec.file_pin(adapter_root / "verify_parent.py"),
                "Parent verifier must be the fixed public adapter")
        roots = [codec.root_pin(adapter_root), *[codec.root_pin(path) for path in codec.core_roots(core_root)]]
        require(verifier["codeRoots"] == sorted(roots, key=lambda item: item["path"]),
                "Parent verifier root closure differs from the fixed dependency")
        files = [codec.file_pin(path) for path in codec.closure(adapter_root)] + config["coreCodeFiles"]
        require(verifier["codeFiles"] == sorted(files, key=lambda item: item["path"]),
                "Parent verifier file closure differs from the fixed dependency")
    except (ImportError, ValueError, OSError) as exc:
        raise StateError("Fixed public parent adapter dependency unavailable or changed") from exc


def _runtime_identity(store):
    store.check_identity()
    return {"path": str(store.root), "device": store.identity[0], "inode": store.identity[1]}


def _trusted_verifier(store, verifier):
    """One fixed operator configuration; request data cannot choose its location."""
    raw = store.read_bytes("parent-verifier", "trust.json")
    require(len(raw) <= 1024 * 1024, "Verifier trust anchor exceeds byte budget")
    document = strict_json(raw)
    require(isinstance(document, dict) and set(document) == {
        "schemaVersion", "configuredAt", "runtimeState", "verifier", "descriptorSha256"}
        and document["schemaVersion"] == TRUST_VERSION, "Invalid fixed verifier trust anchor")
    require(contracts._timestamp(document["configuredAt"]) <= contracts._now(), "Verifier setup time is in the future")
    require(document["runtimeState"] == _runtime_identity(store), "Verifier trust state identity changed")
    require(document["verifier"] == verifier and document["descriptorSha256"] == digest(verifier),
            "Requested verifier does not match the fixed trusted verifier")
    info = os.stat("trust.json", dir_fd=store.directory("parent-verifier"), follow_symlinks=False)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
            and not info.st_mode & 0o077, "Unsafe verifier trust anchor")
    return document, (info.st_dev, info.st_ino, hashlib.sha256(raw).hexdigest())


def trust_verifier(state_root, verifier, *, expected_descriptor_sha256, confirmation):
    """Explicit one-time operator setup, never an execution or parent approval."""
    from provider_common import require_active_session
    require_active_session()
    require(isinstance(expected_descriptor_sha256, str)
            and contracts.SHA256.fullmatch(expected_descriptor_sha256)
            and expected_descriptor_sha256 == digest(verifier), "Exact reviewed verifier descriptor hash is required")
    require(confirmation == "TRUST PARENT VERIFIER " + expected_descriptor_sha256,
            "Exact verifier setup confirmation is required")
    _verify_closure(verifier)
    with StateStore(state_root, create=True) as store, store.locked():
        store.directory("parent-verifier", create=True)
        raw = store.read_bytes("parent-verifier", "trust.json", missing_ok=True)
        if raw is not None:
            document, _ = _trusted_verifier(store, verifier)
            return copy.deepcopy(document)
        document = {"schemaVersion": TRUST_VERSION, "configuredAt": contracts._now().isoformat(),
                    "runtimeState": _runtime_identity(store), "verifier": copy.deepcopy(verifier),
                    "descriptorSha256": expected_descriptor_sha256}
        require(len(canonical_bytes(document)) < 1024 * 1024, "Verifier trust anchor exceeds byte budget")
        store.write_json("parent-verifier", "trust.json", document, expected_bytes=None)
        return copy.deepcopy(document)


def _parent_reference(value, *, current_paths=True):
    require(isinstance(value, dict) and set(value) == {"state", "formalizationId", "projectId", "project"},
            "Invalid parent reference fields")
    contracts._identifier(value["formalizationId"])
    contracts._identifier(value["projectId"])
    for pin in (value["state"], value["project"]):
        if current_paths:
            _verify_directory(pin)
        else:
            _identity_shape(pin, current_path=False)


def stable_id(runtime_state, parent_reference, packet_id):
    contracts._identifier(packet_id)
    # Scope changes cannot reset a parent's ledger. Derive this before normalizing
    # authorityId, and deliberately exclude policy, expiry and verifier pins.
    return "parent-" + digest({"runtimeState": runtime_state, "parentState": parent_reference["state"],
                               "formalizationId": parent_reference["formalizationId"], "packetId": packet_id})


def request_sha256(request):
    return digest({key: value for key, value in request.items() if key != "requestSha256"})


def marker(request):
    prefix = ("plzdo-scope-delegation:v2:" if request.get("schemaVersion") == SCOPE_REQUEST_VERSION
              else "plzdo-delegation:v2:")
    return prefix + request["requestSha256"]


def stable_scope_id(runtime_state, parent_reference):
    # One root per parent identity. Template/child/scope labels never reset it.
    return "parent-scope-" + digest({"runtimeState": runtime_state,
        "parentState": parent_reference["state"], "formalizationId": parent_reference["formalizationId"]})


def _execution_shape(execution):
    return contracts.validate_execution(execution, one_packet=True)


def validate_request(request, store):
    require(isinstance(request, dict), "Invalid prepared parent request")
    scoped = request.get("schemaVersion") == SCOPE_REQUEST_VERSION
    require(set(request) == (_REQUEST_FIELDS - {"packet"} if scoped else _REQUEST_FIELDS)
            and request["schemaVersion"] in (REQUEST_VERSION, SCOPE_REQUEST_VERSION), "Invalid prepared parent request")
    contracts._identifier(request["id"])
    prepared, expires = contracts._timestamp(request["preparedAt"]), contracts._timestamp(request["expiresAt"])
    require(prepared.microsecond == 0 and prepared <= contracts._now() < expires,
            "Prepared request expired or timestamp is invalid")
    require(request["runtimeState"] == _runtime_identity(store), "Delegated runtime state identity changed")
    _parent_reference(request["parentReference"])
    require(request["policyFingerprint"] == contracts.policy_fingerprint(), "Delegated runtime policy drift")
    if scoped:
        from provider_common import require_active_session
        require_active_session()
        from scope_authority import validate_execution
        require(request["id"] == stable_scope_id(request["runtimeState"], request["parentReference"]),
                "Prepared scope stable id drift")
        validate_execution(request["execution"], request["id"])
    else:
        packet = request["packet"]
        require(isinstance(packet, dict), "Invalid delegated packet")
        require(request["id"] == stable_id(request["runtimeState"], request["parentReference"], packet.get("id")),
                "Prepared delegation stable id drift")
        require(packet.get("authorityId") == request["id"], "Delegated packet contract id drift")
        from workflow import validate_task_packet
        require(_same(validate_task_packet(copy.deepcopy(packet)), packet), "Delegated packet normalization drift")
        _execution_shape(request["execution"])
        contracts.binding_for_packet(request, packet)
    require(request["requestSha256"] == request_sha256(request), "Prepared request hash mismatch")
    _trusted_verifier(store, request["verifier"])
    _verify_closure(request["verifier"])
    return request


def _process(verifier, value):
    """Bound stdin, both output streams, lifetime, and the whole process group."""
    data = canonical_bytes(value) + b"\n"
    require(len(data) <= MAX_INPUT, "Verifier input exceeds byte budget")
    argv = [verifier["python"]["path"], "-I", "-B", "-S", verifier["entrypoint"]["path"],
            "--config", verifier["config"]["path"]]
    started = time.monotonic()
    child = subprocess.Popen(argv, cwd="/", env=dict(ENVIRONMENT), stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    output, errors, offset = bytearray(), bytearray(), 0
    try:
        with selectors.DefaultSelector() as selector:
            for stream, event, label in ((child.stdin, selectors.EVENT_WRITE, "input"),
                                         (child.stdout, selectors.EVENT_READ, "output"),
                                         (child.stderr, selectors.EVENT_READ, "errors")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, event, label)
            while selector.get_map():
                remaining = VERIFIER_TIMEOUT - (time.monotonic() - started)
                require(remaining > 0, "Parent verifier timed out")
                for key, _ in selector.select(min(remaining, 0.1)):
                    stream, label = key.fileobj, key.data
                    if label == "input":
                        try:
                            offset += os.write(stream.fileno(), data[offset:offset + 65536])
                        except BrokenPipeError:
                            require(False, "Parent verifier closed input early")
                        if offset == len(data):
                            selector.unregister(stream)
                            stream.close()
                    else:
                        block = os.read(stream.fileno(), 65536)
                        if not block:
                            selector.unregister(stream)
                            stream.close()
                        else:
                            destination = output if label == "output" else errors
                            destination.extend(block)
                            require(len(destination) <= MAX_OUTPUT, "Parent verifier output exceeds byte budget")
            remaining = VERIFIER_TIMEOUT - (time.monotonic() - started)
            require(remaining > 0, "Parent verifier timed out")
            try:
                code = child.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise StateError("Parent verifier timed out") from exc
        require(code == 0 and not errors, "Parent verifier failed or emitted diagnostics")
        return strict_json(bytes(output))
    finally:
        # Even a successful main process may leave descendants holding work.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        for stream in (child.stdin, child.stdout, child.stderr):
            if not stream.closed:
                stream.close()


def _result(result, request, *, operation, started_at):
    fields = {"protocol", "status", "requestSha256", *_PARENT_PINS, "observedAt",
              "authorizationBasis", "atomicLease"}
    require(isinstance(result, dict) and set(result) == fields
            and result["protocol"] == RESULT_VERSION
            and result["requestSha256"] == request["requestSha256"]
            and result["authorizationBasis"] == AUTHORIZATION_BASIS
            and result["atomicLease"] is False, "Invalid parent verifier result")
    observed = contracts._timestamp(result["observedAt"])
    prepared, expires = contracts._timestamp(request["preparedAt"]), contracts._timestamp(request["expiresAt"])
    # The core timestamps are second-granularity; same-second draft/approve works.
    require(max(prepared, started_at.replace(microsecond=0)) <= observed <= contracts._now()
            and observed < expires, "Stale/future parent observation or expired delegation")
    status = result["status"]
    require(status in ({"absent", "prepared", "verified"} if operation == "prepare" else {"verified"}),
            "Parent is not verified/approved")
    if status == "verified":
        require(isinstance(result["parentApprovalHash"], str)
                and contracts.SHA256.fullmatch(result["parentApprovalHash"]), "Invalid parent approval hash")
        created, approved = (contracts._timestamp(result[key]) for key in ("parentCreatedAt", "parentApprovedAt"))
        require(prepared <= created <= approved <= observed, "Parent approval timing is invalid")
    else:
        require(all(result[key] is None for key in _PARENT_PINS), "Unapproved parent cannot supply approval pins")
    return result


def verify_parent(request, store, *, operation="verify"):
    require(operation in ("prepare", "verify"), "Invalid parent verification operation")
    validate_request(request, store)
    _, anchor_before = _trusted_verifier(store, request["verifier"])
    started_at = contracts._now()
    result = _process(request["verifier"], {"protocol": INPUT_VERSION,
                                           "operation": operation, "request": request})
    # Recheck code, packet/policy and all path identities after the subprocess,
    # before any authoritative state write under the caller's held lock.
    validate_request(request, store)
    _, anchor_after = _trusted_verifier(store, request["verifier"])
    require(anchor_after == anchor_before, "Fixed verifier trust anchor changed during verification")
    return _result(result, request, operation=operation, started_at=started_at)


def prepare_request(state_root, packet, *, parent_reference, verifier, expires_at,
                    max_live_integration_calls, allowed_engines, max_runs=1, preview_authorization=None):
    """Persist one immutable scope before the operator creates/approves its parent."""
    require(isinstance(packet, dict), "Expected a packet object")
    _parent_reference(parent_reference)
    with StateStore(state_root, create=True) as store, store.locked():
        _trusted_verifier(store, verifier)
        state = _runtime_identity(store)
        identifier = stable_id(state, parent_reference, packet.get("id"))
        normalized = copy.deepcopy(packet)
        normalized["authorityId"] = identifier
        from workflow import validate_task_packet
        normalized = validate_task_packet(normalized)
        contracts._integer(max_runs, 1, 1000, "packet maxRuns")
        contracts._engines(allowed_engines)
        request = {"schemaVersion": REQUEST_VERSION, "id": identifier,
                   "preparedAt": contracts._now().replace(microsecond=0).isoformat(), "expiresAt": expires_at,
                   "runtimeState": state, "policyFingerprint": contracts.policy_fingerprint(),
                   "parentReference": copy.deepcopy(parent_reference), "verifier": copy.deepcopy(verifier),
                   "packet": normalized, "execution": {"maxLiveIntegrationCalls": max_live_integration_calls,
                       "allowedEngines": list(allowed_engines),
                       "enginePins": contracts.current_engine_pins(allowed_engines), "taskBindings": {normalized["id"]:
                           contracts._packet_binding(normalized, allowed_engines, max_runs)}}}
        if preview_authorization is not None:
            contracts.validate_preview_authorization(preview_authorization,
                bindings=request["execution"]["taskBindings"], packets=[normalized])
            request["execution"]["previewAuthorization"] = copy.deepcopy(preview_authorization)
        store.directory("parent-requests", create=True)
        name = identifier + ".json"
        raw = store.read_bytes("parent-requests", name, missing_ok=True)
        adopted = None
        if raw is not None:
            previous = strict_json(raw)
            validate_request(previous, store)
            request["preparedAt"] = previous["preparedAt"]
        request["requestSha256"] = request_sha256(request)
        if raw is not None:
            require(_same(request, previous), "Prepared delegation scope drift; never reset or overwrite")
            adopted = _adoption_state(store, request, allow_missing=True)
        result = verify_parent(request, store, operation="prepare")
        if adopted is not None:
            require(result["status"] == "verified", "Adopted parent is no longer approved")
            _match_parent(adopted, result)
        if raw is None:
            require(result["status"] == "absent", "Prepare requires an unused proposed parent goal id")
            # Detect collisions with any standalone or partially adopted state.
            _adoption_state(store, request, allow_missing=True)
            store.write_json("parent-requests", name, request, expected_bytes=None)
        return copy.deepcopy(request)


def prepare_scope_request(state_root, scope, *, parent_reference, verifier, expires_at,
                          max_live_integration_calls, allowed_engines, max_total_runs,
                          max_children, max_runs_per_child=1, preview_authorization=None):
    """Prepare a new, opt-in root scope; not an extension of an exact request."""
    from provider_common import require_active_session
    from scope_authority import normalize_scope, validate_execution
    require_active_session()
    _parent_reference(parent_reference)
    with StateStore(state_root, create=True) as store, store.locked():
        _trusted_verifier(store, verifier)
        state = _runtime_identity(store)
        identifier = stable_scope_id(state, parent_reference)
        execution = {"maxLiveIntegrationCalls": max_live_integration_calls,
            "allowedEngines": list(allowed_engines),
            "enginePins": contracts.current_engine_pins(allowed_engines), "maxTotalRuns": max_total_runs,
            "maxChildren": max_children, "maxRunsPerChild": max_runs_per_child,
            "taskScope": normalize_scope(scope, identifier, bind_root=True)}
        if preview_authorization is not None:
            execution["previewAuthorization"] = copy.deepcopy(preview_authorization)
        validate_execution(execution, identifier)
        request = {"schemaVersion": SCOPE_REQUEST_VERSION, "id": identifier,
            "preparedAt": contracts._now().replace(microsecond=0).isoformat(), "expiresAt": expires_at,
            "runtimeState": state, "policyFingerprint": contracts.policy_fingerprint(),
            "parentReference": copy.deepcopy(parent_reference), "verifier": copy.deepcopy(verifier),
            "execution": execution}
        store.directory("parent-requests", create=True)
        name = identifier + ".json"
        raw = store.read_bytes("parent-requests", name, missing_ok=True)
        adopted = None
        if raw is not None:
            previous = strict_json(raw)
            validate_request(previous, store)
            request["preparedAt"] = previous["preparedAt"]
        request["requestSha256"] = request_sha256(request)
        if raw is not None:
            require(_same(request, previous), "Prepared scope drift; never reset or overwrite")
            adopted = _adoption_state(store, request, allow_missing=True)
        result = verify_parent(request, store, operation="prepare")
        if adopted is not None:
            require(result["status"] == "verified", "Adopted parent is no longer approved")
            _match_parent(adopted, result)
        if raw is None:
            require(result["status"] == "absent", "Prepare requires an unused proposed parent goal id")
            _adoption_state(store, request, allow_missing=True)
            store.write_json("parent-requests", name, request, expected_bytes=None)
        return copy.deepcopy(request)


def _adoption_state(store, request, *, allow_missing):
    name = request["id"] + ".json"
    values = []
    for directory in ("contracts", "ledgers"):
        try:
            values.append(store.read_bytes(directory, name, missing_ok=True))
        except StateError:
            # Only an actually absent directory is absence. Unsafe entries fail.
            try:
                os.stat(directory, dir_fd=store.fd, follow_symlinks=False)
            except FileNotFoundError:
                values.append(None)
            else:
                raise
    require((values[0] is None) == (values[1] is None), "Partial delegation adoption; refuse reinitialization")
    if values[0] is None:
        require(allow_missing, "Delegated contract/ledger state is missing")
        if request["schemaVersion"] == SCOPE_REQUEST_VERSION:
            try:
                os.stat("scoped-children", dir_fd=store.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                require(store.read_bytes("scoped-children", name, missing_ok=True) is None,
                        "Partial scoped adoption; refuse catalog reinitialization")
        return None
    document = strict_json(values[0])
    _validate_document(document, request)
    from ledger import validate_ledger
    if request["schemaVersion"] == SCOPE_REQUEST_VERSION:
        from scope_authority import scope_children
        children = scope_children(store, document)
        validate_ledger(strict_json(values[1]), document,
                        bindings={key: entry["binding"] for key, entry in children.items()})
    else:
        validate_ledger(strict_json(values[1]), document)
    return document


def _validate_document(document, request, *, check_freshness=True):
    fields = {"schemaVersion", "id", "status", "adoptedAt", "expiresAt", "policyFingerprint",
              "execution", "request", *_PARENT_PINS}
    require(isinstance(document, dict) and set(document) == fields
            and document["schemaVersion"] == (SCOPE_CONTRACT_VERSION if request["schemaVersion"] == SCOPE_REQUEST_VERSION
                                               else CONTRACT_VERSION) and document["status"] == "delegated",
            "Invalid distinct delegated contract")
    require(_same(document["request"], request) and all(_same(document[key], request[key])
            for key in ("id", "expiresAt", "policyFingerprint", "execution")), "Delegated projection drift")
    prepared = contracts._timestamp(request["preparedAt"])
    created, approved, adopted = (contracts._timestamp(document[key]) for key in (
        "parentCreatedAt", "parentApprovedAt", "adoptedAt"))
    require(prepared <= created <= approved <= adopted
            and (not check_freshness or adopted <= contracts._now())
            and adopted < contracts._timestamp(document["expiresAt"]), "Invalid delegated approval/adoption time")
    require(isinstance(document["parentApprovalHash"], str)
            and contracts.SHA256.fullmatch(document["parentApprovalHash"]), "Invalid adopted approval digest")
    return document


def historical_delegated_contract(store, document):
    """Read sealed historical authority for status/terminal evidence, never calls.

    The caller must still require an existing dispatched ledger reservation for
    terminal writes. No current parent, verifier, target, or implementation is
    consulted here; those checks remain mandatory in current_delegated_contract.
    """
    require(isinstance(document, dict) and document.get("schemaVersion") in (CONTRACT_VERSION, SCOPE_CONTRACT_VERSION),
            "Expected a concrete historical delegated contract")
    identifier = contracts._identifier(document.get("id"))
    current = store.read_json("contracts", identifier + ".json")
    require(_same(current, document), "Historical delegated document changed")
    request = store.read_json("parent-requests", identifier + ".json")
    require(isinstance(request, dict) and len(canonical_bytes(request)) <= MAX_INPUT,
            "Invalid bounded historical parent request")
    scoped = request.get("schemaVersion") == SCOPE_REQUEST_VERSION
    require(request.get("schemaVersion") in (REQUEST_VERSION, SCOPE_REQUEST_VERSION)
            and set(request) == (_REQUEST_FIELDS - {"packet"} if scoped else _REQUEST_FIELDS)
            and request["id"] == identifier, "Invalid historical parent request fields")
    prepared, expires = contracts._timestamp(request["preparedAt"]), contracts._timestamp(request["expiresAt"])
    require(prepared.microsecond == 0 and prepared < expires, "Invalid historical request lifetime")
    require(request["runtimeState"] == _runtime_identity(store), "Historical runtime state identity changed")
    _identity_shape(request["runtimeState"], current_path=False)
    _parent_reference(request["parentReference"], current_paths=False)
    require(isinstance(request["policyFingerprint"], str) and contracts.SHA256.fullmatch(request["policyFingerprint"])
            and isinstance(request["requestSha256"], str) and request["requestSha256"] == request_sha256(request),
            "Historical request hash or policy identity changed")
    verifier = request["verifier"]
    require(isinstance(verifier, dict) and set(verifier) == {"python", "entrypoint", "config", "codeRoots", "codeFiles"},
            "Invalid historical verifier descriptor")
    for name in ("python", "entrypoint", "config"):
        _identity_shape(verifier[name], file=True, current_path=False)
    for name, maximum, is_file in (("codeRoots", 8, False), ("codeFiles", 1024, True)):
        pins = verifier[name]
        require(isinstance(pins, list) and 1 <= len(pins) <= maximum, "Invalid historical verifier closure")
        for pin in pins:
            _identity_shape(pin, file=is_file, current_path=False)
        paths = [pin["path"] for pin in pins]
        require(paths == sorted(set(paths)), "Historical verifier paths must be sorted and unique")
    if scoped:
        require(identifier == stable_scope_id(request["runtimeState"], request["parentReference"]),
                "Historical scope id changed")
        from scope_authority import validate_execution
        validate_execution(request["execution"], identifier, check_freshness=False, historical=True)
    else:
        packet = request["packet"]
        require(isinstance(packet, dict) and packet.get("authorityId") == identifier
                and identifier == stable_id(request["runtimeState"], request["parentReference"], packet.get("id")),
                "Historical packet authority identity changed")
        contracts.validate_execution(request["execution"], one_packet=True, check_freshness=False)
        binding = request["execution"]["taskBindings"].get(packet["id"])
        require(isinstance(binding, dict) and _same(binding, contracts._packet_binding(
            packet, binding["allowedEngines"], binding["maxRuns"])), "Historical packet binding changed")
    _validate_document(current, request, check_freshness=False)
    return copy.deepcopy(current)


def _match_parent(document, result):
    require(all(document[key] == result[key] for key in _PARENT_PINS), "Adopted parent approval identity changed")


def validate_authority_observation(value, document, *, fresh=False):
    """Validate one recorded snapshot without a filesystem read or subprocess."""
    if document.get("schemaVersion") not in (CONTRACT_VERSION, SCOPE_CONTRACT_VERSION):
        require(value is None, "Standalone authority cannot contain a parent observation")
        return None
    fields = {"protocol", "status", "requestSha256", *_PARENT_PINS, "observedAt",
              "authorizationBasis", "atomicLease"}
    require(isinstance(value, dict) and set(value) == fields and value["protocol"] == RESULT_VERSION
            and value["status"] == "verified" and value["atomicLease"] is False
            and value["authorizationBasis"] == AUTHORIZATION_BASIS,
            "Invalid recorded parent authority observation")
    require(value["requestSha256"] == document["request"]["requestSha256"],
            "Parent observation request identity changed")
    _match_parent(document, value)
    observed = contracts._timestamp(value["observedAt"])
    require(contracts._timestamp(document["parentApprovedAt"]) <= observed
            < contracts._timestamp(document["expiresAt"]), "Parent observation outside authority lifetime")
    if fresh:
        require(observed <= contracts._now(), "Parent observation is in the future")
    canonical_bytes(value)
    return value


def adopt_request(state_root, identifier, *, expected_request_sha256):
    """Adopt actual approval pins once; replay preserves the original ledger/time."""
    contracts._identifier(identifier)
    require(isinstance(expected_request_sha256, str) and contracts.SHA256.fullmatch(expected_request_sha256),
            "Exact prepared request hash is required")
    with StateStore(state_root) as store, store.locked():
        request = store.read_json("parent-requests", identifier + ".json")
        require(request.get("id") == identifier and request.get("requestSha256") == expected_request_sha256,
                "Prepared request id/hash changed")
        validate_request(request, store)
        document = _adoption_state(store, request, allow_missing=True)
        result = verify_parent(request, store)
        if document is not None:
            _match_parent(document, result)
            return copy.deepcopy(document)
        scoped = request["schemaVersion"] == SCOPE_REQUEST_VERSION
        if scoped:
            from provider_common import require_active_session
            require_active_session()
        document = {"schemaVersion": SCOPE_CONTRACT_VERSION if scoped else CONTRACT_VERSION,
                    "id": identifier, "status": "delegated",
                    "adoptedAt": contracts._now().isoformat(), "expiresAt": request["expiresAt"],
                    "policyFingerprint": request["policyFingerprint"], "execution": copy.deepcopy(request["execution"]),
                    "request": copy.deepcopy(request), **{key: result[key] for key in _PARENT_PINS}}
        _validate_document(document, request)
        from ledger import initial_ledger
        store.directory("contracts", create=True)
        store.directory("ledgers", create=True)
        if scoped:
            from scope_authority import empty_catalog
            store.directory("scoped-children", create=True)
            store.write_json("scoped-children", identifier + ".json", empty_catalog(document), expected_bytes=None)
        # A crash between writes intentionally leaves a fail-closed partial state.
        store.write_json("ledgers", identifier + ".json", initial_ledger(document), expected_bytes=None)
        store.write_json("contracts", identifier + ".json", document, expected_bytes=None)
        return copy.deepcopy(document)


def current_delegated_contract(store, document, binding=None, packet=None, *, observations=None):
    """Called under the existing StateStore lock for every load and reservation."""
    require(isinstance(document, dict) and document.get("schemaVersion") in (CONTRACT_VERSION, SCOPE_CONTRACT_VERSION),
            "Expected distinct delegated contract")
    contracts._identifier(document.get("id"))
    request = store.read_json("parent-requests", document["id"] + ".json")
    validate_request(request, store)
    current = _adoption_state(store, request, allow_missing=False)
    require(_same(current, document), "Delegated contract changed since authority load")
    if packet is not None:
        require(document["schemaVersion"] == CONTRACT_VERSION,
                "Scoped children require scoped authority validation")
        require(_same(packet, request["packet"]), "Delegated packet drift")
        actual = contracts.binding_for_packet(current, packet)
        require(binding is None or actual == binding, "Supplied delegated binding drift")
    result = verify_parent(request, store)
    _match_parent(current, result)
    if observations is not None:
        require(type(observations) is list, "Observation collector must be a local list")
        validate_authority_observation(result, current, fresh=True)
        observations.append(strict_json(canonical_bytes(result)))
    return current
