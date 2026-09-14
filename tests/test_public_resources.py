"""Installed-resource and explicit nonhistorical Node policy boundaries."""
import hashlib
import json
from pathlib import Path

import host_paths
import workflow_core




def test_explicit_nonhistorical_node_needs_only_exact_file_grants(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    node = root / 'node-prefix/bin/node'
    node.parent.mkdir(parents=True)
    node.write_bytes(b'synthetic Node identity; never executed')
    node.chmod(0o700)
    library = root / 'node-prefix/lib/loader.dylib'
    library.parent.mkdir()
    library.write_bytes(b'synthetic library; never loaded')
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    policy = root / 'runtime-policy.json'
    policy.write_text(json.dumps({'schema': 'local-coding-runtime.v1',
        'executables': [{'command': 'node', 'path': str(node), 'sha256': sha(node)}],
        'read_files': [{'path': str(library), 'sha256': sha(library)}]}))
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY', str(policy))
    monkeypatch.setenv('LOCAL_CODING_RUNTIME_POLICY_SHA256', sha(policy))
    monkeypatch.setenv('LOCAL_CODING_STATE_ROOT', str(root / 'private-state'))
    argv, executable = workflow_core.prepare_check_command(['node', '--check', 'code.js'])
    assert argv == [str(node), '--check', 'code.js']
    assert executable == str(node)
    candidate, scratch = root / 'candidate', root / 'scratch'
    candidate.mkdir()
    scratch.mkdir()
    result = workflow_core.build_permission_state(candidate, [], scratch, runtime_executable=executable)
    entries = result['permissionProfile']['file_system']['entries']
    reads = {entry['path'].get('path') for entry in entries if entry['access'] == 'read'}
    assert str(node) in reads and str(library) in reads
    assert str(node.parent) not in reads and str(library.parent) not in reads
    assert result['permissionProfile']['network'] == 'restricted'
