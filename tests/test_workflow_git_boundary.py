"""No inherited Git authority or implicit fetch before candidate checks."""
import os
from types import SimpleNamespace

import workflow_core as core


def test_packet_git_read_has_clean_environment_and_no_transports(monkeypatch, tmp_path):
    for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0',
                'GIT_CONFIG_VALUE_0', 'GIT_EXEC_PATH', 'GIT_SSH_COMMAND', 'GIT_GRAFT_FILE',
                'GIT_CONFIG_SYSTEM', 'GIT_ATTR_SOURCE', 'PYTHONPATH'):
        monkeypatch.setenv(key, 'untrusted-fixture')
    observed = {}
    def run(argv, **kwargs):
        observed.update(argv=argv, **kwargs)
        return SimpleNamespace(returncode=0, stdout=b'fixture', stderr=b'')
    monkeypatch.setattr(core.subprocess, 'run', run)
    assert core._git(tmp_path, 'cat-file', '-s', 'a' * 40 + ':result.txt') == b'fixture'
    environment = observed['env']
    assert environment['PATH'] == os.defpath
    assert environment['GIT_GRAFT_FILE'] == '/dev/null'
    assert environment['GIT_ALLOW_PROTOCOL'] == ''
    assert environment['GIT_NO_LAZY_FETCH'] == environment['GIT_NO_REPLACE_OBJECTS'] == '1'
    assert not any(value == 'untrusted-fixture' for value in environment.values())
    assert 'protocol.allow=never' in observed['argv']
    assert 'protocol.file.allow=always' not in observed['argv']
    assert '--no-replace-objects' in observed['argv']


def test_only_explicit_candidate_clone_allows_local_file_transport(monkeypatch, tmp_path):
    calls, environments = [], []
    def run(argv, **kwargs):
        calls.append(argv)
        environments.append(kwargs['env'])
        return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')
    monkeypatch.setattr(core.subprocess, 'run', run)
    core._git(tmp_path, 'clone', '--no-local', '--', '/source', '/candidate')
    core._git(tmp_path, 'checkout', '--detach', 'a' * 40)
    assert all('protocol.allow=never' in argv for argv in calls)
    assert 'protocol.file.allow=always' in calls[0]
    assert 'protocol.file.allow=always' not in calls[1]
    assert [env['GIT_ALLOW_PROTOCOL'] for env in environments] == ['file', '']
