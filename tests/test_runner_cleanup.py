"""Actual tiny offline subprocesses and synthetic cleanup observations only."""
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from engine_types import require_cleanup
import run_bounded as runner
import workflow_core as core
import ollama_engine as ollama


def test_finished_child_has_explicit_initial_group_cleanup(tmp_path):
    summary = runner.run([sys.executable, '-I', '-S', '-c', 'print("fixture")'], tmp_path, tmp_path / 'done', 5,
                         env_allowlist=(), pipe_output=True)
    cleanup = summary['cleanup']
    require_cleanup(cleanup)
    assert cleanup['owned'] is True and cleanup['started'] is True
    assert cleanup['process_reaped'] is True and cleanup['group_absent'] is True
    assert cleanup['scope'] == 'initial-posix-process-group'
    assert cleanup['detached_descendants_verified'] is False
    assert core.check_execution_receipt(summary, tmp_path / 'done')['passed'] is True


def test_failed_spawn_records_no_start_without_execution_success(tmp_path):
    summary = runner.run([str(tmp_path / 'missing-executable')], tmp_path, tmp_path / 'failed', 5,
                         env_allowlist=(), pipe_output=True)
    assert summary['return_code'] == 127 and summary['error']
    require_cleanup(summary['cleanup'])
    assert summary['cleanup']['started'] is False and summary['cleanup']['owned'] is False
    assert core.check_execution_receipt(summary, tmp_path / 'failed')['passed'] is False


def test_timeout_reaps_child_and_records_cleanup(tmp_path):
    summary = runner.run([sys.executable, '-I', '-S', '-c', 'import time;time.sleep(5)'],
                         tmp_path, tmp_path / 'timeout', 0.15, env_allowlist=(), pipe_output=True)
    assert summary['timed_out'] is True and summary['return_code'] == 124
    require_cleanup(summary['cleanup'])
    assert summary['cleanup']['group_absent'] is True
    assert core.check_execution_receipt(summary, tmp_path / 'timeout')['passed'] is False


def test_existing_group_and_observation_error_cannot_claim_cleanup(monkeypatch):
    process = SimpleNamespace(pid=999999, poll=lambda: 0)
    monkeypatch.setattr(runner, 'group_exists', lambda pid: True)
    assert runner.process_cleanup_receipt(process)['passed'] is False
    def denied(pid):
        raise PermissionError('Synthetic observation failure')
    monkeypatch.setattr(runner, 'group_exists', denied)
    receipt = runner.process_cleanup_receipt(process)
    assert receipt['completed'] is False and receipt['passed'] is False
    assert receipt['error_type'] == 'PermissionError'


def test_omitted_process_cleanup_is_not_a_successful_checker_receipt(tmp_path):
    summary = runner.run([sys.executable, '-I', '-S', '-c', 'pass'], tmp_path, tmp_path / 'evidence', 5,
                         env_allowlist=(), pipe_output=True)
    del summary['cleanup']
    (tmp_path / 'evidence' / 'summary.json').write_text(json.dumps(summary))
    receipt = core.check_execution_receipt(summary, tmp_path / 'evidence')
    assert receipt['passed'] is False
    assert 'CHECK_PROCESS_CLEANUP_UNPROVEN' in receipt['diagnostic_codes']


def test_generation_helper_startup_ignores_site_and_pythonpath(tmp_path):
    marker = tmp_path / 'injected-startup'
    (tmp_path / 'sitecustomize.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
    env = {**os.environ, 'PYTHONPATH': str(tmp_path), 'PYTHONSTARTUP': str(tmp_path / 'sitecustomize.py')}
    command = ollama._generation_command('generate_stream.py', '--help')
    completed = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
    assert '--profile' in completed.stdout
    assert not marker.exists()


def test_model_slot_is_exclusive_across_processes(tmp_path, monkeypatch):
    import composition
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    monkeypatch.setattr(composition, 'current_state_root', lambda: state)
    path = state / 'runs' / '.local-model.lock'
    code = 'import fcntl,sys; f=open(sys.argv[1],"a+"); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)'
    command = [sys.executable, '-I', '-S', '-B', '-c', code, str(path)]
    with ollama.local_model_slot(1) as verify:
        verify()
        held = subprocess.run(command, capture_output=True, timeout=3)
        assert held.returncode != 0
    released = subprocess.run(command, capture_output=True, timeout=3)
    assert released.returncode == 0


def test_model_slot_identity_replacement_is_detected(tmp_path, monkeypatch):
    import composition
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    monkeypatch.setattr(composition, 'current_state_root', lambda: state)
    with ollama.local_model_slot(1) as verify:
        path = state / 'runs' / '.local-model.lock'
        path.unlink()
        path.write_text('')
        path.chmod(0o600)
        with pytest.raises(ollama.ContractError, match='identity changed'):
            verify()
