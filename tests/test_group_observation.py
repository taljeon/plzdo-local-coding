"""Deterministic owned-group exit observations; no processes or signals launched."""
import errno
import signal
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from engine_types import EngineFailure, require_cleanup
import run_bounded as runner


@pytest.fixture
def clock(monkeypatch):
    state = SimpleNamespace(seconds=0.0)

    def advance(seconds):
        assert 0 < seconds <= 0.02
        state.seconds += seconds

    monkeypatch.setattr(runner, 'time', SimpleNamespace(
        monotonic=lambda: state.seconds, sleep=advance))
    return state


def test_post_term_eperm_requires_later_reap_and_absence(monkeypatch, clock):
    process = SimpleNamespace(pid=900001, poll=Mock(return_value=-15),
                              wait=Mock(return_value=-15))
    observed = []

    def signal_group(pid, sig):
        assert pid == process.pid
        if sig == signal.SIGTERM:
            return
        if sig == 0:
            observed.append(sig)
            if len(observed) == 1:
                return  # The owned group is initially present.
            if len(observed) == 2:
                raise PermissionError(errno.EPERM, 'synthetic exit transition')
        raise ProcessLookupError(errno.ESRCH, 'synthetic group absent after reap')

    monkeypatch.setattr(runner.os, 'killpg', signal_group)
    assert runner.terminate_group(process) is True
    assert len(observed) >= 3
    process.wait.assert_called_once_with(timeout=5)
    assert 0 < clock.seconds < 0.3
    observed_before_receipt = len(observed)
    receipt = runner.process_cleanup_receipt(process)
    require_cleanup(receipt)
    assert receipt['process_reaped'] is True and receipt['group_absent'] is True
    assert len(observed) == observed_before_receipt + 1  # Fresh independent ESRCH proof.


def test_persistent_eperm_is_bounded_and_cannot_prove_cleanup(monkeypatch, clock):
    process = SimpleNamespace(pid=900002, poll=Mock(return_value=-15), wait=Mock(return_value=-15))
    signals = []

    def signal_group(pid, sig):
        assert pid == process.pid
        if sig == 0:
            raise PermissionError(errno.EPERM, 'synthetic unproven group')
        signals.append(sig)

    monkeypatch.setattr(runner.os, 'killpg', signal_group)
    assert runner.terminate_group(process) is False
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert 5.3 <= clock.seconds < 5.32
    process.wait.assert_called_once_with(timeout=5)
    receipt = runner.process_cleanup_receipt(process)
    assert receipt['process_reaped'] is True
    assert receipt['group_absent'] is False
    assert receipt['completed'] is False and receipt['passed'] is False
    with pytest.raises(EngineFailure, match='Owned cleanup has not completed'):
        require_cleanup(receipt)


@pytest.mark.parametrize('denied_signal', [signal.SIGTERM, signal.SIGKILL])
def test_termination_signal_permission_denial_still_fails_closed(monkeypatch, clock, denied_signal):
    process = SimpleNamespace(pid=900003, poll=Mock(return_value=None), wait=Mock())
    signals = []

    def signal_group(pid, sig):
        assert pid == process.pid
        signals.append(sig)
        if sig in (0, denied_signal):
            raise PermissionError(errno.EPERM, 'synthetic signal denial')

    monkeypatch.setattr(runner.os, 'killpg', signal_group)
    assert runner.terminate_group(process) is False
    assert denied_signal in signals
    assert 5.3 <= clock.seconds < 5.32
    process.wait.assert_called_once_with(timeout=5)
    assert runner.process_cleanup_receipt(process)['passed'] is False
