import subprocess

from tools.iao_autonomy_daemon import stop_child


class FakeProcess:
    def __init__(self, timeout=False):
        self.returncode = None
        self.terminated = False
        self.killed = False
        self.timeout = timeout
        self.wait_calls = 0

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        if not self.timeout:
            self.returncode = 0

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.timeout and not self.killed:
            raise subprocess.TimeoutExpired("fake", timeout)
        return self.returncode


def test_stop_child_terminates_gracefully():
    process = FakeProcess()
    stop_child(process)
    assert process.terminated
    assert not process.killed
    assert process.returncode == 0


def test_stop_child_kills_after_timeout():
    process = FakeProcess(timeout=True)
    stop_child(process, timeout=1)
    assert process.terminated
    assert process.killed
    assert process.returncode == -9


def test_stop_child_ignores_already_exited_process():
    process = FakeProcess()
    process.returncode = 0
    stop_child(process)
    assert not process.terminated
    assert not process.killed
