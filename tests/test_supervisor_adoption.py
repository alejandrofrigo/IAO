import unittest
from unittest.mock import patch

from tools import iao_five_motor_supervisor as supervisor


class AdoptedProcessTests(unittest.TestCase):
    def make_process(self):
        return supervisor.AdoptedProcess(
            43210, ["python", "tools/example_motor.py"], 123456
        )

    def test_dead_pid_is_reported_as_exited(self):
        proc = self.make_process()
        with patch.object(supervisor, "process_alive", return_value=False):
            self.assertEqual(proc.poll(), 255)
        self.assertEqual(proc.identity_status, "PROCESS_GONE")

    def test_temporary_starttime_read_failure_does_not_report_exit(self):
        proc = self.make_process()
        with (
            patch.object(supervisor, "process_alive", return_value=True),
            patch.object(supervisor, "proc_starttime", return_value=None),
        ):
            self.assertIsNone(proc.poll())
        self.assertEqual(proc.identity_status, "STARTTIME_UNAVAILABLE")

    def test_changed_starttime_does_not_report_exit(self):
        proc = self.make_process()
        with (
            patch.object(supervisor, "process_alive", return_value=True),
            patch.object(supervisor, "proc_starttime", return_value=999999),
        ):
            self.assertIsNone(proc.poll())
        self.assertEqual(proc.identity_status, "PID_REUSED_OR_CHANGED")

    def test_command_mismatch_does_not_report_exit(self):
        proc = self.make_process()
        with (
            patch.object(supervisor, "process_alive", return_value=True),
            patch.object(supervisor, "proc_starttime", return_value=123456),
            patch.object(supervisor, "process_matches", return_value=False),
        ):
            self.assertIsNone(proc.poll())
        self.assertEqual(proc.identity_status, "COMMAND_UNVERIFIED")

    def test_process_group_mismatch_does_not_report_exit(self):
        proc = self.make_process()
        with (
            patch.object(supervisor, "process_alive", return_value=True),
            patch.object(supervisor, "proc_starttime", return_value=123456),
            patch.object(supervisor, "process_matches", return_value=True),
            patch.object(supervisor.os, "getpgid", return_value=99999),
        ):
            self.assertIsNone(proc.poll())
        self.assertEqual(proc.identity_status, "PROCESS_GROUP_UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
