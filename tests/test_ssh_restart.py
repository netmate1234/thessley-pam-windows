"""Installing over ssh: sshd is restarted later (not under the running session), and a half-written block gives a way out."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from thessley_pam_win import ssh_policy  # noqa: E402


class SshRestart(unittest.TestCase):
    def test_inside_ssh_session_is_detected_from_the_environment(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(ssh_policy.inside_ssh_session())
        for var in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"):
            with mock.patch.dict(os.environ, {var: "x"}, clear=True):
                self.assertTrue(ssh_policy.inside_ssh_session(), var)

    def test_restart_inside_ssh_is_scheduled_not_done_now(self):
        done = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.dict(os.environ, {"SSH_CONNECTION": "1.2.3.4 5 6.7.8.9 22"}, clear=True), \
                mock.patch.object(ssh_policy.subprocess, "run", return_value=done) as run:
            ssh_policy._restart_sshd()
        self.assertEqual(run.call_count, 1)
        argv = run.call_args[0][0]
        self.assertEqual(argv[:2], ["schtasks", "/Create"])
        self.assertIn("SYSTEM", argv)
        self.assertTrue(any("Restart-Service sshd" in a for a in argv))  # the restart is inside the task, not run here
        self.assertRegex(argv[argv.index("/ST") + 1], r"^\d\d:\d\d$")

    def test_restart_outside_ssh_is_immediate(self):
        done = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(ssh_policy.subprocess, "run", return_value=done) as run:
            ssh_policy._restart_sshd()
        self.assertEqual(run.call_args[0][0][0], "powershell.exe")

    def test_scheduling_failure_is_an_error_not_silence(self):
        failed = mock.Mock(returncode=1, stdout="", stderr="denied")
        with mock.patch.object(ssh_policy.subprocess, "run", return_value=failed):
            with self.assertRaises(RuntimeError):
                ssh_policy._restart_sshd_later()

    def test_half_written_block_message_names_the_line_and_the_way_out(self):
        lines = ["Port 22", "# BEGIN THESSLEY SSH QR USER norab", "Match Group administrators"]
        with self.assertRaises(RuntimeError) as ctx:
            ssh_policy._remove_block(lines, "# BEGIN THESSLEY SSH QR USER norab", "# END THESSLEY SSH QR USER norab", "SSH QR policy for norab")
        msg = str(ctx.exception)
        self.assertIn("# BEGIN THESSLEY SSH QR USER norab", msg)
        self.assertIn("remove-for-reinstall", msg)
        self.assertEqual(lines[1], "# BEGIN THESSLEY SSH QR USER norab")  # nothing was changed


if __name__ == "__main__":
    unittest.main()
