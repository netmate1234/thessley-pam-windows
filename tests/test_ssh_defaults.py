"""Turning on QR approval for the local accounts: one account sshd cannot look up must not stop the others."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from thessley_pam_win import ssh_policy  # noqa: E402


class Defaults(unittest.TestCase):
    def run_defaults(self, accounts, failing):
        done = []

        def fake_set_access(name, qr, blocked, factor="native", *, restart_service=True):
            if name in failing:
                raise failing[name]
            done.append(name)
            return f"backup-{name}"

        with mock.patch.object(ssh_policy, "policies", return_value={}), \
                mock.patch.object(ssh_policy, "blocked_users", return_value=set()), \
                mock.patch.object(ssh_policy, "local_accounts", return_value=[{"name": a} for a in accounts]), \
                mock.patch.object(ssh_policy, "_paths", return_value=("cfg", "sshd")), \
                mock.patch.object(ssh_policy, "set_access", side_effect=fake_set_access), \
                mock.patch.object(ssh_policy, "_restart_sshd") as restart:
            result = ssh_policy.enable_default_policies()
        return result, done, restart

    def test_an_account_sshd_cannot_resolve_is_skipped_and_the_rest_are_done(self):
        (backup, added, skipped), done, restart = self.run_defaults(
            ["sshuser", "norab", "thessleyqrtest"], {"norab": ssh_policy.UnresolvableAccount("x")})
        self.assertEqual(added, ["sshuser", "thessleyqrtest"])
        self.assertEqual(done, ["sshuser", "thessleyqrtest"])
        self.assertEqual(backup, "backup-sshuser")
        self.assertEqual(len(skipped), 1)
        self.assertTrue(skipped[0].startswith("norab"))
        restart.assert_called_once()

    def test_a_real_failure_still_stops_everything(self):
        with self.assertRaises(RuntimeError):
            with mock.patch.object(ssh_policy.shutil, "copyfile"), mock.patch.object(ssh_policy.subprocess, "run"):
                self.run_defaults(["sshuser", "norab"], {"norab": RuntimeError("sshd rejected the updated config")})

    def test_all_accounts_unresolvable_changes_nothing_and_does_not_restart(self):
        (backup, added, skipped), done, restart = self.run_defaults(["norab"], {"norab": ssh_policy.UnresolvableAccount("x")})
        self.assertEqual((backup, added, done), (None, [], []))
        restart.assert_not_called()


if __name__ == "__main__":
    unittest.main()
