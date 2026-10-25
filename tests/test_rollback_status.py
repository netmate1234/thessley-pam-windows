"""Rollback status must follow Task Scheduler when tasks appear or expire."""
import subprocess
import pytest
from unittest.mock import patch

from thessley_pam_win import web


def test_new_rollback_is_found_after_an_empty_cache_expires():
    result = subprocess.CompletedProcess([], 0, '"\\ThessleyCredentialProviderRollback","future","Ready"\n')
    with patch.object(web, "_ROLLBACK_CACHE", (10.0, [])), \
            patch.object(web.time, "monotonic", return_value=20.0), \
            patch.object(web.subprocess, "run", return_value=result) as query:
        assert web.setup_rollback_tasks() == ["ThessleyCredentialProviderRollback"]
        query.assert_called_once()


def test_expired_task_disappears_after_cache_expiry():
    result = subprocess.CompletedProcess([], 0, '"\\UnrelatedTask","future","Ready"\n')
    with patch.object(web, "_ROLLBACK_CACHE", (10.0, ["ThessleyCredentialProviderRollback"])), \
            patch.object(web.time, "monotonic", return_value=30.0), \
            patch.object(web.subprocess, "run", return_value=result):
        assert web.setup_rollback_tasks() == []


def test_fresh_cache_does_not_launch_another_scheduler_query():
    with patch.object(web, "_ROLLBACK_CACHE", (10.0, ["ThessleyCredentialProviderRollback"])), \
            patch.object(web.time, "monotonic", return_value=11.0), \
            patch.object(web.subprocess, "run") as query:
        assert web.setup_rollback_tasks() == ["ThessleyCredentialProviderRollback"]
        query.assert_not_called()


def test_failed_scheduler_query_is_reported_as_unavailable():
    with patch.object(web, "_ROLLBACK_CACHE", (10.0, [])), \
            patch.object(web.time, "monotonic", return_value=20.0), \
            patch.object(web.subprocess, "run", side_effect=subprocess.TimeoutExpired("schtasks", 15)):
        assert web.setup_rollback_tasks() is None


def test_confirmation_timeout_checks_whether_cancellation_completed():
    with patch.object(web.os.path, "isfile", return_value=True), \
            patch.object(web.subprocess, "run", side_effect=subprocess.TimeoutExpired("powershell", 45)), \
            patch.object(web, "setup_rollback_tasks", return_value=[]) as status:
        assert "Setup confirmed" in web.cancel_setup_rollback_tasks()
        status.assert_called_once_with(refresh=True)


def test_confirmation_timeout_reports_a_remaining_timer():
    with patch.object(web.os.path, "isfile", return_value=True), \
            patch.object(web.subprocess, "run", side_effect=subprocess.TimeoutExpired("powershell", 45)), \
            patch.object(web, "setup_rollback_tasks", return_value=["ThessleyCredentialProviderRollback"]):
        with pytest.raises(RuntimeError, match="still pending"):
            web.cancel_setup_rollback_tasks()


def test_successful_command_does_not_claim_success_when_timer_remains():
    with patch.object(web.os.path, "isfile", return_value=True), \
            patch.object(web.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "done", "")), \
            patch.object(web, "setup_rollback_tasks", return_value=["ThessleyCredentialProviderRollback"]):
        with pytest.raises(RuntimeError, match="not been fully confirmed"):
            web.cancel_setup_rollback_tasks()


def test_successful_confirmation_verifies_timer_absence():
    with patch.object(web.os.path, "isfile", return_value=True), \
            patch.object(web.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "Timers cancelled.", "")), \
            patch.object(web, "setup_rollback_tasks", return_value=[]) as status:
        assert web.cancel_setup_rollback_tasks() == "Timers cancelled."
        status.assert_called_once_with(refresh=True)


@pytest.mark.parametrize('tasks,label', [
    (["ThessleySSHConfigRollback-Setup"], "SSH login setup recovery"),
    (["ThessleyCredentialProviderRollback"], "Windows sign-in tile recovery"),
])
def test_admin_distinguishes_the_login_method_being_protected(tmp_path, tasks, label):
    with patch.object(web.store, 'BASE', str(tmp_path)), \
            patch.object(web, 'setup_rollback_tasks', return_value=tasks), \
            patch.object(web.ssh_policy, 'local_accounts', return_value=[]), \
            patch.object(web.ssh_policy, 'policies', return_value={}), \
            patch.object(web.ssh_policy, 'custom_match_users', return_value=set()), \
            patch.object(web.ssh_policy, 'blocked_users', return_value=set()), \
            patch.object(web.machine, 'interface_networks', return_value=[]), \
            patch.object(web.machine, 'lan_ip', return_value='127.0.0.1'), \
            patch.object(web.update_task, 'last_run', return_value={}):
        body = web.admin_page(web.Session('martin', 15), '')
        assert '<strong>Setup rollback</strong>' in body
        assert label in body
        assert tasks[0] in body
        assert 'Keep setup and stop rollback' in body
