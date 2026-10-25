"""Rollback status must follow Task Scheduler when tasks appear or expire."""
import subprocess
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
