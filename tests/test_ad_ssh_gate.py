import io
import json
import socket
import socketserver
import threading
import unittest
from unittest import mock

from thessley_pam_win import ad_ssh_gate, daemon, grants

SID = "S-1-5-21-1-2-3-1001"
ENV = {"SSH_CONNECTION": "192.168.1.50 1 2 22"}


class Recorder(socketserver.StreamRequestHandler):
    """Stands in for the approval service: records the request and answers with `reply`."""
    requests: list = []
    reply: dict = {"done": True, "ok": True}

    def handle(self):
        type(self).requests.append(json.loads(self.rfile.readline()))
        self.wfile.write(json.dumps(self.reply).encode() + b"\n")


class GateWithoutATerminal(unittest.TestCase):
    def run_gate(self, env, reply=None):
        Recorder.requests = []
        Recorder.reply = reply or {"done": True, "ok": True}
        srv = socketserver.TCPServer(("127.0.0.1", 0), Recorder)
        threading.Thread(target=srv.handle_request, daemon=True).start()
        started, out = [], io.StringIO()
        try:
            with mock.patch.object(ad_ssh_gate.gate, "default_shell", return_value=r"C:\Windows\System32\cmd.exe"):
                code = ad_ssh_gate.main(env, out, srv.server_address, run=lambda cmd: started.append(cmd) or 0, sid=SID)
        finally:
            srv.server_close()
        return code, started, out.getvalue()

    def test_scp_without_a_terminal_asks_the_service_for_a_pass_only(self):
        code, started, _ = self.run_gate({**ENV, "SSH_ORIGINAL_COMMAND": "scp -v -t C:/Users/martin/x.txt"})
        self.assertEqual(code, 0)
        self.assertEqual(len(started), 1)
        self.assertEqual(Recorder.requests[0]["pass_only"], True)

    def test_scp_without_a_valid_pass_starts_nothing(self):
        code, started, _ = self.run_gate({**ENV, "SSH_ORIGINAL_COMMAND": "scp -t x"}, {"done": True, "ok": False})
        self.assertEqual(code, 1)
        self.assertEqual(started, [])

    def test_a_terminal_login_still_asks_for_a_full_approval(self):
        code, started, _ = self.run_gate({**ENV, "SSH_TTY": "/dev/pty0"})
        self.assertEqual(code, 0)
        self.assertNotIn("pass_only", Recorder.requests[0])

    def test_other_commands_without_a_terminal_are_refused_before_the_service(self):
        for original in ("", "dir C:\\", "powershell -c whoami", "internal-sftp", "sftp-server.exe & calc",
                         "sftp-server.exe; id", "sftp-server.exe C:\\evil.exe", "scp -t x & calc", "scp -t x; id",
                         "scp -t $(id)", "scp -t x | more", "scp -t x\r\ncalc", "scp x y", "scpx -t y"):
            code, started, out = self.run_gate({**ENV, "SSH_ORIGINAL_COMMAND": original})
            self.assertEqual(code, 1, original)
            self.assertEqual(started, [], original)
            self.assertEqual(Recorder.requests, [], original)
            self.assertIn("interactive terminal", out, original)

    def test_sftp_without_a_terminal_asks_the_service_for_a_pass_only(self):
        for original in ("sftp-server.exe", "sftp-server", "sftp-server.exe -l INFO"):
            code, started, _ = self.run_gate({**ENV, "SSH_ORIGINAL_COMMAND": original})
            self.assertEqual(code, 0, original)
            self.assertEqual(len(started), 1, original)
            self.assertIn(original, started[0])
            self.assertEqual(Recorder.requests[0]["pass_only"], True)

    def test_sftp_without_a_valid_pass_starts_nothing(self):
        code, started, _ = self.run_gate({**ENV, "SSH_ORIGINAL_COMMAND": "sftp-server.exe"}, {"done": True, "ok": False})
        self.assertEqual(code, 1)
        self.assertEqual(started, [])

    def test_sftp_in_a_terminal_session_is_refused(self):
        code, started, out = self.run_gate({**ENV, "SSH_TTY": "/dev/pty0", "SSH_ORIGINAL_COMMAND": "sftp-server.exe"})
        self.assertEqual(code, 1)
        self.assertEqual(started, [])
        self.assertEqual(Recorder.requests, [])
        self.assertIn("SFTP", out)

    def test_scp_remote_commands_are_recognised(self):
        for original in ("scp -t x", "scp -f x", "scp -v -t x", "scp -r -d -t C:/Users/martin/", "scp.exe -t x",
                         'scp -t "C:/Program Files (x86)/x"', "SCP -t x"):
            self.assertTrue(ad_ssh_gate.is_scp_command(original), original)


class ServiceSide(unittest.TestCase):
    def handler(self):
        h = object.__new__(daemon.Handler) if hasattr(daemon, "Handler") else None
        self.assertIsNotNone(h, "daemon handler class not found")
        h.connection = mock.Mock()
        h.client_address = ("127.0.0.1", 1)
        h.server = mock.Mock(server_address=("127.0.0.1", 47800))
        h.sent = []
        h._send = lambda msg: h.sent.append(msg) or True
        return h

    def run_service(self, grace, held):
        h = self.handler()
        principal = {"authorized": True, "principal_id": "p1", "authority": "LAB", "username": "martin"}
        ident = {"sid": SID, "sid_type": 1, "authority": "LAB"}
        with mock.patch.object(daemon.peer, "client_identity", return_value=ident), \
                mock.patch.object(daemon.ad_agent, "configured", return_value=True), \
                mock.patch.object(daemon.ad_agent, "resolve_principal", return_value=principal), \
                mock.patch.object(daemon.ad_agent, "phone_keys", return_value=[{"credential_id": "c1", "principal_id": "p1"}]), \
                mock.patch.object(daemon.ad_agent, "start_login") as start, \
                mock.patch.object(daemon.grants, "grace_hours", return_value=grace), \
                mock.patch.object(daemon.grants, "grace_any_ip", return_value=False), \
                mock.patch.object(daemon.grants, "valid", return_value=held), \
                mock.patch.object(daemon.grants, "remaining", return_value="9 min"):
            ok = h._ad_ssh_approve(SID, "192.168.1.50", threading.Event(), pass_only=True)
        return ok, start, h.sent

    def test_a_valid_pass_covers_scp(self):
        ok, start, _ = self.run_service(1.0, {"credential": "c1"})
        self.assertTrue(ok)
        start.assert_not_called()

    def test_no_pass_refuses_scp_without_a_phone_request(self):
        ok, start, sent = self.run_service(1.0, None)
        self.assertFalse(ok)
        start.assert_not_called()
        self.assertIn("ssh -tt", sent[0]["say"])

    def test_passes_switched_off_refuses_scp(self):
        ok, start, sent = self.run_service(0, None)
        self.assertFalse(ok)
        start.assert_not_called()
        self.assertIn("switched off", sent[0]["say"])


if __name__ == "__main__":
    unittest.main()
