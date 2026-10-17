import io
import json
import socket
import socketserver
import sys
import tempfile
import threading
import time
import unittest

from thessley_pam_win import approve, daemon, gate, grants, machine, store

from fakephone import FakePhone, wait_for_link


class Out(io.StringIO):
    """Collects what the gate prints, readable while the gate is still running."""
    def lines(self):
        return self.getvalue().splitlines()

    def __iter__(self):  # live view for wait_for_link
        return iter(self.lines())


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._base, self._lan = store.BASE, machine.lan_ip
        store.BASE = self.tmp.name
        machine.lan_ip = lambda: "127.0.0.1"
        store.ensure_dirs()
        self.server = daemon.Server(("127.0.0.1", 0))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.address = self.server.server_address
        self.ran = []

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        machine.lan_ip = self._lan
        store.BASE = self._base
        self.tmp.cleanup()

    def run_gate(self, env=None, user="alice"):
        out, result = Out(), {}

        def work():
            def runner(cmd):
                self.ran.append(cmd)
                return 0
            result["code"] = gate.main(env=env or {"SSH_CONNECTION": "192.168.1.50 50000 192.168.1.10 22"}, out=out,
                                       address=self.address, run=runner, user=user)
        t = threading.Thread(target=work)
        t.start()
        return t, out, result

    def test_approved_login_starts_the_shell(self):
        phone = FakePhone("alice")
        t, out, result = self.run_gate()
        phone.answer(wait_for_link(out))
        t.join(20)
        self.assertEqual(result["code"], 0)
        self.assertEqual(len(self.ran), 1)
        self.assertIn("Thessley Passkey", out.getvalue())

    def test_the_command_given_to_ssh_runs_after_approval(self):
        phone = FakePhone("alice")
        t, out, result = self.run_gate({"SSH_CONNECTION": "192.168.1.50 1 2 22", "SSH_ORIGINAL_COMMAND": "dir C:\\"})
        phone.answer(wait_for_link(out))
        t.join(20)
        self.assertEqual(result["code"], 0)
        self.assertIn('dir C:\\', self.ran[0])

    def test_denied_login_never_starts_anything(self):
        phone = FakePhone("alice")
        t, out, result = self.run_gate()
        phone.answer(wait_for_link(out), "deny")
        t.join(20)
        self.assertEqual(result["code"], 1)
        self.assertEqual(self.ran, [])

    def test_unenrolled_user_is_refused_without_a_shell(self):
        t, out, result = self.run_gate(user="nobody")
        t.join(20)
        self.assertEqual(result["code"], 1)
        self.assertEqual(self.ran, [])
        self.assertIn("refused", out.getvalue().lower())

    def test_wrong_users_phone_cannot_open_the_door(self):
        FakePhone("alice")
        mallory = FakePhone("mallory")
        self._wait, approve.WAIT = approve.WAIT, 3  # nobody answers: do not sit through the real approval window
        self.addCleanup(setattr, approve, "WAIT", self._wait)
        t, out, result = self.run_gate()
        link = wait_for_link(out)
        self.assertEqual(mallory.answer(link)[0], 403)
        # nobody else answers: stop the wait early by closing from the gate's side is not possible here,
        # so shorten it through the service-side approval wait
        t.join(30)
        self.assertEqual(result["code"], 1)
        self.assertEqual(self.ran, [])

    def test_pass_second_login_needs_no_phone(self):
        grants.set_grace(4)
        phone = FakePhone("alice")
        t, out, result = self.run_gate()
        phone.answer(wait_for_link(out))
        t.join(20)
        self.assertEqual(result["code"], 0)
        t, out, result = self.run_gate()
        t.join(20)
        self.assertEqual(result["code"], 0)
        self.assertIn("approved earlier", out.getvalue())
        self.assertEqual(len(self.ran), 2)

    def test_a_pass_is_for_one_address(self):
        grants.set_grace(4)
        phone = FakePhone("alice")
        t, out, result = self.run_gate()
        phone.answer(wait_for_link(out))
        t.join(20)
        t, out, result = self.run_gate({"SSH_CONNECTION": "10.9.9.9 1 2 22"})
        link = wait_for_link(out)  # asked again
        phone.answer(link, "deny")
        t.join(20)
        self.assertEqual(result["code"], 1)

    def test_service_not_running_refuses(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        out = Out()
        code = gate.main(env={}, out=out, address=("127.0.0.1", port), run=lambda c: self.ran.append(c) or 0, user="alice")
        self.assertEqual(code, 1)
        self.assertEqual(self.ran, [])
        self.assertIn("not running", out.getvalue())

    def test_bad_ip_in_the_request_is_refused_by_the_service(self):
        with socket.create_connection(self.address) as s:
            s.sendall(b'{"op":"approve","user":"alice","rhost":"not-an-ip"}\n')
            reply = json.loads(s.makefile().readline())
        self.assertEqual(reply["ok"], False)

    def test_garbage_request_is_refused(self):
        for raw in (b"hello\n", b"[]\n", b'{"op":"other"}\n', b'{"op":"approve"}\n', b"\n"):
            with socket.create_connection(self.address) as s:
                s.sendall(raw)
                reply = json.loads(s.makefile().readline())
            self.assertEqual(reply.get("ok"), False, raw)


class WhereTheGateTalks(unittest.TestCase):
    """scp and sftp run as the command given to ssh: stdout is their data, so the gate's lines must not go there."""

    def run_main(self, env):
        out, err = Out(), Out()
        old = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            gate.main(env=env, address=("127.0.0.1", 1), run=lambda cmd: 0, user="alice")   # nothing listens: it refuses and says so
        finally:
            sys.stdout, sys.stderr = old
        return out.getvalue(), err.getvalue()

    def test_a_command_given_to_ssh_gets_the_gate_lines_on_stderr_not_stdout(self):
        out, err = self.run_main({"SSH_CONNECTION": "192.168.1.50 1 2 22", "SSH_ORIGINAL_COMMAND": "scp -t C:\\x"})
        self.assertEqual(out, "")
        self.assertIn("Thessley Passkey", err)

    def test_an_interactive_login_keeps_the_gate_lines_on_stdout(self):
        out, err = self.run_main({"SSH_CONNECTION": "192.168.1.50 1 2 22"})
        self.assertIn("Thessley Passkey", out)
        self.assertEqual(err, "")


class FakeService(socketserver.StreamRequestHandler):
    replies: list = []

    def handle(self):
        self.rfile.readline()
        for r in self.replies:
            self.wfile.write((r if isinstance(r, str) else json.dumps(r)).encode() + b"\n")


class GateTrustsOnlyAClearYes(unittest.TestCase):
    def ask(self, replies):
        FakeService.replies = replies
        srv = socketserver.TCPServer(("127.0.0.1", 0), FakeService)
        threading.Thread(target=srv.handle_request, daemon=True).start()
        try:
            return gate.ask("alice", "1.2.3.4", Out(), srv.server_address, timeout=5)
        finally:
            srv.server_close()

    def test_only_done_ok_true_passes(self):
        self.assertTrue(self.ask([{"say": "hi"}, {"done": True, "ok": True}]))

    def test_everything_else_refuses(self):
        for replies in ([{"done": True, "ok": False}], [{"done": True}], [{"done": True, "ok": "yes"}],
                        [{"done": True, "ok": 1}], [{"say": "x"}], [], ["not json"], [{"ok": True}]):
            self.assertFalse(self.ask(replies), replies)


class ShellCommands(unittest.TestCase):
    def test_interactive_and_command_forms(self):
        self.assertEqual(gate.shell_command(r"C:\Windows\System32\cmd.exe", None), r'"C:\Windows\System32\cmd.exe"')
        self.assertEqual(gate.shell_command(r"C:\Windows\System32\cmd.exe", "dir"), r'"C:\Windows\System32\cmd.exe" /s /c "dir"')
        self.assertIn("-Command", gate.shell_command(r"C:\Program Files\PowerShell\7\pwsh.exe", "Get-Date"))

    def test_client_address(self):
        self.assertEqual(gate.client_address({"SSH_CONNECTION": "1.2.3.4 5 6.7.8.9 22"}), "1.2.3.4")
        self.assertEqual(gate.client_address({}), "-")

    def test_current_user_comes_from_the_token(self):
        self.assertTrue(gate.current_user())


if __name__ == "__main__":
    unittest.main()
