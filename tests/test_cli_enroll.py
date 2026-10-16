"""The enrol command as a normal user, against a test service (never the real one on port 47800)."""

import contextlib
import io
import tempfile
import threading
import time
import unittest

from thessley_pam_win import cli, daemon, gate, machine, store

from fakeenroll import EnrollingPhone

ME = store.normalize_user(gate.current_user())


class Live(io.StringIO):
    """What the command prints, readable while it is still running."""
    def text(self):
        return self.getvalue()


class CliEnroll(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = (store.BASE, machine.lan_ip, cli.PORT, cli._is_admin, cli._ask_yes)
        store.BASE = self.tmp.name
        machine.lan_ip = lambda: "127.0.0.1"
        store.ensure_dirs()
        self.server = daemon.Server(("127.0.0.1", 0))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        cli.PORT = self.server.server_address[1]
        cli._is_admin = lambda: False          # a normal user, as the point of this feature
        cli._ask_yes = lambda prompt, timeout: True

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        store.BASE, machine.lan_ip, cli.PORT, cli._is_admin, cli._ask_yes = self._saved
        self.tmp.cleanup()

    def run_cli(self, argv, phone=None):
        out, result = Live(), {}

        def work():
            with contextlib.redirect_stdout(out):
                try:
                    result["code"] = cli.main(argv)
                except SystemExit as e:
                    result["code"] = e.code
        t = threading.Thread(target=work)
        t.start()
        if phone:
            end = time.monotonic() + 20
            while time.monotonic() < end:
                link = next((l[len("Link: "):] for l in out.text().splitlines() if l.startswith("Link: thessleypam://enroll")), None)
                if link:
                    phone.enroll(link)
                    break
                time.sleep(0.1)
        t.join(60)
        return out.text(), result.get("code")

    def test_a_normal_user_enrols_their_own_phone(self):
        phone = EnrollingPhone(ME)
        text, code = self.run_cli(["enroll"], phone)
        self.assertEqual(code, 0, text)
        self.assertIn("Added", text)
        self.assertEqual(len(store.devices(ME)), 1)
        self.assertGreater(len([l for l in text.splitlines() if "█" in l or "▀" in l]), 10)  # the QR code

    def test_a_normal_user_cannot_name_another_account(self):
        text, code = self.run_cli(["enroll", "--user", "somebodyelse"])
        self.assertNotEqual(code, 0)
        self.assertEqual(store.devices("somebodyelse"), [])

    def test_naming_yourself_is_fine(self):
        phone = EnrollingPhone(ME)
        text, code = self.run_cli(["enroll", "--user", ME], phone)
        self.assertEqual(code, 0, text)

    def test_declining_the_code_adds_nothing(self):
        cli._ask_yes = lambda prompt, timeout: False
        phone = EnrollingPhone(ME)
        text, code = self.run_cli(["enroll"], phone)
        self.assertEqual(code, 1)
        self.assertEqual(store.devices(ME), [])

    def test_an_administrator_terminal_prints_the_link_without_a_flag(self):
        """As in thessley-pam-linux: the link is always printed, above the QR code (for the desktop app, or a phone that
        cannot scan the screen). The old --link flag is still accepted."""
        for argv in (["enroll"], ["enroll", "--link"]):
            cli._is_admin = lambda: True       # an administrator terminal: runs in this process, not through the service
            phone = EnrollingPhone(ME)
            text, code = self.run_cli(argv, phone)
            self.assertEqual(code, 0, text)
            lines = text.splitlines()
            link_at = next(i for i, l in enumerate(lines) if l.startswith("Link: thessleypam://enroll"))
            qr_at = next(i for i, l in enumerate(lines) if "\u2588" in l or "\u2580" in l)
            self.assertLess(link_at, qr_at, "the link comes above the QR code")
            for d in store.devices(ME):          # keep the next round independent
                store.remove_device(ME, d["credential_id"])

    def test_service_not_running_says_so(self):
        self.server.shutdown()
        self.server.server_close()
        text, code = self.run_cli(["enroll"])
        self.assertEqual(code, 1)
        self.assertIn("not running", text)

    def test_other_commands_still_need_an_administrator(self):
        for argv in (["list"], ["remove", "--user", ME, "c_x"], ["grace", "--hours", "4"], ["self-enroll", "off"], ["passes"]):
            text, code = self.run_cli(argv)
            self.assertNotEqual(code, 0, argv)


if __name__ == "__main__":
    unittest.main()
