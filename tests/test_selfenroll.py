"""A user enrolling an approver for their own account, through the real service, without being an administrator."""

import json
import socket
from urllib.parse import parse_qs, urlsplit
import tempfile
import threading
import time
import unittest

from thessley_pam_win import daemon, gate, grants, machine, store

from fakeenroll import EnrollingPhone
from fakephone import FakePhone

ME = store.normalize_user(gate.current_user())  # the account these tests run as: the service sees it as the caller


def ipc(address, request, *, on_link=None, answer="yes", on_approval_link=None):
    """Speak to the service like the enrol command does. Returns (lines shown, final message)."""
    lines, final = [], {}
    with socket.create_connection(address, timeout=90) as s:
        s.sendall((json.dumps(request) + "\n").encode())
        f = s.makefile("rw", encoding="utf-8")
        for raw in f:
            msg = json.loads(raw)
            if "say" in msg:
                lines.append(msg["say"])
                if msg["say"].startswith("Link: thessleypam://enroll") and on_link:
                    on_link(msg["say"][len("Link: "):])
                if msg["say"].startswith("Link: thessleypam://sudo") and on_approval_link:
                    on_approval_link(msg["say"][len("Link: "):])
            if "ask" in msg:
                f.write(json.dumps({"answer": answer}) + "\n")
                f.flush()
            if msg.get("done"):
                final = msg
                break
    return lines, final


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._base, self._lan = store.BASE, machine.lan_ip
        store.BASE = self.tmp.name
        machine.lan_ip = lambda: "127.0.0.1"
        store.ensure_dirs()
        self.server = daemon.Server(("127.0.0.1", 0))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.address = self.server.server_address

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        machine.lan_ip = self._lan
        store.BASE = self._base
        self.tmp.cleanup()

    def enrol(self, user=ME, **kw):
        phone = EnrollingPhone(user)
        lines, final = ipc(self.address, {"op": "enroll", "user": user}, on_link=lambda link: phone.enroll(link), **kw)
        return phone, lines, final


class FirstApprover(Base):
    def test_first_approver_without_an_administrator(self):
        phone, lines, final = self.enrol()
        self.assertTrue(final["ok"], lines)
        status, data = phone.wait()
        self.assertEqual((status, data["result"]), (200, "ok"))
        self.assertEqual(len(store.devices(ME)), 1)
        self.assertEqual(store.devices(ME)[0]["public_key"], phone.public_key)

    def test_not_confirmed_adds_nothing(self):
        phone, lines, final = self.enrol(answer="no")
        self.assertFalse(final["ok"])
        self.assertEqual(store.devices(ME), [])
        self.assertEqual(phone.wait()[1]["result"], "denied")

    def test_a_user_can_only_enrol_for_themselves(self):
        lines, final = ipc(self.address, {"op": "enroll", "user": "somebodyelse"})
        self.assertFalse(final["ok"])
        self.assertFalse(any(l.startswith("Link:") for l in lines))
        self.assertEqual(store.devices("somebodyelse"), [])
        self.assertIn("your own account", " ".join(lines))

    def test_the_name_in_the_request_is_not_trusted_even_with_a_domain_prefix(self):
        lines, final = ipc(self.address, {"op": "enroll", "user": "OTHERPC\\somebodyelse"})
        self.assertFalse(final["ok"])
        self.assertEqual(store.devices("somebodyelse"), [])

    def test_bad_names_are_refused(self):
        for name in ("..\\..\\x", "a b", "", "a|b"):
            lines, final = ipc(self.address, {"op": "enroll", "user": name})
            self.assertFalse(final["ok"], name)

    def test_switch_off_needs_an_administrator(self):
        grants.set_self_enroll_first(False)
        lines, final = ipc(self.address, {"op": "enroll", "user": ME})
        self.assertFalse(final["ok"])
        self.assertIn("administrator", " ".join(lines))
        self.assertFalse(any(l.startswith("Link:") for l in lines))
        grants.set_self_enroll_first(True)
        self.assertTrue(grants.self_enroll_first())

    def test_a_lost_phone_does_not_reopen_first_come_enrolment(self):
        old = FakePhone(ME)
        store.set_disabled(ME, old.credential_id, True)  # an administrator switched the lost phone off
        lines, final = ipc(self.address, {"op": "enroll", "user": ME})
        self.assertFalse(final["ok"])
        self.assertIn("switched off", " ".join(lines))
        self.assertFalse(any(l.startswith("Link:") for l in lines))
        self.assertEqual(len(store.devices(ME)), 1)

    def test_only_one_enrolment_per_account_at_a_time(self):
        first = EnrollingPhone(ME)
        started = threading.Event()
        result = {}

        def delayed(link):
            started.set()
            time.sleep(2)
            first.enroll(link)

        def run_first():
            result["out"] = ipc(self.address, {"op": "enroll", "user": ME}, on_link=delayed)
        t = threading.Thread(target=run_first)
        t.start()
        self.assertTrue(started.wait(10))
        lines, final = ipc(self.address, {"op": "enroll", "user": ME})
        self.assertFalse(final["ok"])
        self.assertIn("already running", " ".join(lines))
        t.join(60)
        self.assertTrue(result["out"][1]["ok"])


class MoreApprovers(Base):
    def setUp(self):
        super().setUp()
        self.old = FakePhone(ME, "Old phone")

    def test_needs_an_approval_from_an_enrolled_approver(self):
        phone = EnrollingPhone(ME, "Second phone")
        approval_links = []

        def approve_it(link):
            approval_links.append(link)
            self.old.answer(link)
        lines, final = ipc(self.address, {"op": "enroll", "user": ME}, on_link=lambda l: phone.enroll(l),
                           on_approval_link=approve_it)
        self.assertTrue(final["ok"], lines)
        self.assertEqual(len(store.devices(ME)), 2)
        # the apps are told what is being approved: same service name as thessley-pam-linux, no client address
        q = {k: v[0] for k, v in parse_qs(urlsplit(approval_links[0]).query).items()}
        self.assertEqual((q["s"], q["tty"]), ("thessley-enroll", "add-device"))
        self.assertNotIn("r", q)
        self.assertIn("adding a device", " ".join(lines))
        self.assertEqual(phone.wait()[1]["result"], "ok")

    def test_denied_by_the_enrolled_approver_adds_nothing_and_shows_no_enrol_link(self):
        lines, final = ipc(self.address, {"op": "enroll", "user": ME}, on_approval_link=lambda l: self.old.answer(l, "deny"))
        self.assertFalse(final["ok"])
        self.assertFalse(any(l.startswith("Link: thessleypam://enroll") for l in lines))
        self.assertEqual(len(store.devices(ME)), 1)

    def test_a_pass_does_not_stand_in_for_the_approval_and_none_is_created(self):
        grants.set_grace(4)
        grants.add(ME, grants.LOCAL, 4, self.old.credential_id)  # a live pass for exactly this situation
        before = grants.all_passes()
        phone = EnrollingPhone(ME)
        asked = []

        def approve_it(link):
            asked.append(link)
            self.old.answer(link)
        lines, final = ipc(self.address, {"op": "enroll", "user": ME}, on_link=lambda l: phone.enroll(l),
                           on_approval_link=approve_it)
        self.assertTrue(asked, "the pass was used instead of asking the approver")
        self.assertTrue(final["ok"], lines)
        self.assertEqual(grants.all_passes(), before)

    def test_closing_the_terminal_adds_nothing(self):
        s = socket.create_connection(self.address, timeout=10)
        s.sendall((json.dumps({"op": "enroll", "user": ME}) + "\n").encode())
        f = s.makefile("r", encoding="utf-8")
        for raw in f:
            if json.loads(raw).get("say", "").startswith("Link: thessleypam://sudo"):
                break
        s.close()  # the user closes the terminal while the approval is waiting
        time.sleep(3)
        self.assertEqual(len(store.devices(ME)), 1)


if __name__ == "__main__":
    unittest.main()
