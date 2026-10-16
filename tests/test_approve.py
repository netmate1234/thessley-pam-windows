import tempfile
import threading
import time
import unittest

from thessley_pam_win import approve, grants, store

from fakephone import FakePhone, wait_for_link

IP = "127.0.0.1"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._base = store.BASE
        store.BASE = self.tmp.name
        self.lines: list[str] = []
        self.logs: list[tuple[str, bool]] = []

    def tearDown(self):
        store.BASE = self._base
        self.tmp.cleanup()

    def start(self, user="alice", rhost="192.168.1.50", wait=15, port=47850):
        result = {}

        def work():
            result["ok"] = approve.run(user, rhost, "ssh", self.lines.append, lambda m, w=False: self.logs.append((m, w)),
                                       ip=IP, port=port, wait=wait)
        t = threading.Thread(target=work)
        t.start()
        return t, result


class ApproveTests(Base):
    def test_approve(self):
        phone = FakePhone("alice")
        t, result = self.start()
        status, data = phone.answer(wait_for_link(self.lines))
        t.join(20)
        self.assertEqual((status, data["result"]), (200, "ok"))
        self.assertTrue(result["ok"])
        self.assertTrue(store.devices("alice")[0]["last_used"])

    def test_link_and_qr_are_shown(self):
        phone = FakePhone("alice")
        t, result = self.start()
        link = wait_for_link(self.lines)
        self.assertTrue(link.startswith("thessleypam://sudo?"))
        end = time.monotonic() + 10
        while not any("Waiting for the approval" in l for l in self.lines) and time.monotonic() < end:
            time.sleep(0.05)  # the link line comes first, the QR code after it
        self.assertGreater(len([l for l in self.lines if "█" in l or "▀" in l or "▄" in l]), 10)
        phone.answer(link, "deny")
        t.join(20)

    def test_deny(self):
        phone = FakePhone("alice")
        t, result = self.start()
        phone.answer(wait_for_link(self.lines), "deny")
        t.join(20)
        self.assertFalse(result["ok"])
        self.assertIn("denied", " ".join(self.lines).lower())

    def test_bad_signature_is_ignored_and_the_real_answer_still_works(self):
        phone = FakePhone("alice")
        t, result = self.start()
        link = wait_for_link(self.lines)
        status, _ = phone.answer(link, "approve", tamper=True)  # signed as "deny", sent as "approve"
        self.assertEqual(status, 400)
        status, _ = phone.answer(link, "approve")
        t.join(20)
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])

    def test_unknown_phone_and_old_timestamp_are_refused(self):
        phone = FakePhone("alice")
        t, result = self.start()
        link = wait_for_link(self.lines)
        self.assertEqual(phone.answer(link, credential_id="c_nope")[0], 403)
        self.assertEqual(phone.answer(link, timestamp=1)[0], 400)
        phone.answer(link, "deny")
        t.join(20)
        self.assertFalse(result["ok"])

    def test_a_phone_of_another_user_cannot_approve(self):
        FakePhone("alice")
        mallory = FakePhone("mallory")
        t, result = self.start()
        status, _ = mallory.answer(wait_for_link(self.lines))
        self.assertEqual(status, 403)
        approve_state = result.get("ok")
        self.assertIsNone(approve_state)  # still waiting
        # let it end
        t.join(20)
        self.assertFalse(result["ok"])

    def test_second_answer_is_refused(self):
        phone = FakePhone("alice")
        t, result = self.start()
        link = wait_for_link(self.lines)
        self.assertEqual(phone.answer(link, "approve")[0], 200)
        self.assertEqual(phone.answer(link, "approve")[0], 409)
        t.join(20)
        self.assertTrue(result["ok"])

    def test_timeout_refuses(self):
        FakePhone("alice")
        t, result = self.start(wait=1.5)
        t.join(20)
        self.assertFalse(result["ok"])
        self.assertIn("no answer", " ".join(self.lines).lower())

    def test_no_approver_enrolled_refuses_without_asking(self):
        t, result = self.start()
        t.join(20)
        self.assertFalse(result["ok"])
        self.assertFalse(any(l.startswith("Link: ") for l in self.lines))

    def test_bad_user_names_are_refused(self):
        for name in ("..\\..\\x", "a b", "", "a|b", "../x"):
            lines = []
            self.assertFalse(approve.run(name, "1.2.3.4", "ssh", lines.append, ip=IP, port=47860, wait=1), name)

    def test_domain_prefix_and_case_are_normalised(self):
        phone = FakePhone("alice")
        t, result = self.start(user="LAPTOP\\Alice")
        status, _ = phone.answer(wait_for_link(self.lines))
        t.join(20)
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])


class PassTests(Base):
    def _with_grace(self, hours):
        store.ensure_dirs()
        grants.set_grace(hours)

    def test_pass_skips_the_next_approval_from_the_same_address(self):
        self._with_grace(4)
        phone = FakePhone("alice")
        t, result = self.start()
        phone.answer(wait_for_link(self.lines))
        t.join(20)
        self.assertTrue(result["ok"])
        self.assertEqual(len(grants.all_passes()), 1)

        self.lines.clear()
        t, result = self.start()
        t.join(20)
        self.assertTrue(result["ok"])
        self.assertIn("approved earlier", " ".join(self.lines))
        self.assertFalse(any(l.startswith("Link: ") for l in self.lines))

    def test_pass_does_not_work_from_another_address(self):
        self._with_grace(4)
        phone = FakePhone("alice")
        t, result = self.start(rhost="192.168.1.50")
        phone.answer(wait_for_link(self.lines))
        t.join(20)
        self.lines.clear()
        t, result = self.start(rhost="192.168.1.99", wait=1.5)
        t.join(20)
        self.assertFalse(result["ok"])  # asked again, nobody answered
        self.assertTrue(any(l.startswith("Link: ") for l in self.lines))

    def test_removing_or_disabling_the_approver_ends_the_pass(self):
        self._with_grace(4)
        phone = FakePhone("alice")
        t, result = self.start()
        phone.answer(wait_for_link(self.lines))
        t.join(20)
        self.assertEqual(len(grants.all_passes()), 1)
        store.set_disabled("alice", phone.credential_id, True)
        self.assertEqual(grants.all_passes(), [])
        self.lines.clear()
        t, result = self.start(wait=1)
        t.join(20)
        self.assertFalse(result["ok"])  # no active approver left

    def test_pass_is_fixed_length_and_expires(self):
        self._with_grace(4)
        grants.add("alice", "9.9.9.9", 4, "c_x", now=1000)
        self.assertIsNotNone(grants.valid("alice", "9.9.9.9", {"c_x"}, now=1000 + 4 * 3600 - 1))
        self.assertIsNone(grants.valid("alice", "9.9.9.9", {"c_x"}, now=1000 + 4 * 3600 + 1))
        self.assertIsNone(grants.valid("alice", "9.9.9.9", {"c_other"}, now=1000))

    def test_grace_is_capped_and_off_by_default(self):
        store.ensure_dirs()
        self.assertEqual(grants.grace_hours(), 0.0)
        grants.set_grace(100)
        self.assertEqual(grants.grace_hours(), grants.MAX_HOURS)
        grants.set_grace(0)
        self.assertEqual(grants.grace_hours(), 0.0)

    def test_end_pass(self):
        grants.add("alice", "9.9.9.9", 4, "c_x")
        grants.add("bob", "9.9.9.9", 4, "c_y")
        self.assertEqual(grants.revoke("alice"), 1)
        self.assertEqual([p["user"] for p in grants.all_passes()], ["bob"])
        self.assertEqual(grants.revoke(), 1)
        self.assertEqual(grants.all_passes(), [])


if __name__ == "__main__":
    unittest.main()
