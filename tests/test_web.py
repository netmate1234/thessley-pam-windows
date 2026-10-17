"""The admin web page, against a real HTTPS server on 127.0.0.1 and a stand-in phone that signs approvals.
No browser, no sshd, no Windows needed for these (the machine facts are stubbed). Run from the repo root:
    python -m pytest tests/test_web.py
"""

import base64
import datetime
import http.client
import json
import re
import ssl
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit

from fakeenroll import EnrollingPhone
from fakephone import FakePhone, answer_unsigned
from thessley_pam_win import approve, grants, machine, store, web

USER = "alice"
OTHER = "bob"


class Browser:
    """A very small browser: keeps cookies, does not follow redirects on its own."""

    def __init__(self, port: int):
        self.port = port
        self.cookies: dict[str, str] = {}

    def request(self, method: str, path: str, data: dict | None = None):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=ctx, timeout=20)
        headers = {}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        body = None
        if data is not None:
            body = urlencode(data)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body, headers)
        resp = conn.getresponse()
        raw = resp.read()
        for name, value in resp.getheaders():
            if name.lower() == "set-cookie":
                k, v = value.split(";", 1)[0].split("=", 1)
                if v == "" or "Max-Age=0" in value:
                    self.cookies.pop(k, None)
                else:
                    self.cookies[k] = v
        conn.close()
        return resp, raw.decode("utf-8", "replace")

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, data=None):
        return self.request("POST", path, data or {})


class WebBase(unittest.TestCase):
    """The server, the stand-in phone and the helpers; the tests are in WebTest and KeyDetailsTest."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._saved = (store.BASE, machine.lan_ip, machine.machine_id, approve.WAIT, web.is_admin, approve.PORT)
        self.addCleanup(self._restore)
        store.BASE = self.tmp.name
        store.ensure_dirs()
        machine.lan_ip = lambda: "127.0.0.1"
        machine.machine_id = lambda: "ab" * 16   # the real one reads the Windows registry
        approve.WAIT = 6
        self._web_waits = (web.WEB_WAIT, web.WEB_CONFIRM_WAIT, web.WEB_ENROLL_WAIT)
        web.WEB_WAIT, web.WEB_CONFIRM_WAIT, web.WEB_ENROLL_WAIT = 6, 30, 30   # the page's longer waits, shortened
        WebBase.next_port += 10                    # a port range of its own per test: closed ports can linger on this system
        approve.PORT = WebBase.next_port
        self.admin = False
        web.is_admin = lambda name: self.admin
        self.phone = FakePhone(USER, "My phone")
        self.app = web.WebApp(journal=lambda: [], qr=lambda link: b"<svg xmlns='http://www.w3.org/2000/svg'/>")
        cert, key = store.BASE + "/c.pem", store.BASE + "/k.pem"
        web.ensure_cert(cert, key, ["127.0.0.1"])
        self.httpd = web.make_server(self.app, "127.0.0.1", 0, cert, key)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.shutdown)
        self.addCleanup(self.httpd.server_close)
        self.b = Browser(self.port)

    next_port = 47900

    def _restore(self):
        store.BASE, machine.lan_ip, machine.machine_id, approve.WAIT, web.is_admin, approve.PORT = self._saved
        web.WEB_WAIT, web.WEB_CONFIRM_WAIT, web.WEB_ENROLL_WAIT = self._web_waits

    # -- helpers
    def wait_for(self, browser, flow_id, want, timeout=15):
        end = time.time() + timeout
        last = {}
        while time.time() < end:
            _, body = browser.get(f"/status/{flow_id}")
            last = json.loads(body)
            if want(last):
                return last
            time.sleep(0.15)
        self.fail(f"the page never reached the wanted state; last status {last}")

    def start_flow(self, browser, path, data):
        resp, _ = browser.post(path, data)
        self.assertEqual(resp.status, 303, path)
        m = re.fullmatch(r"/wait/([0-9a-f]{32})", resp.getheader("Location"))
        self.assertIsNotNone(m, resp.getheader("Location"))
        return m.group(1)

    def login(self, browser=None, answer="approve"):
        browser = browser or self.b
        fid = self.start_flow(browser, "/login", {"user": USER})
        status = self.wait_for(browser, fid, lambda s: s.get("link"))
        self.phone.answer(status["link"], answer)
        if answer == "approve":
            self.wait_for(browser, fid, lambda s: s.get("next"))
        else:
            self.wait_for(browser, fid, lambda s: s["state"] in ("refused", "timeout"))
        return fid

    def csrf(self, browser=None):
        _, body = (browser or self.b).get("/keys")
        return re.search(r'name="csrf" value="([^"]+)"', body).group(1)

    def step_up(self, path, data, browser=None, answer="approve"):
        """Do a change that needs a fresh approval; return the final status."""
        browser = browser or self.b
        fid = self.start_flow(browser, path, dict(data, csrf=self.csrf(browser)))
        status = self.wait_for(browser, fid, lambda s: s.get("link"))
        self.phone.answer(status["link"], answer)
        if answer == "approve":
            return fid, self.wait_for(browser, fid, lambda s: s.get("next"))
        return fid, self.wait_for(browser, fid, lambda s: s["state"] in ("refused", "timeout"))


class WebTest(WebBase):
    # -- sign-in
    def test_sign_in_with_an_approval_opens_the_page(self):
        self.assertEqual(self.b.get("/keys")[0].status, 303)  # not signed in: sent to the sign-in page
        self.login()
        resp, body = self.b.get("/keys")
        self.assertEqual(resp.status, 200)
        self.assertIn("My phone", body)
        self.assertIn(self.phone.credential_id, body)

    def test_the_link_names_the_service_for_the_apps(self):
        fid = self.start_flow(self.b, "/login", {"user": USER})
        status = self.wait_for(self.b, fid, lambda s: s.get("link"))
        q = {k: v[0] for k, v in parse_qs(urlsplit(status["link"]).query).items()}
        self.assertEqual((q["s"], q["tty"]), ("thessley-web", "web"))
        self.assertEqual(q["r"], "127.0.0.1")  # where the sign-in comes from, shown on the phone

    def test_user_names_are_normalised_like_everywhere_else(self):
        for typed in ("Alice", "LAPTOP\\ALICE", "alice@example.com"):
            b = Browser(self.port)
            resp, _ = b.post("/login", {"user": typed})
            self.assertEqual(resp.status, 303, typed)

    def test_the_session_cookie_is_locked_down(self):
        fid = self.start_flow(self.b, "/login", {"user": USER})
        status = self.wait_for(self.b, fid, lambda s: s.get("link"))
        self.phone.answer(status["link"])
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        cookies = []
        for _ in range(60):
            conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=ctx, timeout=10)
            conn.request("GET", f"/status/{fid}", headers={"Cookie": f"thessley_wait={self.b.cookies['thessley_wait']}"})
            r = conn.getresponse()
            r.read()
            cookies = [v for k, v in r.getheaders() if k.lower() == "set-cookie" and v.startswith("thessley_session=")]
            conn.close()
            if cookies:
                break
            time.sleep(0.2)
        self.assertTrue(cookies)
        for flag in ("HttpOnly", "Secure", "SameSite=Strict"):
            self.assertIn(flag, cookies[0])

    def test_a_denied_sign_in_gives_no_session(self):
        self.login(answer="deny")
        self.assertNotIn("thessley_session", self.b.cookies)
        self.assertEqual(self.b.get("/keys")[0].status, 303)

    def test_deny_without_a_signature_also_ends_the_sign_in(self):
        fid = self.start_flow(self.b, "/login", {"user": USER})
        status = self.wait_for(self.b, fid, lambda s: s.get("link"))
        code, _ = answer_unsigned(self.phone, status["link"], "deny")
        self.assertEqual(code, 200)
        self.wait_for(self.b, fid, lambda s: s["state"] == "refused")
        self.assertNotIn("thessley_session", self.b.cookies)

    def test_unsigned_approval_never_signs_anyone_in(self):
        fid = self.start_flow(self.b, "/login", {"user": USER})
        status = self.wait_for(self.b, fid, lambda s: s.get("link"))
        code, _ = answer_unsigned(self.phone, status["link"], "approve")
        self.assertEqual(code, 400)
        self.assertNotIn("thessley_session", self.b.cookies)

    def test_no_answer_in_time_is_a_refusal(self):
        fid = self.start_flow(self.b, "/login", {"user": USER})
        self.wait_for(self.b, fid, lambda s: s["state"] == "timeout", timeout=20)
        self.assertNotIn("thessley_session", self.b.cookies)

    def test_unknown_accounts_and_accounts_without_a_key_look_the_same(self):
        store.remove_device(USER, self.phone.credential_id)
        for name in (USER, "no-such-user-x", "", "../etc", "bad name; rm"):
            resp, body = self.b.post("/login", {"user": name})
            self.assertEqual(resp.status, 200, name)
            self.assertIn("cannot sign in here", body)
        self.assertEqual(self.app.flows, {})

    def test_another_browser_cannot_take_over_a_sign_in(self):
        fid = self.start_flow(self.b, "/login", {"user": USER})
        status = self.wait_for(self.b, fid, lambda s: s.get("link"))
        self.phone.answer(status["link"])
        thief = Browser(self.port)  # knows the request id from somewhere, but not the cookie
        self.assertEqual(json.loads(thief.get(f"/status/{fid}")[1])["state"], "gone")
        self.assertEqual(thief.get(f"/qr/{fid}.svg")[0].status, 404)

    def test_sign_in_requests_are_rate_limited(self):
        statuses = [self.b.post("/login", {"user": "no-such-user-x"})[0].status for _ in range(web.LOGIN_RATE[0] + 2)]
        self.assertIn(429, statuses)

    def test_the_wait_page_offers_an_open_in_the_app_button(self):
        """The browser's own app can be opened with the request: a thessleypam:// button next to the QR code and the text link."""
        fid = self.start_flow(self.b, "/login", {"user": USER})
        _, page = self.b.get(f"/wait/{fid}")
        self.assertIn("Open this request in the Thessley app", page)
        self.assertIn("startsWith('thessleypam://')", page)       # only ever a link of this kind becomes the button
        self.assertIn(".btn{", page)                                # and it is styled as a button
        status = self.wait_for(self.b, fid, lambda s: s.get("link"))
        self.assertTrue(status["link"].startswith("thessleypam://"))

    def test_every_page_has_an_open_the_app_button(self):
        """A button that opens the Thessley app on whatever this browser runs on, even where there is no request to answer."""
        for path in ("/", "/nowhere"):
            _, body = self.b.get(path)
            self.assertIn('href="thessleypam://open"', body, path)
            self.assertIn("Open the Thessley app", body, path)
        self.login()
        for path in ("/keys", "/log", "/admin"):
            _, body = self.b.get(path)
            self.assertIn('href="thessleypam://open"', body, path)

    def test_every_page_has_the_security_headers(self):
        resp, _ = self.b.get("/")
        self.assertIn("default-src 'none'", resp.getheader("Content-Security-Policy"))
        self.assertIn("frame-ancestors 'none'", resp.getheader("Content-Security-Policy"))
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.getheader("Cache-Control"), "no-store")

    def test_a_sign_in_never_uses_or_leaves_a_pass(self):
        grants.set_grace(4)
        self.login()
        self.assertEqual(grants.all_passes(), [])      # the approval granted none
        b2 = Browser(self.port)                        # and a second sign-in still has to be approved
        fid = self.start_flow(b2, "/login", {"user": USER})
        status = self.wait_for(b2, fid, lambda s: s.get("link") or s["state"] == "approved")
        self.assertTrue(status.get("link"))

    # -- changes need a fresh approval
    def test_renaming_asks_the_phone_first(self):
        self.login()
        fid = self.start_flow(self.b, "/keys/rename", {"csrf": self.csrf(), "user": USER, "cred": self.phone.credential_id, "label": "Work phone"})
        self.assertEqual(store.devices(USER)[0]["label"], "My phone")     # nothing happens before the approval
        status = self.wait_for(self.b, fid, lambda s: s.get("link"))
        q = {k: v[0] for k, v in parse_qs(urlsplit(status["link"]).query).items()}
        self.assertEqual((q["s"], q["tty"]), ("thessley-web-change", "web-change"))
        self.phone.answer(status["link"])
        self.wait_for(self.b, fid, lambda s: s.get("next"))
        self.assertEqual(store.devices(USER)[0]["label"], "Work phone")
        self.assertIn("Work phone", self.b.get("/keys")[1])

    def test_a_denied_change_changes_nothing(self):
        self.login()
        self.step_up("/keys/remove", {"user": USER, "cred": self.phone.credential_id}, answer="deny")
        self.assertEqual(len(store.devices(USER)), 1)

    def test_switch_off_and_remove(self):
        self.login()
        cred = self.phone.credential_id
        self.step_up("/keys/disable", {"user": USER, "cred": cred})
        self.assertTrue(store.devices(USER)[0].get("disabled"))
        store.set_disabled(USER, cred, False)  # the only key is off now, so nothing could approve switching it on
        self.step_up("/keys/remove", {"user": USER, "cred": cred})
        self.assertEqual(store.devices(USER), [])

    def test_a_form_without_the_right_token_is_refused(self):
        self.login()
        for token in ("", "wrong"):
            resp, _ = self.b.post("/keys/remove", {"csrf": token, "user": USER, "cred": self.phone.credential_id})
            self.assertEqual(resp.status, 400)
        self.assertEqual(len(store.devices(USER)), 1)

    def test_a_bad_key_id_or_label_is_refused(self):
        self.login()
        csrf = self.csrf()
        self.assertEqual(self.b.post("/keys/remove", {"csrf": csrf, "user": USER, "cred": "../../etc"})[0].status, 404)
        self.assertEqual(self.b.post("/keys/rename", {"csrf": csrf, "user": USER, "cred": self.phone.credential_id, "label": "<script>"})[0].status, 400)

    def test_signing_out_and_idle_sessions(self):
        self.login()
        self.b.post("/logout", {"csrf": self.csrf()})
        self.assertEqual(self.b.get("/keys")[0].status, 303)
        self.login()
        for s in self.app.sessions.values():
            s.last -= s.minutes * 60 + 5
        self.assertEqual(self.b.get("/keys")[0].status, 303)

    # -- adding an approver
    def test_adding_an_approver_from_the_page(self):
        self.login()
        self.step_up("/keys/add", {"user": USER})
        flow = [f for f in self.app.flows.values() if f.kind == "enroll"][0]
        status = self.wait_for(self.b, flow.id, lambda s: s.get("link"))
        q = {k: v[0] for k, v in parse_qs(urlsplit(status["link"]).query).items()}
        self.assertEqual(q["u"], USER)
        new = EnrollingPhone(USER, "Second phone")
        new.enroll(status["link"])
        status = self.wait_for(self.b, flow.id, lambda s: s["state"] == "confirm")
        self.assertRegex(status["code"], r"^\d{3} \d{3}$")
        self.b.post(f"/enroll/{flow.id}/confirm", {"csrf": self.csrf(), "answer": "yes"})
        self.wait_for(self.b, flow.id, lambda s: s.get("next"))
        self.assertEqual(sorted(d["label"] for d in store.devices(USER)), ["My phone", "Second phone"])

    def test_the_codes_not_matching_adds_nothing(self):
        self.login()
        self.step_up("/keys/add", {"user": USER})
        flow = [f for f in self.app.flows.values() if f.kind == "enroll"][0]
        status = self.wait_for(self.b, flow.id, lambda s: s.get("link"))
        EnrollingPhone(USER).enroll(status["link"])
        self.wait_for(self.b, flow.id, lambda s: s["state"] == "confirm")
        self.b.post(f"/enroll/{flow.id}/confirm", {"csrf": self.csrf(), "answer": "no"})
        self.wait_for(self.b, flow.id, lambda s: s["state"] == "failed")
        self.assertEqual(len(store.devices(USER)), 1)

    def test_each_way_of_not_adding_a_device_says_which_it_was(self):
        for lines, expected in ((["Timed out. Nothing was added."], "No device answered"),
                                (["Not added."], "not confirmed in time or did not match"),
                                (["Cancelled. Nothing was added."], "cancelled"),
                                (["error: OSError()"], "Something went wrong"),
                                ([], "was not added")):
            f = web.Flow("enroll", USER)
            f.lines = lines
            self.assertIn(expected, web.make_handler(self.app).failure_text(f))

    def test_every_page_says_which_computer_it_is_for(self):
        host = machine.hostname()
        page = web.page("Sign in", "", "n")
        self.assertIn(f"<h1>Thessley Passkeys for {host}</h1>", page)
        self.assertIn(f"Thessley Passkeys for {host}</title>", page)

    # -- passes
    def pass_for(self, user, rhost="192.168.1.50", hours=4):
        cred = store.devices(user)[0]["credential_id"]
        return grants.add(user, rhost, hours, cred)

    def test_the_keys_page_lists_the_passes_and_each_can_be_ended(self):
        self.pass_for(USER)
        self.pass_for(USER, "192.168.1.51")
        self.login()
        _, body = self.b.get("/keys")
        self.assertIn("<h2>Passes</h2>", body)
        self.assertIn("192.168.1.50", body)
        self.assertIn("approved by My phone", body)
        resp, _ = self.b.post("/passes/end", {"csrf": self.csrf(), "user": USER, "rhost": "192.168.1.50"})
        self.assertEqual(resp.status, 303)    # no fresh approval is asked: ending a pass only takes access away
        self.assertEqual([p["rhost"] for p in grants.passes_of(USER)], ["192.168.1.51"])
        self.assertIn("Ended 1 pass", self.b.get("/keys")[1])

    def test_all_passes_can_be_ended_at_once_and_the_page_says_so_when_there_are_none(self):
        self.pass_for(USER)
        self.pass_for(USER, "192.168.1.51")
        self.login()
        self.b.post("/passes/end", {"csrf": self.csrf(), "user": USER, "all": "1"})
        self.assertEqual(grants.passes_of(USER), [])
        self.assertIn("No pass is active", self.b.get("/keys")[1])

    def test_ending_a_pass_needs_the_session_and_the_csrf_token_and_only_your_own_account(self):
        self.pass_for(USER)
        self.assertEqual(self.b.post("/passes/end", {"user": USER, "all": "1"})[0].status, 303)   # not signed in
        self.assertEqual(len(grants.passes_of(USER)), 1)
        self.login()
        self.b.post("/passes/end", {"csrf": "wrong", "user": USER, "all": "1"})
        self.assertEqual(len(grants.passes_of(USER)), 1)
        store.add_device(OTHER, FakePhone(OTHER).public_key, "Bob's", [])
        self.assertEqual(self.b.post("/passes/end", {"csrf": self.csrf(), "user": OTHER, "all": "1"})[0].status, 403)

    # -- who may do what
    def test_a_normal_user_sees_only_their_own_keys_and_no_admin_page(self):
        store.add_device(OTHER, FakePhone(OTHER).public_key, "Bob's", [])
        self.login()
        self.assertEqual(self.b.get(f"/keys?user={OTHER}")[0].status, 403)
        self.assertEqual(self.b.get("/admin")[0].status, 403)
        self.assertEqual(self.b.post("/admin/set", {"csrf": self.csrf(), "name": "grace", "value": "9"})[0].status, 403)
        self.assertEqual(grants.grace_hours(), 0)

    def test_an_administrator_changes_a_setting_with_an_approval(self):
        self.admin = True
        self.login()
        resp, body = self.b.get("/admin")
        self.assertEqual(resp.status, 200)
        self.assertIn("Settings for this computer", body)
        self.step_up("/admin/set", {"name": "grace", "value": "2"})
        self.assertEqual(grants.grace_hours(), 2)
        self.step_up("/admin/set", {"name": "self_enroll", "value": "off"})
        self.assertFalse(grants.self_enroll_first())

    def test_an_administrator_can_see_another_accounts_keys(self):
        store.add_device(OTHER, FakePhone(OTHER).public_key, "Bob's phone", [])
        self.admin = True
        self.login()
        resp, body = self.b.get(f"/keys?user={OTHER}")
        self.assertEqual(resp.status, 200)
        self.assertIn("Bob&#x27;s phone", body)

    def test_admin_settings_are_validated(self):
        self.admin = True
        self.login()
        csrf = self.csrf()
        self.assertEqual(self.b.post("/admin/set", {"csrf": csrf, "name": "grace", "value": "-3"})[0].status, 400)
        self.assertEqual(self.b.post("/admin/set", {"csrf": csrf, "name": "grace", "value": "abc"})[0].status, 400)
        self.assertEqual(self.b.post("/admin/set", {"csrf": csrf, "name": "self_enroll", "value": "maybe"})[0].status, 400)
        self.assertEqual(self.b.post("/admin/set", {"csrf": csrf, "name": "rm -rf", "value": "on"})[0].status, 404)

    # -- output safety and the log
    def test_nothing_from_the_key_list_reaches_the_page_unescaped(self):
        store.add_device(USER, FakePhone(USER).public_key, "<img src=x onerror=alert(1)>", [])
        self.login()
        _, body = self.b.get("/keys")
        self.assertNotIn("<img src=x", body)
        self.assertIn("&lt;img src=x", body)

    def test_the_activity_log_shows_my_account_only(self):
        cred = self.phone.credential_id
        self.app.journal = lambda: [
            f"2026-10-17 01:14:10 INFO approved by 'My phone' ({cred}) from 192.168.1.5 for {USER} (from 192.168.1.50)",
            "2026-10-17 01:15:00 WARN timeout for somebody-else (from 192.168.1.60)",
            f"2026-10-17 01:16:00 WARN denied by 'My phone' ({cred}, no signature) for {USER} (from 192.168.1.50)",
            "2026-10-17 01:17:00 INFO service started on 127.0.0.1:47800",
        ]
        self.login()
        _, body = self.b.get("/log")
        self.assertIn("Approved by My phone", body)
        self.assertIn("Denied by My phone", body)
        self.assertNotIn("somebody-else", body)
        self.admin = True
        _, everyone = self.b.get("/log?all=1")
        self.assertIn("somebody-else", everyone)

    def test_parse_activity(self):
        ok = web.parse_activity("2026-10-17 01:14:10 INFO pass granted to windows (from 192.168.1.190, 4 h)", None)
        self.assertEqual(ok, ("2026-10-17 01:14:10", "Pass granted to windows from 192.168.1.190 for 4 h"))
        self.assertIsNone(web.parse_activity("garbage", None))
        self.assertIsNone(web.parse_activity("2026-10-17 01:14:10 WARN timeout for bob (from 1.2.3.4)", "alice"))

    def test_certificate_is_kept_between_runs(self):
        cert, key = store.BASE + "/again.pem", store.BASE + "/again.key"
        first = web.ensure_cert(cert, key, ["127.0.0.1"])
        self.assertEqual(web.ensure_cert(cert, key, ["127.0.0.1"]), first)


class KeyDetailsTest(WebBase):
    """What the page says about each key."""

    @staticmethod
    def fake_android_chain(key_level: int, attestation_level: int) -> list:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Android Keystore Key")])
        raw = bytes([0x30, 0x0C, 0x02, 0x01, 0x04, 0x0A, 0x01, attestation_level, 0x02, 0x01, 0x04, 0x0A, 0x01, key_level])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(web.ATTESTATION_OID), raw), critical=False)
                .sign(key, hashes.SHA256()))
        return [base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()]

    def keys_body(self):
        self.login()
        return self.b.get("/keys")[1]

    def test_an_app_key_says_what_it_is_and_shows_its_fingerprint(self):
        body = self.keys_body()
        self.assertIn("An app key", body)
        self.assertIn("ECDSA on secp256r1", body)
        self.assertRegex(body, r"[0-9a-f]{4}(:[0-9a-f]{4}){7}…")

    def test_a_phone_key_shows_where_the_key_lives(self):
        store.add_device(USER, FakePhone(USER).public_key, "Strong phone", self.fake_android_chain(key_level=2, attestation_level=1))
        body = self.keys_body()
        self.assertIn("A phone key (Android Keystore)", body)
        self.assertIn("StrongBox (separate secure chip)", body)
        self.assertIn("does not check them against a root of trust", body)

    def test_a_tpm_key_proven_at_enrolment_says_so_with_the_maker(self):
        store.add_device(USER, FakePhone(USER).public_key, "Desktop in a TPM", [],
                         {"level": "tpm", "maker": "INTC", "model": "ADL", "checked_at": 1760000000})
        body = self.keys_body()
        self.assertIn("held in a TPM chip, proven at enrolment", body)
        self.assertIn("Verified by this computer", body)
        self.assertIn("INTC ADL", body)
        self.assertIn("revocation lists are not checked", body)  # said plainly: what the proof does not cover

    def test_a_tpm_claim_that_did_not_verify_says_why(self):
        store.add_device(USER, FakePhone(USER).public_key, "Doubtful desktop", [],
                         {"level": "unverified", "reason": "certified name does not match the key"})
        body = self.keys_body()
        self.assertIn("could not verify it: certified name does not match the key", body)

    def test_an_unreadable_chain_does_not_break_the_page(self):
        store.add_device(USER, FakePhone(USER).public_key, "Odd phone", ["not base64 der"])
        body = self.keys_body()
        self.assertIn("could not be read", body)
        self.assertIn("Odd phone", body)

    def test_use_count_and_passes(self):
        cred = self.phone.credential_id
        self.app.journal = lambda: [
            f"2026-10-17 01:14:10 INFO approved by 'My phone' ({cred}) from 192.168.1.5 for {USER} (from 192.168.1.5)",
            f"2026-10-17 02:00:00 INFO approved by 'My phone' ({cred}) from 192.168.1.9 for {USER} (from 192.168.1.9)",
        ]
        grants.add(USER, "192.168.1.5", 4, cred)
        body = self.keys_body()
        self.assertIn("2, the last on 2026-10-17 02:00:00 from 192.168.1.9", body)
        self.assertIn("from 192.168.1.5", body)

    def test_the_der_reader_refuses_garbage(self):
        for bad in (b"", b"\x30", b"\x31\x00", b"\x30\x05\x02"):
            with self.assertRaises((ValueError, IndexError)):
                web.parse_key_description(bad)


class SettingsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._base = store.BASE
        self.addCleanup(lambda: setattr(store, "BASE", self._base))
        store.BASE = self.tmp.name

    def test_defaults_and_limits(self):
        st = grants.web_settings()
        self.assertEqual((st["enabled"], st["listen"], st["port"], st["session_minutes"]), (False, "", 47820, 15))
        grants.set_web(enabled=True, port=70000, session_minutes=0)
        st = grants.web_settings()
        self.assertEqual((st["enabled"], st["port"], st["session_minutes"]), (True, 65535, 1))
        with self.assertRaises(ValueError):
            grants.set_web(nonsense=1)


if __name__ == "__main__":
    unittest.main()
