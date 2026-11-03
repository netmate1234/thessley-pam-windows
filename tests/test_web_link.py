"""The one-time first-phone link names the address the admin page really listens on, and is not issued for a dead address."""
import os
import socket
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from thessley_pam_win import cli, store, web  # noqa: E402


def _listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return s, s.getsockname()[1]


class WebLinkHost(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._base = store.BASE
        store.BASE = self.tmp.name

    def tearDown(self):
        store.BASE = self._base
        self.tmp.cleanup()

    def st(self, port, listen=""):
        return {"port": port, "listen": listen}

    def test_record_and_forget(self):
        web.record_listening("192.168.1.190", 47820)
        with open(web.listening_path()) as f:
            self.assertEqual(f.read().strip(), "192.168.1.190 47820")
        web.forget_listening()
        self.assertFalse(os.path.exists(web.listening_path()))
        web.forget_listening()  # nothing there: no error

    def test_uses_the_address_the_page_recorded_not_the_guess(self):
        srv, port = _listener()
        try:
            web.record_listening("127.0.0.1", port)
            with mock.patch.object(cli.machine, "lan_ip", return_value="10.8.0.3"):  # the VPN adapter a default-route guess could pick
                host, problem = cli.web_page_host(self.st(port))
            self.assertEqual((host, problem), ("127.0.0.1", None))
        finally:
            srv.close()

    def test_falls_back_to_the_guess_when_nothing_was_recorded(self):
        srv, port = _listener()
        try:
            with mock.patch.object(cli.machine, "lan_ip", return_value="127.0.0.1"):
                self.assertEqual(cli.web_page_host(self.st(port)), ("127.0.0.1", None))
        finally:
            srv.close()

    def test_a_recorded_address_for_another_port_is_ignored(self):
        srv, port = _listener()
        try:
            web.record_listening("203.0.113.9", port + 1)
            with mock.patch.object(cli.machine, "lan_ip", return_value="127.0.0.1"):
                self.assertEqual(cli.web_page_host(self.st(port)), ("127.0.0.1", None))
        finally:
            srv.close()

    def test_no_link_for_an_address_that_does_not_answer(self):
        srv, port = _listener()
        srv.close()  # nothing listens now
        with mock.patch.object(cli.machine, "lan_ip", return_value="127.0.0.1"):
            host, problem = cli.web_page_host(self.st(port))
        self.assertIn("does not answer", problem)
        self.assertIn("127.0.0.1", problem)


if __name__ == "__main__":
    unittest.main()
