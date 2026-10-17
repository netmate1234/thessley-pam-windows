"""The admin page must not share its port with another program (Windows lets two sockets bind one port unless asked not to)."""

import socket
import unittest
from http.server import BaseHTTPRequestHandler

from thessley_pam_win import web


class ExclusivePort(unittest.TestCase):
    @unittest.skipUnless(hasattr(socket, "SO_EXCLUSIVEADDRUSE"), "Windows only: Linux already refuses a second listener")
    def test_a_second_server_cannot_take_the_same_port(self):
        first = web.Server(("127.0.0.1", 0), BaseHTTPRequestHandler)
        try:
            port = first.server_address[1]
            with self.assertRaises(OSError):
                web.Server(("127.0.0.1", port), BaseHTTPRequestHandler)      # another copy of the page
            plain = socket.socket()
            plain.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)      # an ordinary program asking to share the port
            try:
                with self.assertRaises(OSError):
                    plain.bind(("127.0.0.1", port))
            finally:
                plain.close()
        finally:
            first.server_close()

    def test_the_port_is_free_again_after_it_closes(self):
        first = web.Server(("127.0.0.1", 0), BaseHTTPRequestHandler)
        port = first.server_address[1]
        first.server_close()
        again = web.Server(("127.0.0.1", port), BaseHTTPRequestHandler)
        again.server_close()


if __name__ == "__main__":
    unittest.main()
