#!/usr/bin/env python3
"""Unit tests for handshake classification helpers.

Network behaviour against real servers is covered by the Perl acceptance
test (t/70_tls_baseline.t); here we test the deterministic pieces and the
alert/category mapping without opening sockets.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tlsbaseline.probe import (
    TLS_ALERTS,
    VERSION_TO_PROTOCOL,
    _build_client_hello,
)


class ClientHelloTests(unittest.TestCase):
    def test_minimal_client_hello_layout(self):
        hello = _build_client_hello(3, 3, [0x002F])
        self.assertEqual(hello[0], 0x16)              # handshake record
        self.assertEqual(hello[1:3], b"\x03\x03")     # record version
        self.assertEqual(hello[5], 0x01)              # ClientHello type
        # record length matches the rest of the buffer
        length = int.from_bytes(hello[3:5], "big")
        self.assertEqual(length, len(hello) - 5)

    def test_multiple_cipher_codes(self):
        hello = _build_client_hello(3, 1, [0x002F, 0x0035])
        # cipher suite length field: two suites * 2 bytes
        # record header (5) then handshake:
        # type(1)+len(3)+version(2)+random(32)+sidlen(1)
        offset = 5 + 1 + 3 + 2 + 32 + 1
        self.assertEqual(int.from_bytes(hello[offset:offset + 2], "big"), 4)


class MappingTests(unittest.TestCase):
    def test_known_alerts(self):
        self.assertEqual(TLS_ALERTS[0x28], "handshake_failure")
        self.assertEqual(TLS_ALERTS[0x46], "protocol_version")
        self.assertEqual(TLS_ALERTS[0x56], "inappropriate_fallback")

    def test_version_mapping_covers_supported_protocols(self):
        self.assertEqual(VERSION_TO_PROTOCOL[(3, 1)], "TLS1")
        self.assertEqual(VERSION_TO_PROTOCOL[(3, 3)], "TLS1_2")


if __name__ == "__main__":
    unittest.main()
