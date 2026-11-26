#!/usr/bin/env python3
"""Unit tests for testssl flat JSON parsing."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tlsbaseline.parser import build_structure, parse_cipher_finding


MODERN_CIPHER_LINE = (
    "TLSv1.2   xc030   ECDHE-RSA-AES256-GCM-SHA384       "
    "ECDH 253   AESGCM      256      "
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
)
LEGACY_CIPHER_LINE = (
    "TLSv1   x39     DHE-RSA-AES256-SHA                "
    "DH 2048    AES         256      "
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
)


class CipherParsingTests(unittest.TestCase):
    def test_modern_line(self):
        parsed = parse_cipher_finding(MODERN_CIPHER_LINE)
        self.assertEqual(parsed["protocol"], "TLSv1.2")
        self.assertEqual(parsed["hex_code"], "0xc030")
        self.assertEqual(parsed["bits"], 256)
        self.assertEqual(parsed["encryption"], "AESGCM")
        self.assertEqual(parsed["iana_name"],
                         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")

    def test_legacy_line_with_short_hex(self):
        parsed = parse_cipher_finding(LEGACY_CIPHER_LINE)
        self.assertEqual(parsed["hex_code"], "0x39")
        self.assertEqual(parsed["key_exchange"], "DH 2048")
        self.assertEqual(parsed["iana_name"],
                         "TLS_DHE_RSA_WITH_AES_256_CBC_SHA")

    def test_unknown_shape_is_kept_not_dropped(self):
        flat = [{
            "id": "cipher-tls1_2_x1234",
            "severity": "OK",
            "finding": "something unexpected",
        }]
        structured = build_structure(flat, target="host", port=443)
        self.assertEqual(len(structured["ciphers"]), 1)
        self.assertEqual(structured["ciphers"][0]["key"],
                         "cipher-tls1_2_x1234")
        self.assertIn("raw_finding", structured["ciphers"][0])


class StructureTests(unittest.TestCase):
    def _flat(self):
        return [
            {"id": "TLS1_2", "severity": "OK",
             "finding": "offered", "ip": "h/1.2.3.4", "port": "443"},
            {"id": "TLS1", "severity": "INFO",
             "finding": "not offered", "ip": "h/1.2.3.4", "port": "443"},
            {"id": "cipher-tls1_2_xc02f", "severity": "OK",
             "finding": MODERN_CIPHER_LINE.replace("xc030", "xc02f")
             .replace("AES256", "AES128").replace("256", "128"),
             "ip": "h/1.2.3.4", "port": "443"},
        ]

    def test_protocols_and_ciphers(self):
        structured = build_structure(self._flat())
        status = {p["protocol"]: p["offered"]
                  for p in structured["protocols"]}
        self.assertTrue(status["TLS1_2"])
        self.assertFalse(status["TLS1"])
        self.assertEqual(len(structured["ciphers"]), 1)
        cipher = structured["ciphers"][0]
        self.assertEqual(cipher["key"], "cipher-tls1_2_xc02f")
        self.assertEqual(cipher["hex_code"], "0xc02f")

    def test_target_fallback_from_ip_field(self):
        structured = build_structure(self._flat())
        self.assertEqual(structured["target"]["host"], "h")
        self.assertEqual(structured["target"]["port"], 443)

    def test_raw_findings_preserved(self):
        structured = build_structure(self._flat())
        ids = {entry["id"] for entry in structured["rawFindings"]}
        self.assertEqual(ids, {"TLS1_2", "TLS1", "cipher-tls1_2_xc02f"})


if __name__ == "__main__":
    unittest.main()
