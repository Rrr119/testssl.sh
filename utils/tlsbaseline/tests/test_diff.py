#!/usr/bin/env python3
"""Unit tests for baseline diffing."""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tlsbaseline.diff import build_diff, diff_ciphers


def _cipher(key, iana, severity="OK", bits=128):
    return {
        "key": key,
        "id": key,
        "offered": True,
        "severity": severity,
        "protocol": "TLSv1.2",
        "hex_code": key[-4:],
        "iana_name": iana,
        "openssl_name": iana.lower(),
        "key_exchange": "ECDH 256",
        "encryption": "AESGCM",
        "bits": bits,
    }


def _doc(ciphers, protocols=None, failures=None):
    return {
        "schemaVersion": "1.0",
        "target": {"host": "h", "port": 443},
        "scan": {"scannedAt": "2026-11-26T10:00:00+0800"},
        "protocols": protocols or [],
        "ciphers": ciphers,
        "failures": failures or [],
    }


class CipherDiffTests(unittest.TestCase):
    def test_added_removed_and_changed_pinpoint_keys(self):
        old = _doc([
            _cipher("cipher-tls1_2_xc02f", "A"),
            _cipher("cipher-tls1_2_xc030", "B"),
        ])
        new = copy.deepcopy(old)
        new["ciphers"] = [c for c in new["ciphers"]
                          if c["key"] != "cipher-tls1_2_xc02f"]
        new["ciphers"].append(_cipher("cipher-tls1_2_x009c", "C",
                                      severity="MEDIUM", bits=168))
        for cipher in new["ciphers"]:
            if cipher["key"] == "cipher-tls1_2_xc030":
                cipher["severity"] = "MEDIUM"

        result = diff_ciphers(old, new)
        self.assertEqual([x["key"] for x in result["removed"]],
                         ["cipher-tls1_2_xc02f"])
        self.assertEqual([x["key"] for x in result["added"]],
                         ["cipher-tls1_2_x009c"])
        self.assertEqual(result["added"][0]["item"]["iana_name"], "C")
        changed = result["changed"][0]
        self.assertEqual(changed["key"], "cipher-tls1_2_xc030")
        self.assertEqual(changed["changes"]["severity"],
                         {"old": "OK", "new": "MEDIUM"})
        self.assertEqual(result["counts"],
                         {"added": 1, "removed": 1, "changed": 1})

    def test_identity_change_is_remove_plus_add(self):
        old = _doc([_cipher("cipher-tls1_2_xc02f", "A")])
        new = _doc([_cipher("cipher-tls1_2_xc030", "B")])
        result = diff_ciphers(old, new)
        self.assertEqual(len(result["changed"]), 0)
        self.assertEqual(result["removed"][0]["key"],
                         "cipher-tls1_2_xc02f")
        self.assertEqual(result["added"][0]["key"],
                         "cipher-tls1_2_xc030")

    def test_identical_documents_have_no_changes(self):
        doc = _doc([_cipher("cipher-tls1_2_xc02f", "A")],
                   protocols=[{"protocol": "TLS1_2", "offered": True,
                               "severity": "OK", "detail": "offered"}],
                   failures=[{"protocol": "TLS1", "category": "tls_alert",
                              "reason": "fatal_alert_protocol_version"}])
        result = build_diff(doc, copy.deepcopy(doc))
        self.assertFalse(result["summary"]["hasChanges"])
        self.assertEqual(result["summary"]["cipherChanges"], 0)


class ProtocolAndFailureDiffTests(unittest.TestCase):
    def test_protocol_toggle(self):
        old = _doc([], protocols=[
            {"protocol": "TLS1_3", "offered": False, "severity": "INFO",
             "detail": "not offered"},
        ])
        new = copy.deepcopy(old)
        new["protocols"][0].update(offered=True, severity="OK",
                                   detail="offered")
        result = build_diff(old, new)
        self.assertEqual(
            [x["protocol"] for x in result["protocols"]["changed"]],
            ["TLS1_3"])
        self.assertTrue(result["summary"]["hasChanges"])

    def test_failure_category_change(self):
        old = _doc([], failures=[
            {"protocol": "TLS1", "category": "tls_alert",
             "reason": "fatal_alert_protocol_version"},
        ])
        new = copy.deepcopy(old)
        new["failures"][0] = {"protocol": "TLS1",
                              "category": "tcp_timeout",
                              "reason": "tcp_syn_no_response"}
        result = build_diff(old, new)
        self.assertEqual(result["failures"]["changed"][0]["protocol"],
                         "TLS1")
        self.assertEqual(
            result["failures"]["changed"][0]["new"]["category"],
            "tcp_timeout")


if __name__ == "__main__":
    unittest.main()
