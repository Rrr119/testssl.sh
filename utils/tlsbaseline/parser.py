#!/usr/bin/env python3
"""Parse testssl.sh flat JSON into a stable, diff-friendly structure.

testssl.sh already emits a flat JSON array via ``--jsonfile``.  Each
cipher finding contains a stable id such as
``cipher-tls1_2_xc030`` but its machine relevant fields (hex code, IANA
name, key exchange, strength) are buried in a fixed width ``finding``
string.  This module normalises those records so that baseline diffs can
pinpoint an individual cipher suite instead of comparing raw text.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

SCHEMA_VERSION = "1.0"

# "TLSv1.2   xc030   ECDHE-RSA-AES256-GCM-SHA384   ECDH 253   AESGCM   256   TLS_..."
CIPHER_LINE_RE = re.compile(
    r"^\s*(?P<protocol>TLSv\d(?:\.\d)?|SSLv\d)\s+"
    r"x(?P<hex>[0-9a-fA-F]{2,4})\s+"
    r"(?P<openssl>\S+)\s+"
    r"(?P<kx>.+?)\s+"
    r"(?P<enc>\S+)\s+"
    r"(?P<bits>\d+)\s+"
    r"(?P<iana>\S+)\s*$"
)

PROTOCOL_IDS = {"SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"}


def load_flat_json(path: str) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON array of findings")
    return data


def parse_cipher_finding(finding: str) -> Optional[dict[str, Any]]:
    match = CIPHER_LINE_RE.match(finding)
    if not match:
        return None
    parts = match.groupdict()
    return {
        "protocol": parts["protocol"],
        "hex_code": "0x" + parts["hex"].lower(),
        "openssl_name": parts["openssl"],
        "iana_name": parts["iana"],
        "key_exchange": " ".join(parts["kx"].split()),
        "encryption": parts["enc"],
        "bits": int(parts["bits"]),
    }


def _cipher_key(entry_id: str, parsed: dict[str, Any]) -> str:
    """Stable identity of a cipher item across scans.

    Prefer the testssl id (it already encodes protocol + hex code) and
    fall back to protocol/IANA pair for records produced elsewhere.
    """
    if entry_id:
        return entry_id
    return f"{parsed['protocol']}:{parsed['iana_name']}"


def build_structure(
    flat: list[dict[str, Any]],
    target: Optional[str] = None,
    port: Optional[int] = None,
) -> dict[str, Any]:
    """Convert flat findings into the structured scan document."""
    protocols: dict[str, dict[str, Any]] = {}
    ciphers: dict[str, dict[str, Any]] = {}
    raw_findings: list[dict[str, Any]] = []

    host = target
    host_port = port

    for entry in flat:
        entry_id = entry.get("id", "")
        severity = entry.get("severity", "")
        finding = entry.get("finding", "")
        if host is None and entry.get("ip"):
            host = entry["ip"].split("/")[0]
        if host_port is None and entry.get("port"):
            try:
                host_port = int(entry["port"])
            except ValueError:
                host_port = entry["port"]

        raw_findings.append({
            "id": entry_id,
            "severity": severity,
            "finding": finding,
            "cve": entry.get("cve", ""),
            "cwe": entry.get("cwe", ""),
        })

        if entry_id in PROTOCOL_IDS:
            offered = finding.strip().startswith("offered")
            protocols[entry_id] = {
                "protocol": entry_id,
                "offered": offered,
                "severity": severity,
                "detail": finding.strip(),
            }
            continue

        if entry_id.startswith("cipher-"):
            parsed = parse_cipher_finding(finding)
            if parsed is None:
                # Keep unknown shapes instead of silently dropping them.
                ciphers[entry_id] = {
                    "key": entry_id,
                    "id": entry_id,
                    "offered": True,
                    "severity": severity,
                    "raw_finding": finding.strip(),
                }
                continue
            key = _cipher_key(entry_id, parsed)
            ciphers[key] = {
                "key": key,
                "id": entry_id,
                "offered": True,
                "severity": severity,
                **parsed,
            }

    return {
        "schemaVersion": SCHEMA_VERSION,
        "target": {
            "host": host,
            "port": host_port,
        },
        "protocols": sorted(protocols.values(), key=lambda item: item["protocol"]),
        "ciphers": sorted(ciphers.values(), key=lambda item: item["key"]),
        "rawFindings": raw_findings,
    }
