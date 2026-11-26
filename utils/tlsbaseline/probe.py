#!/usr/bin/env python3
"""Handshake probes and failure-reason classification.

testssl.sh's flat JSON records an unsupported protocol or cipher simply as
"not offered" without the reason.  This module performs lightweight raw
TLS handshakes so that failures can be classified into stable machine
readable categories, independently of the (possibly missing) OpenSSL
binary output.
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, asdict
from typing import Optional

# TLS alert descriptions (RFC 8446 section 6 / RFC 5246 section 7.2.2).
TLS_ALERTS = {
    0x00: "close_notify",
    0x0A: "unexpected_message",
    0x14: "bad_record_mac",
    0x15: "decryption_failed",
    0x16: "record_overflow",
    0x1E: "decompression_failure",
    0x28: "handshake_failure",
    0x29: "no_certificate_RESERVED",
    0x2A: "bad_certificate",
    0x2B: "unsupported_certificate",
    0x2C: "certificate_revoked",
    0x2D: "certificate_expired",
    0x2E: "certificate_unknown",
    0x2F: "illegal_parameter",
    0x30: "unknown_ca",
    0x31: "access_denied",
    0x32: "decode_error",
    0x33: "decrypt_error",
    0x3C: "export_restriction_RESERVED",
    0x46: "protocol_version",
    0x47: "insufficient_security",
    0x50: "internal_error",
    0x56: "inappropriate_fallback",
    0x5A: "user_canceled",
    0x64: "no_renegotiation",
    0x6D: "missing_extension",
    0x6E: "unsupported_extension",
    0x70: "unrecognized_name",
    0x71: "bad_certificate_status_response",
    0x73: "unknown_psk_identity",
    0x78: "certificate_required",
    0x85: "no_application_protocol",
}

# Stable failure categories consumed by the asset inventory.  Keeping this
# list explicit makes historical comparisons reliable: categories never
# depend on free text from a specific OpenSSL version.
CATEGORY_DNS_FAILURE = "dns_failure"
CATEGORY_TCP_UNREACHABLE = "tcp_unreachable"
CATEGORY_TCP_REFUSED = "tcp_refused"
CATEGORY_TCP_TIMEOUT = "tcp_timeout"
CATEGORY_TLS_ALERT = "tls_alert"
CATEGORY_TLS_CLOSED = "tls_connection_closed"
CATEGORY_TLS_TIMEOUT = "tls_timeout"
CATEGORY_TLS_MALFORMED = "tls_malformed_response"
CATEGORY_PROBE_ERROR = "probe_error"
CATEGORY_SUCCESS = "success"

# Reasons grouped by whether the asset is reachable at all.
NETWORK_CATEGORIES = {
    CATEGORY_DNS_FAILURE,
    CATEGORY_TCP_UNREACHABLE,
    CATEGORY_TCP_REFUSED,
    CATEGORY_TCP_TIMEOUT,
}
HANDSHAKE_CATEGORIES = {
    CATEGORY_TLS_ALERT,
    CATEGORY_TLS_CLOSED,
    CATEGORY_TLS_TIMEOUT,
    CATEGORY_TLS_MALFORMED,
}

PROTOCOL_VERSIONS = {
    "SSLv2": (2, 0),
    "SSLv3": (3, 0),
    "TLS1": (3, 1),
    "TLS1_1": (3, 2),
    "TLS1_2": (3, 3),
    "TLS1_3": (3, 4),
}

VERSION_TO_PROTOCOL = {
    (2, 0): "SSLv2",
    (3, 0): "SSLv3",
    (3, 1): "TLS1",
    (3, 2): "TLS1_1",
    (3, 3): "TLS1_2",
    (3, 4): "TLS1_3",
}


@dataclass
class ProbeResult:
    """Outcome of a single handshake attempt."""

    target: str
    port: int
    protocol: str
    category: str
    reason: str
    alert_code: Optional[str] = None
    alert_name: Optional[str] = None
    negotiated: Optional[str] = None
    elapsed_ms: Optional[int] = None
    detail: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _recvn(sock: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _build_client_hello(major: int, minor: int, cipher_codes: list[int]) -> bytes:
    """Build a minimal TLS 1.x ClientHello (raw socket, stdlib only)."""
    version = bytes([major, minor])
    cipher_bytes = b"".join(struct.pack("!H", code) for code in cipher_codes)
    body = (
        version
        + b"\x01" * 32                      # random
        + b"\x00"                           # empty session id
        + struct.pack("!H", len(cipher_bytes))
        + cipher_bytes
        + b"\x01\x00"                       # compression: null
        + b"\x00\x00"                       # no extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16" + version + struct.pack("!H", len(handshake)) + handshake


def check_tcp(host: str, port: int, timeout: float = 4.0) -> ProbeResult:
    """TCP layer check used when a target does not complete a handshake."""
    started = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        category = CATEGORY_SUCCESS
        reason = "tcp_connect_ok"
    except ConnectionRefusedError:
        category = CATEGORY_TCP_REFUSED
        reason = "connection_refused"
    except socket.timeout:
        category = CATEGORY_TCP_TIMEOUT
        reason = "tcp_syn_no_response"
    except OSError as exc:
        category = CATEGORY_TCP_UNREACHABLE
        reason = type(exc).__name__
    finally:
        sock.close()
    elapsed = int((time.monotonic() - started) * 1000)
    return ProbeResult(
        target=host,
        port=port,
        protocol="TCP",
        category=category,
        reason=reason,
        elapsed_ms=elapsed,
    )


def handshake_probe(
    host: str,
    port: int,
    protocol: str,
    cipher_codes: Optional[list[int]] = None,
    timeout: float = 5.0,
) -> ProbeResult:
    """Send one ClientHello and classify the server response.

    A successful ServerHello is reported as ``success`` even though the
    full handshake is not completed: the goal is to learn whether the
    protocol/cipher combination is accepted and, if not, why.
    """
    if protocol not in PROTOCOL_VERSIONS:
        raise ValueError(f"unsupported protocol label: {protocol}")
    major, minor = PROTOCOL_VERSIONS[protocol]
    # TLS_RSA_WITH_AES_128_CBC_SHA (0x002f): available on every legacy
    # stack, so protocol-version rejections are not masked by a missing
    # cipher.
    cipher_codes = cipher_codes or [0x002F]
    started = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.connect((host, port))
        except ConnectionRefusedError:
            return ProbeResult(host, port, protocol, CATEGORY_TCP_REFUSED,
                               "connection_refused",
                               elapsed_ms=int((time.monotonic() - started) * 1000))
        except socket.timeout:
            return ProbeResult(host, port, protocol, CATEGORY_TCP_TIMEOUT,
                               "tcp_syn_no_response",
                               elapsed_ms=int((time.monotonic() - started) * 1000))
        except OSError as exc:
            return ProbeResult(host, port, protocol, CATEGORY_TCP_UNREACHABLE,
                               type(exc).__name__, detail=str(exc),
                               elapsed_ms=int((time.monotonic() - started) * 1000))

        sock.sendall(_build_client_hello(major, minor, cipher_codes))
        header = _recvn(sock, 5)
        elapsed = int((time.monotonic() - started) * 1000)
        if len(header) < 5:
            return ProbeResult(host, port, protocol, CATEGORY_TLS_CLOSED,
                               "server_closed_without_alert",
                               elapsed_ms=elapsed)
        content_type = header[0]
        record_length = struct.unpack("!H", header[3:5])[0]
        payload = _recvn(sock, record_length)
        if content_type == 21:  # alert
            if len(payload) < 2:
                return ProbeResult(host, port, protocol, CATEGORY_TLS_MALFORMED,
                                   "truncated_alert_record", detail=payload.hex(),
                                   elapsed_ms=elapsed)
            level = payload[0]
            code = payload[1]
            return ProbeResult(
                host, port, protocol, CATEGORY_TLS_ALERT,
                f"fatal_alert_{TLS_ALERTS.get(code, 'unknown')}",
                alert_code=f"0x{code:02x}",
                alert_name=TLS_ALERTS.get(code, "unknown"),
                detail=f"alert_level={level}",
                elapsed_ms=elapsed,
            )
        if content_type == 22:  # handshake message
            if payload and payload[0] == 2:  # ServerHello
                # ServerHello layout: type(1) length(3) version(2) random(32)...
                negotiated = None
                downgraded = False
                if len(payload) >= 6:
                    negotiated = VERSION_TO_PROTOCOL.get(
                        (payload[4], payload[5]),
                        f"{payload[4]}.{payload[5]}",
                    )
                    downgraded = (payload[4], payload[5]) != (major, minor)
                return ProbeResult(host, port, protocol, CATEGORY_SUCCESS,
                                   "server_hello_downgraded" if downgraded
                                   else "server_hello_received",
                                   negotiated=negotiated, elapsed_ms=elapsed,
                                   detail="downgraded_by_server"
                                          if downgraded else None)
            handshake_type = payload[0] if payload else None
            return ProbeResult(host, port, protocol, CATEGORY_TLS_MALFORMED,
                               "unexpected_handshake_message",
                               detail=f"handshake_type={handshake_type}",
                               elapsed_ms=elapsed)
        return ProbeResult(host, port, protocol, CATEGORY_TLS_MALFORMED,
                          "unexpected_content_type",
                          detail=f"content_type={content_type}",
                          elapsed_ms=elapsed)
    except socket.timeout:
        return ProbeResult(host, port, protocol, CATEGORY_TLS_TIMEOUT,
                           "no_tls_response",
                           elapsed_ms=int((time.monotonic() - started) * 1000))
    except OSError as exc:
        return ProbeResult(host, port, protocol, CATEGORY_PROBE_ERROR,
                           type(exc).__name__, detail=str(exc),
                           elapsed_ms=int((time.monotonic() - started) * 1000))
    finally:
        sock.close()


def resolve_host(hostname: str) -> tuple[Optional[str], Optional[str]]:
    """Return (ip, error_category). Empty ip means a DNS failure."""
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET,
                                   socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return None, f"{CATEGORY_DNS_FAILURE}:{exc.errno}"
    if not infos:
        return None, CATEGORY_DNS_FAILURE
    return infos[0][4][0], None
