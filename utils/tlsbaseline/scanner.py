#!/usr/bin/env python3
"""Orchestrate testssl.sh scans and enrich them with failure reasons."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Optional

from .parser import build_structure, load_flat_json
from .probe import (
    NETWORK_CATEGORIES,
    PROTOCOL_VERSIONS,
    ProbeResult,
    check_tcp,
    handshake_probe,
    resolve_host,
)


def find_testssl(start_dir: Optional[str] = None) -> str:
    cur = os.path.abspath(start_dir or os.getcwd())
    while True:
        candidate = os.path.join(cur, "testssl.sh")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    found = shutil.which("testssl.sh")
    if found:
        return found
    raise FileNotFoundError("could not locate testssl.sh")


def run_testssl(
    target: str,
    output_json: str,
    testssl_bin: Optional[str] = None,
    extra_args: Optional[list[str]] = None,
    timeout: int = 900,
) -> tuple[int, str, str]:
    """Run testssl.sh with flat JSON output.

    Returns (returncode, stdout, stderr).  The sandbox/CI flags
    (``--ssl-native`` and connect timeouts) can be supplied through
    ``extra_args``; the function itself stays environment agnostic.
    """
    binary = testssl_bin or find_testssl()
    cmd = [
        binary,
        "--color", "0",
        "--quiet",
        "--ip", "one",
        "--overwrite",
        "--jsonfile", output_json,
    ]
    if extra_args:
        cmd.extend(extra_args)
    cmd.append(target)

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", (
            f"testssl.sh timed out after {timeout}s: {exc.stderr or ''}")
    return proc.returncode, proc.stdout, proc.stderr


def _host_port(target: str) -> tuple[str, int]:
    target = target.replace("https://", "").replace("http://", "").rstrip("/")
    if ":" in target:
        host, port_text = target.rsplit(":", 1)
        return host, int(port_text.split("/", 1)[0])
    return target, 443


def classify_failure_reasons(
    host: str,
    port: int,
    structured: dict[str, Any],
    timeout: float = 5.0,
) -> tuple[list[dict[str, Any]], Optional[ProbeResult]]:
    """Probe every non-offered protocol and classify why it failed.

    Also returns the TCP layer result so a completely unreachable target
    can be flagged at scan level instead of per protocol.
    """
    failures: list[dict[str, Any]] = []
    tcp_result = check_tcp(host, port, timeout=timeout)

    if tcp_result.category in NETWORK_CATEGORIES:
        if not structured.get("protocols"):
            # testssl could not run any protocol check: record a scan level
            # failure so consumers do not have to infer it from empty lists.
            failures.append({
                "protocol": "ALL",
                "category": tcp_result.category,
                "reason": tcp_result.reason,
                "alert_code": None,
                "alert_name": None,
                "elapsed_ms": tcp_result.elapsed_ms,
                "detail": "no protocol result; target unreachable at TCP layer",
            })
            return failures, tcp_result
        for proto in structured.get("protocols", []):
            if not proto["offered"]:
                failures.append({
                    "protocol": proto["protocol"],
                    "category": tcp_result.category,
                    "reason": tcp_result.reason,
                    "alert_code": None,
                    "alert_name": None,
                    "elapsed_ms": tcp_result.elapsed_ms,
                })
        return failures, tcp_result

    for proto in structured.get("protocols", []):
        if proto["offered"] or proto["protocol"] not in PROTOCOL_VERSIONS:
            continue
        result = handshake_probe(host, port, proto["protocol"], timeout=timeout)
        failures.append({
            "protocol": proto["protocol"],
            "category": result.category,
            "reason": result.reason,
            "alert_code": result.alert_code,
            "alert_name": result.alert_name,
            "elapsed_ms": result.elapsed_ms,
            "detail": result.detail,
        })
    return failures, tcp_result


def scan(
    target: str,
    output_path: str,
    testssl_bin: Optional[str] = None,
    extra_args: Optional[list[str]] = None,
    timeout: int = 900,
    probe_timeout: float = 5.0,
    label: Optional[str] = None,
) -> dict[str, Any]:
    """Full pipeline: testssl run -> structured doc -> failure reasons."""
    host, port = _host_port(target)
    ip, dns_error = resolve_host(host)

    tmp_dir = tempfile.mkdtemp(prefix="tlsbaseline-")
    flat_path = os.path.join(tmp_dir, "testssl-flat.json")
    started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    started_monotonic = time.monotonic()
    try:
        run_info: dict[str, Any] = {
            "target": target,
            "testsslBin": _safe_find_testssl(testssl_bin),
            "extraArgs": extra_args or [],
        }

        if dns_error:
            structured = {
                "schemaVersion": "1.0",
                "target": {"host": host, "port": port, "ip": None},
                "protocols": [],
                "ciphers": [],
                "rawFindings": [],
            }
            failures = [{
                "protocol": "ALL",
                "category": dns_error.split(":", 1)[0],
                "reason": "name_resolution_failed",
                "alert_code": None,
                "alert_name": None,
                "detail": dns_error,
            }]
            tcp_category = dns_error.split(":", 1)[0]
        else:
            returncode, stdout, stderr = run_testssl(
                target, flat_path, testssl_bin=testssl_bin,
                extra_args=extra_args, timeout=timeout,
            )
            run_info["stdoutTail"] = (stdout + stderr)[-2000:]
            if os.path.isfile(flat_path):
                structured = build_structure(load_flat_json(flat_path),
                                             target=host, port=port)
            else:
                structured = {
                    "schemaVersion": "1.0",
                    "target": {"host": host, "port": port, "ip": ip},
                    "protocols": [],
                    "ciphers": [],
                    "rawFindings": [],
                }
            structured["target"]["ip"] = ip
            failures, tcp_result = classify_failure_reasons(
                ip or host, port, structured, timeout=probe_timeout,
            )
            tcp_category = tcp_result.category
            run_info["returnCode"] = returncode

        structured["scan"] = {
            "scannedAt": started,
            "durationMs": int((time.monotonic() - started_monotonic) * 1000),
            "label": label or target,
            "testssl": run_info,
            "connectivity": {
                "ip": ip,
                "tcpCategory": tcp_category,
                "reachable": tcp_category not in NETWORK_CATEGORIES,
            },
        }
        structured["failures"] = failures
        structured["summary"] = {
            "protocolsOffered": sum(1 for p in structured["protocols"]
                                    if p.get("offered")),
            "cipherCount": len(structured["ciphers"]),
            "failureCount": len(failures),
            "failureCategories": sorted({f["category"] for f in failures}),
        }

        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(structured, handle, indent=2, sort_keys=False)
            handle.write("\n")
        return structured
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _safe_find_testssl(explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    try:
        return find_testssl()
    except FileNotFoundError:
        return ""
