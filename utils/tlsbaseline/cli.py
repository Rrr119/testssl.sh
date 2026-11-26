#!/usr/bin/env python3
"""Command line interface for the TLS baseline tooling.

Subcommands:

* ``scan``   run testssl.sh, emit a structured JSON document and
             classify handshake failures;
* ``parse``  convert an existing testssl.sh flat JSON file;
* ``diff``   compare two structured documents and locate per-cipher
             changes;
* ``probe``  run a single raw handshake probe (useful for triage).
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .diff import build_diff
from .parser import build_structure, load_flat_json
from .probe import PROTOCOL_VERSIONS, handshake_probe
from .scanner import find_testssl, scan


def _write_json(document: dict, path: str | None) -> None:
    text = json.dumps(document, indent=2)
    if path and path != "-":
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)


def cmd_scan(args: argparse.Namespace) -> int:
    extra = list(args.testssl_arg or [])
    if args.ssl_native:
        extra.append("--ssl-native")
    if args.openssl_timeout:
        extra.extend(["--openssl-timeout", str(args.openssl_timeout)])
    if args.socket_timeout:
        extra.extend(["--socket-timeout", str(args.socket_timeout)])
    if args.checks:
        extra.extend(args.checks.split())

    document = scan(
        target=args.target,
        output_path=args.output,
        testssl_bin=args.openssl_testssl or find_testssl(),
        extra_args=extra,
        timeout=args.timeout,
        probe_timeout=args.probe_timeout,
        label=args.label,
    )
    if not args.quiet:
        summary = document["summary"]
        print(
            f"scan complete: {summary['protocolsOffered']} protocol(s), "
            f"{summary['cipherCount']} cipher(s), "
            f"{summary['failureCount']} classified failure(s) -> {args.output}",
            file=sys.stderr,
        )
    return 0


def cmd_parse(args: argparse.Namespace) -> int:
    flat = load_flat_json(args.input)
    document = build_structure(flat)
    _write_json(document, args.output)
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    with open(args.baseline, encoding="utf-8") as handle:
        old_doc = json.load(handle)
    with open(args.current, encoding="utf-8") as handle:
        new_doc = json.load(handle)
    document = build_diff(old_doc, new_doc,
                          old_label=args.baseline_label or args.baseline,
                          new_label=args.current_label or args.current)
    _write_json(document, args.output)
    if args.exit_code and document["summary"]["hasChanges"]:
        return 2
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    if args.protocol not in PROTOCOL_VERSIONS:
        print(f"unknown protocol {args.protocol!r}, "
              f"choose one of {sorted(PROTOCOL_VERSIONS)}", file=sys.stderr)
        return 1
    cipher_codes = None
    if args.cipher_hex:
        cipher_codes = [int(code, 16) for code in args.cipher_hex.split(",")]
    result = handshake_probe(args.host, args.port, args.protocol,
                             cipher_codes=cipher_codes,
                             timeout=args.timeout)
    _write_json(result.to_dict(), args.output)
    return 0 if result.category == "success" else 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tls_baseline.py",
        description="Structured JSON, baseline diff and failure "
                    "classification for testssl.sh",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="run testssl.sh and emit structured JSON")
    scan_p.add_argument("target", help="host, host:port or URL")
    scan_p.add_argument("-o", "--output", required=True, help="output JSON path")
    scan_p.add_argument("--testssl", dest="openssl_testssl",
                        help="path to testssl.sh (auto-detected by default)")
    scan_p.add_argument("--label", help="label stored in the scan document")
    scan_p.add_argument("--ssl-native", action="store_true",
                        help="pass --ssl-native to testssl.sh")
    scan_p.add_argument("--openssl-timeout", type=int,
                        help="openssl timeout forwarded to testssl.sh")
    scan_p.add_argument("--socket-timeout", type=int,
                        help="socket timeout forwarded to testssl.sh")
    scan_p.add_argument("--checks", default="-p -E -P",
                        help="testssl.sh single-check flags "
                             "(default: '-p -E -P')")
    scan_p.add_argument("--testssl-arg", action="append",
                        help="extra raw testssl.sh argument (repeatable)")
    scan_p.add_argument("--timeout", type=int, default=900,
                        help="overall testssl.sh timeout in seconds")
    scan_p.add_argument("--probe-timeout", type=float, default=5.0,
                        help="timeout for raw failure-classification probes")
    scan_p.add_argument("-q", "--quiet", action="store_true")
    scan_p.set_defaults(func=cmd_scan)

    parse_p = sub.add_parser("parse",
                             help="convert an existing testssl flat JSON file")
    parse_p.add_argument("input")
    parse_p.add_argument("-o", "--output", default="-")
    parse_p.set_defaults(func=cmd_parse)

    diff_p = sub.add_parser("diff", help="diff two structured scan documents")
    diff_p.add_argument("baseline")
    diff_p.add_argument("current")
    diff_p.add_argument("-o", "--output", default="-")
    diff_p.add_argument("--baseline-label")
    diff_p.add_argument("--current-label")
    diff_p.add_argument("--exit-code", action="store_true",
                        help="exit 2 when differences are found")
    diff_p.set_defaults(func=cmd_diff)

    probe_p = sub.add_parser("probe", help="raw handshake probe for triage")
    probe_p.add_argument("host")
    probe_p.add_argument("port", type=int)
    probe_p.add_argument("protocol", choices=sorted(PROTOCOL_VERSIONS))
    probe_p.add_argument("--cipher-hex",
                         help="comma separated hex cipher codes, e.g. 0x002f")
    probe_p.add_argument("--timeout", type=float, default=5.0)
    probe_p.add_argument("-o", "--output", default="-")
    probe_p.set_defaults(func=cmd_probe)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
