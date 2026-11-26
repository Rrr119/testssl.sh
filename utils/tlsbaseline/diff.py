#!/usr/bin/env python3
"""Baseline diff between two structured scan documents.

The diff is key based rather than text based:

* protocols are compared by their testssl id (``TLS1_2`` ...);
* cipher suites are compared by the stable ``key`` (testssl id which
  encodes protocol and hex code, e.g. ``cipher-tls1_2_xc030``);
* failures are compared by protocol and category.

Every changed item carries the exact key so an asset inventory can
pinpoint the individual cipher suite that was added or removed.
"""

from __future__ import annotations

from typing import Any

DIFF_SCHEMA_VERSION = "1.0"

# Fields that describe an offered cipher item.  Identity fields (key, id,
# hex code) are excluded: a change there means remove + add, not an edit.
CIPHER_COMPARE_FIELDS = (
    "offered",
    "severity",
    "iana_name",
    "openssl_name",
    "key_exchange",
    "encryption",
    "bits",
)
PROTOCOL_COMPARE_FIELDS = ("offered", "severity", "detail")


def _index(items: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    indexed = {}
    for item in items:
        indexed[item[key]] = item
    return indexed


def _field_changes(old: dict[str, Any], new: dict[str, Any],
                   fields: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    changes = {}
    for field in fields:
        old_value = old.get(field)
        new_value = new.get(field)
        if old_value != new_value:
            changes[field] = {"old": old_value, "new": new_value}
    return changes


def diff_ciphers(old_doc: dict[str, Any],
                 new_doc: dict[str, Any]) -> dict[str, Any]:
    old_items = _index(old_doc.get("ciphers", []), "key")
    new_items = _index(new_doc.get("ciphers", []), "key")
    added, removed, changed = [], [], []

    for key in sorted(set(new_items) - set(old_items)):
        item = dict(new_items[key])
        item.pop("key", None)
        added.append({"key": key, "item": item})

    for key in sorted(set(old_items) - set(new_items)):
        item = dict(old_items[key])
        item.pop("key", None)
        removed.append({"key": key, "item": item})

    for key in sorted(set(old_items) & set(new_items)):
        field_changes = _field_changes(old_items[key], new_items[key],
                                       CIPHER_COMPARE_FIELDS)
        if field_changes:
            changed.append({
                "key": key,
                "hex_code": new_items[key].get("hex_code")
                            or old_items[key].get("hex_code"),
                "iana_name": new_items[key].get("iana_name")
                             or old_items[key].get("iana_name"),
                "changes": field_changes,
            })

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
    }


def diff_protocols(old_doc: dict[str, Any],
                   new_doc: dict[str, Any]) -> dict[str, Any]:
    old_items = _index(old_doc.get("protocols", []), "protocol")
    new_items = _index(new_doc.get("protocols", []), "protocol")
    added, removed, changed = [], [], []

    for name in sorted(set(new_items) - set(old_items)):
        added.append({"protocol": name, "item": new_items[name]})
    for name in sorted(set(old_items) - set(new_items)):
        removed.append({"protocol": name, "item": old_items[name]})
    for name in sorted(set(old_items) & set(new_items)):
        field_changes = _field_changes(old_items[name], new_items[name],
                                       PROTOCOL_COMPARE_FIELDS)
        if field_changes:
            changed.append({"protocol": name, "changes": field_changes})

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
    }


def diff_failures(old_doc: dict[str, Any],
                  new_doc: dict[str, Any]) -> dict[str, Any]:
    old_items = _index(old_doc.get("failures", []), "protocol")
    new_items = _index(new_doc.get("failures", []), "protocol")
    added, removed, changed = [], [], []

    for name in sorted(set(new_items) - set(old_items)):
        added.append({"protocol": name, "item": new_items[name]})
    for name in sorted(set(old_items) - set(new_items)):
        removed.append({"protocol": name, "item": old_items[name]})
    for name in sorted(set(old_items) & set(new_items)):
        if old_items[name] != new_items[name]:
            changed.append({
                "protocol": name,
                "old": old_items[name],
                "new": new_items[name],
            })

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
    }


def build_diff(old_doc: dict[str, Any], new_doc: dict[str, Any],
               old_label: str = "baseline",
               new_label: str = "current") -> dict[str, Any]:
    protocol_diff = diff_protocols(old_doc, new_doc)
    cipher_diff = diff_ciphers(old_doc, new_doc)
    failure_diff = diff_failures(old_doc, new_doc)

    summary = {
        "cipherChanges": sum(cipher_diff["counts"].values()),
        "protocolChanges": sum(protocol_diff["counts"].values()),
        "failureChanges": sum(failure_diff["counts"].values()),
        "hasChanges": any([
            sum(cipher_diff["counts"].values()),
            sum(protocol_diff["counts"].values()),
            sum(failure_diff["counts"].values()),
        ]),
    }

    return {
        "diffSchemaVersion": DIFF_SCHEMA_VERSION,
        "baseline": {
            "label": old_label,
            "scannedAt": old_doc.get("scan", {}).get("scannedAt"),
            "target": old_doc.get("target"),
        },
        "current": {
            "label": new_label,
            "scannedAt": new_doc.get("scan", {}).get("scannedAt"),
            "target": new_doc.get("target"),
        },
        "summary": summary,
        "protocols": protocol_diff,
        "ciphers": cipher_diff,
        "failures": failure_diff,
    }
