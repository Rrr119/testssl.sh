# TLS baseline tooling

Structured JSON output, historical baseline diffing and handshake failure
classification on top of testssl.sh's `--jsonfile` output.

The tool is pure Python standard library (Python 3.8+) and lives next to
`testssl.sh`, so no extra dependencies are needed on scanning hosts.

## Why

testssl.sh already emits a flat JSON array, but:

* cipher details (hex code, IANA name, key exchange, strength) are packed
  into a fixed width `finding` string, which is awkward for an asset
  inventory to parse;
* unsupported protocols/ciphers are recorded as "not offered" without the
  reason (TLS alert? closed port? timeout? DNS failure?);
* there is no built-in comparison between two scans at cipher granularity.

## Commands

```
utils/tls_baseline.py scan <target> -o scan.json [--ssl-native]
    [--openssl-timeout N] [--socket-timeout N] [--checks '-p -E -P']
    [--label NAME] [--timeout N] [--probe-timeout N]

utils/tls_baseline.py parse <testssl-flat.json> -o structured.json
utils/tls_baseline.py diff <baseline.json> <current.json> [-o diff.json]
    [--exit-code]
utils/tls_baseline.py probe <host> <port> <protocol> [--cipher-hex 0x002f]
```

`scan` runs testssl.sh with `--jsonfile`, normalises the result and then
performs raw TLS probes for every non-offered protocol to classify the
failure reason.

## Structured scan document

```json
{
  "schemaVersion": "1.0",
  "target": { "host": "www.example.com", "port": 443, "ip": "..." },
  "scan": {
    "scannedAt": "2026-11-26T10:00:00+0800",
    "label": "www.example.com",
    "connectivity": { "ip": "...", "tcpCategory": "success",
                      "reachable": true },
    "testssl": { "returnCode": 0, "extraArgs": ["--ssl-native"] }
  },
  "protocols": [
    { "protocol": "TLS1_2", "offered": true,
      "severity": "OK", "detail": "offered" }
  ],
  "ciphers": [
    {
      "key": "cipher-tls1_2_xc02f",
      "id": "cipher-tls1_2_xc02f",
      "offered": true,
      "severity": "OK",
      "protocol": "TLSv1.2",
      "hex_code": "0xc02f",
      "openssl_name": "ECDHE-RSA-AES128-GCM-SHA256",
      "iana_name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "key_exchange": "ECDH 256",
      "encryption": "AESGCM",
      "bits": 128
    }
  ],
  "failures": [
    {
      "protocol": "TLS1",
      "category": "tls_alert",
      "reason": "fatal_alert_protocol_version",
      "alert_code": "0x46",
      "alert_name": "protocol_version"
    }
  ],
  "summary": {
    "protocolsOffered": 1,
    "cipherCount": 2,
    "failureCount": 5,
    "failureCategories": ["tls_alert", "tls_connection_closed"]
  },
  "rawFindings": [ ... ]
}
```

### Stable cipher identity

Every cipher item carries `key`, which is the testssl finding id
(`cipher-<proto>_x<hex>`, e.g. `cipher-tls1_2_xc030`). It encodes protocol
and cipher hex code and therefore stays stable across scans, locales and
OpenSSL versions. The diff uses this key, so changes are attributed to the
exact cipher suite.

### Failure categories

| Category                  | Meaning                                            |
| ------------------------- | -------------------------------------------------- |
| `dns_failure`             | hostname does not resolve                          |
| `tcp_refused`             | TCP RST / connection refused                       |
| `tcp_timeout`             | SYN without a response                             |
| `tcp_unreachable`         | other network/route error                          |
| `tls_alert`               | TLS alert received (with `alert_code`/`alert_name`)|
| `tls_connection_closed`   | server closed without sending an alert             |
| `tls_timeout`             | TCP connected but no TLS response                  |
| `tls_malformed_response`  | response could not be parsed                       |
| `probe_error`             | local probe error                                  |

Common alert names: `handshake_failure` (0x28), `protocol_version`
(0x46), `insufficient_security` (0x47), `inappropriate_fallback` (0x56),
`unrecognized_name` (0x70).

## Diff document

`diff` compares protocols, ciphers and failures by stable key:

```json
{
  "summary": { "cipherChanges": 2, "protocolChanges": 1,
               "failureChanges": 0, "hasChanges": true },
  "ciphers": {
    "added":   [ { "key": "cipher-tls1_2_x009c", "item": { ... } } ],
    "removed": [ { "key": "cipher-tls1_2_xc02f", "item": { ... } } ],
    "changed": [ { "key": "cipher-tls1_2_xc030",
                   "changes": { "severity": { "old": "OK",
                                              "new": "MEDIUM" } } } ],
    "counts": { "added": 1, "removed": 1, "changed": 1 }
  }
}
```

With `--exit-code` the command exits `2` when differences are found,
which makes it usable in CI.

## Tests

```
# unit tests (no network)
cd utils && python3 -m unittest discover -s tlsbaseline/tests

# end-to-end acceptance test (local openssl s_server instances)
prove t/70_tls_baseline.t
```
