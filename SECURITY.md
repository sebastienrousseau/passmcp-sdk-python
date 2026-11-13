<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security Policy

passmcp-sdk-python builds MCP servers and clients and verifies `passmcp` evaluation
attestations offline before admission decisions.

## Reporting a Vulnerability

Report security issues privately via
[GitHub private vulnerability reporting](https://github.com/sebastienrousseau/passmcp-sdk-python/security/advisories/new).
Do not open a public issue. Acknowledgement within **72 hours**; remediation
within **90 days**.

## Security Invariants

- **Target digests are recomputed, never trusted**: `covers` and `validate`
  recompute SHA-256 and SHA-512 over `transport + "\n" + trim(endpoint)` and
  reject mismatched subject names, missing rubric versions, and inconsistent
  verdict counts.
- **Read-only by default**: client execution policies refuse tools without
  `readOnlyHint: true` unless mutations are explicitly enabled.
- **Capability gating and Origin checks**: undeclared capabilities return
  JSON-RPC `-32601`, missing resources return SEP-2164 `-32602` with
  `error.data.uri` on `2026-07-28`, and untrusted HTTP `Origin` headers are
  rejected before dispatch.
