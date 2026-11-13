<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Working on passmcp-sdk-python as an AI agent

Read [DEVELOPMENT.md](DEVELOPMENT.md) first for the local equivalent of every
CI gate.

## Non-negotiable invariants

1. **Apache-2.0 clean licensing**: every source file carries an `Apache-2.0`
   SPDX header (`reuse lint` must report 0 issues); never import GPL-3.0 code.
2. **Byte-exact attestation verification**: target descriptors are computed as
   `transport + "\n" + trim(endpoint)` in UTF-8, matching
   `satellion.com/passmcp-reporting/attestation` on `testdata/statement.json`.
3. **Conformance by default**:
   - Capability-gated RPC dispatch (`-32601` when capability is undeclared).
   - SEP-2164 on `2026-07-28`: missing `resources/read` returns `-32602` with
     `error.data.uri`.
   - SEP-2549 on `2026-07-28`: list responses validate and emit `_meta.ttlMs >= 0`
     and `_meta.cacheScope` in `{"public", "private"}`.
   - Stateless `server/discover` returns protocol version, server info,
     capabilities, and declared catalogs in one round-trip.
   - Read-only client execution policy refuses tools unless `readOnlyHint: true`
     or mutations are explicitly enabled.
4. **Signed commits and lockstep versioning**: commits carry SSH signatures and
   DCO `Signed-off-by:` trailers; release work happens on `feat/vX.Y.Z`.
