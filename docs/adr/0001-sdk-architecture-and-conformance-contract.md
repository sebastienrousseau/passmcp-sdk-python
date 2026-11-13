<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 0001 - Initial Python SDK architecture and conformance contract

**Status:** Accepted · **Date:** 2026-11-12

## Context

`passmcp-sdk-python` (`passmcp-sdk`) is the Python MCP client and server SDK in the `passmcp`
family ([passmcp ADR 0013](https://github.com/sebastienrousseau/passmcp/blob/main/docs/adr/0013-language-sdks-are-apache-satellites.md)).
Servers built on generic JSON-RPC wrappers routinely fail `passmcp`'s protocol,
catalog, and security checks because capability gating, `Origin` validation,
SEP-2164 missing-resource payloads, SEP-2549 list cache hints, stateless
`server/discover`, and read-only execution policies are left to application
boilerplate.

## Decision

1. **Capability-derived server dispatch**: `capabilities` in `initialize` and
   `server/discover` are derived from registered handlers rather than hand-typed
   booleans. Calling `tools/*`, `resources/*`, or `prompts/*` when none are
   registered returns JSON-RPC `-32601`.
2. **Revision-aware protocol errors and cache metadata**: on `2026-07-28`,
   missing resources return `-32602` with `data.uri` (SEP-2164) and list
   endpoints validate `ttlMs >= 0` and `cacheScope` in `{"public", "private"}`
   (SEP-2549).
3. **Read-only client policy by default**: client tool execution refuses tools
   lacking `readOnlyHint: true` unless explicitly configured with
   `allow_mutations`.
4. **Offline `in-toto` evaluation verifier**: validates `Statement/v1`
   (`mcp-evaluation/v1`) bytes without network calls, recomputing SHA-256 and
   SHA-512 digests over `transport + "\n" + trim(endpoint)`.
