<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to passmcp-sdk-python are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions are
[Semantic Versioning](https://semver.org/) shaped.

**This repository carries passmcp's version.** It is in lockstep with
[passmcp](https://github.com/sebastienrousseau/passmcp) ([ADR 0013](https://github.com/sebastienrousseau/passmcp/blob/main/docs/adr/0013-language-sdks-are-apache-satellites.md)):
it starts at `Status: Unreleased` on `feat/v0.0.10` and joins the family
release stream with its first signed tag.

## [Unreleased]

### Added

- **Initial Python MCP client and server core (`passmcp-sdk`)** covering MCP
  revisions `2025-06-18`, `2025-11-25`, and `2026-07-28`: capability-gated
  JSON-RPC 2.0 dispatch (`initialize`, `ping`, stateless `server/discover`,
  `tools/list`, `tools/call`, `resources/list`, `resources/templates/list`,
  `resources/read`, `prompts/list`, `prompts/get`), JSON Schema `inputSchema`
  validation with `structuredContent` support, SEP-2164 unknown-resource errors
  (`-32602` with `error.data.uri` on `2026-07-28`), SEP-2549 list cache hints
  (`ttlMs`, `cacheScope`, and `_meta`), strict HTTP `Origin` validation, and
  read-only-by-default client tool execution policy (`readOnlyHint: true`).
- **Stdio and Streamable HTTP transports** (`serve_stdio`, `StdioTransport`,
  `StreamableHttpHandler`, WSGI/`BaseHTTPRequestHandler` adapters, and
  `HttpClientTransport`) supporting child-process pipes, `2026-07-28` mirrored
  header validation (`-32020`), `404` unknown-method framing, Bearer token
  challenges, and `Mcp-Session-Id` lifecycle on handshake revisions, plus a
  runnable `examples/stdio_server.py` clearing `passmcp check --stdio` at
  `100/100` (`A`, `0` failures, `0` warnings).
- **OAuth 2.1 + S256 PKCE and metadata discovery** (`generate_pkce_verifier`,
  `compute_s256_challenge`, `verify_s256`, `WWW-Authenticate` Bearer challenge
  builder/parser, RFC 9728 Protected Resource Metadata URL derivation and
  resource-binding validation, and RFC 8414 Authorization Server Metadata
  validation).
- **Offline `passmcp` attestation verifier** for `https://in-toto.io/Statement/v1`
  statements carrying `https://satellion.com/attestation/mcp-evaluation/v1`,
  recomputing SHA-256 and SHA-512 over the canonical target descriptor
  (`transport + "\n" + trim(endpoint)`) and verifying verdict counts, rubric
  presence, `covers(transport, endpoint)`, and `verdict_for(check_id)` against
  `passmcp-reporting`'s fixture.
