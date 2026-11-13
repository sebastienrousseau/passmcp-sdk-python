<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<h1 align="center">passmcp-sdk-python</h1>

<p align="center">
  Apache-2.0 Python MCP client and server SDK (`passmcp-sdk`) with capability-gated `2026-07-28` conformance and offline `passmcp` attestation verification.
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/passmcp-sdk-python/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/passmcp-sdk-python/ci.yml?branch=main&style=for-the-badge" alt="Build: CI status" /></a>
  <a href="https://github.com/sebastienrousseau/passmcp-sdk-python/releases"><img src="https://img.shields.io/github/v/release/sebastienrousseau/passmcp-sdk-python?style=for-the-badge" alt="Release: latest tag" /></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge" alt="License: Apache-2.0" /></a>
  <a href="https://github.com/sebastienrousseau/passmcp-sdk-python"><img src="https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge" alt="Python 3.11+" /></a>
</p>


## Contents

- [Install](#install)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [The passmcp-sdk-python ecosystem](#the-passmcp-sdk-python-ecosystem)
- [Capabilities at a glance](#capabilities-at-a-glance)
- [Ecosystem comparison](#ecosystem-comparison)
- [Benchmarks](#benchmarks)
- [Features](#features)
- [Configuration](#configuration)
- [Examples](#examples)
- [When not to use passmcp-sdk-python](#when-not-to-use-passmcp-sdk-python)
- [Development](#development)
- [Security](#security)
- [Documentation](#documentation)
- [Stability guarantees](#stability-guarantees)
- [License](#license)

---

## Install

```sh
pip install passmcp-sdk==0.0.10
```

---

## Requirements

| Requirement | Floor | Notes |
| :--- | :--- | :--- |
| Toolchain | Python 3.11+ | Enforced in `pyproject.toml` and `.github/workflows/ci.yml` |
| Licence | Apache-2.0 | Safe to embed in proprietary and open-source gateways, agents, and servers |
| Network | None for verification | Attestation parsing and `covers()` run strictly offline |

---

## Quick Start

```python
from pathlib import Path
from passmcp_sdk import McpServer, Tool, parse_statement

srv = McpServer(name="billing", version="0.0.10")
srv.register_tool(
    Tool(name="health", description="Read-only health probe", read_only_hint=True),
    lambda _args: "ok",
)

st = parse_statement(Path("testdata/statement.json").read_bytes())
assert st.covers("http", "https://mcp.example.com/mcp")
print(srv.name, st.score_grade)
```

---

## The passmcp-sdk-python ecosystem

Every component is released at **0.0.10** and moves in lockstep: one version across the family, released together ([docs/ecosystem.md](https://github.com/sebastienrousseau/passmcp/blob/main/docs/ecosystem.md)).

| Component | Purpose | Use case |
| :--- | :--- | :--- |
| [passmcp](https://github.com/sebastienrousseau/passmcp) | The MCP server diagnostic: checks in nine phases, every finding tied to the request that showed it, signed attestations | Test a server before your agents trust it, and gate it in CI |
| [passmcp-reporting](https://github.com/sebastienrousseau/passmcp-reporting) | The attestation format, its JSON Schemas and offline verifier, the graph model, and the agentgateway processor | Verify an attestation in a gateway, registry or pipeline |
| [passmcp-server](https://github.com/sebastienrousseau/passmcp-server) | passmcp's diagnostics as read-only MCP tools | Evaluate a server, or check an attestation, from inside the agent |
| [passmcp-action](https://github.com/sebastienrousseau/passmcp-action) | passmcp in GitHub Actions and GitLab CI, the image pinned by digest | Fail a build on the findings you choose |
| [passmcp-graph](https://github.com/sebastienrousseau/passmcp-graph) | A local graph of agents, servers, tools and identities built from attestations | Find inherited risk and over-privilege, and gate on policy |
| [passmcp-registry](https://github.com/sebastienrousseau/passmcp-registry) | A signed public scorecard of the MCP Registry's remote servers (no run published yet) | Check a public server's standing before connecting to it |
| [passmcp-lsp](https://github.com/sebastienrousseau/passmcp-lsp) | A language server for MCP artefacts, with check-id hover from the guidance catalogue | Catch mistakes in server.json, tool schemas and client configuration while editing |
| [passmcp-census](https://github.com/sebastienrousseau/passmcp-census) | The reliability census: methodology, disclosure log and reproduction command (no edition published yet) | Cite ecosystem-wide reliability figures, and reproduce them, once an edition is published |
| [satellion.com](https://github.com/sebastienrousseau/satellion.github.io) | The website, the Go module paths and the format URIs | Read the manual, and resolve `satellion.com/...` imports |
| [passmcp-sdk-go](https://github.com/sebastienrousseau/passmcp-sdk-go) | Apache-2.0 Go MCP client and server SDK with offline attestation verification (not yet released) | Build an MCP server or client in Go that clears passmcp's checks and verifies attestations offline |
| [passmcp-sdk-python](https://github.com/sebastienrousseau/passmcp-sdk-python) | Apache-2.0 Python MCP client and server SDK with offline attestation verification (not yet released) | Build an MCP server or client in Python that clears passmcp's checks and verifies attestations offline |
| [passmcp-sdk-java](https://github.com/sebastienrousseau/passmcp-sdk-java) | Apache-2.0 Java MCP client and server SDK with offline attestation verification (not yet released) | Build an MCP server or client in Java that clears passmcp's checks and verifies attestations offline |
| [passmcp-sdk-cpp](https://github.com/sebastienrousseau/passmcp-sdk-cpp) | Apache-2.0 C++20 MCP client and server SDK with offline attestation verification (not yet released) | Build an MCP server or client in C++ that clears passmcp's checks and verifies attestations offline |
| [passmcp-sdk-typescript](https://github.com/sebastienrousseau/passmcp-sdk-typescript) | Apache-2.0 TypeScript MCP client and server SDK with offline attestation verification (not yet released) | Build an MCP server or client in TypeScript that clears passmcp's checks and verifies attestations offline |
| [passmcp-sdk-rust](https://github.com/sebastienrousseau/passmcp-sdk-rust) | Apache-2.0 Rust MCP client and server SDK with offline attestation verification (not yet released) | Build an MCP server or client in Rust that clears passmcp's checks and verifies attestations offline |

---

## Capabilities at a glance

| Area | Capability | Status |
| :--- | :--- | :--- |
| Transports | Line-delimited `stdio` (`serve_stdio`, `StdioTransport`) and Streamable HTTP (`StreamableHttpHandler`, WSGI/`BaseHTTPRequestHandler`, `HttpClientTransport`) | Released in `0.0.10` |
| Protocol | JSON-RPC 2.0 `initialize`, `ping`, stateless `server/discover`, and `2026-07-28` mirrored header validation (`-32020`) | Released in `0.0.10` |
| Capability & schema gating | Derived `capabilities`, JSON Schema `inputSchema` validation (`-32602`), `structuredContent`, and `-32601` for undeclared RPCs | Released in `0.0.10` |
| SEP-2164 & SEP-2549 | Missing `resources/read` returns `-32602` + `error.data.uri` (`2026-07-28`); list responses validate & emit `ttlMs` / `cacheScope` | Released in `0.0.10` |
| Auth, Origin & safety | OAuth 2.1 S256 PKCE, RFC 9728 / RFC 8414 metadata validation, `OriginGuard`, and `readOnlyHint: true` default client policy | Released in `0.0.10` |
| Attestation | Offline `in-toto` `Statement/v1` (`mcp-evaluation/v1`) SHA-256 / SHA-512 target-descriptor verifier | Released in `0.0.10` |

---

## Ecosystem comparison

| Property | `passmcp-sdk-python` | Generic JSON-RPC / default SDK scaffolding |
| :--- | :--- | :--- |
| Undeclared capability RPCs | Derived from registered handlers; `-32601` automatically | Often left wired with empty lists or generic `-32603` errors |
| SEP-2164 & SEP-2549 (`2026-07-28`) | Built into resource reads and list responses | Hand-rolled per server |
| Client tool safety | Refuses unannotated tools by default (ADR 0004) | Executes any tool unless caller filters |
| Offline `passmcp` attestation check | Built-in `parse` / `validate` / `covers` / `verdict_for` | Custom SHA-256 + schema glue |

---

## Benchmarks

Micro-benchmarks for JSON-RPC dispatch and SHA-256 / SHA-512 statement
verification are run via `make test` and will be published with hardware notes
at the first tagged release (`v0.0.10`).

---

## Features

- **Server & client symmetry**: build servers that clear `passmcp check` and
  clients that enforce `passmcp` attestations and `readOnlyHint` policies before
  calling tools.
- **Stateless discovery (`server/discover`)**: one-request discovery of protocol
  revision, server identity, capabilities, tools, resources, templates, and
  prompts.
- **Zero-network attestation verification**: verifies `in-toto` statements
  against `passmcp-reporting`'s canonical target descriptor format.

---

## Configuration

Server and client options are passed explicitly via typed constructors (protocol
revision, allowed HTTP `Origin` values, SEP-2549 cache hints, and client
mutation policy) with zero hidden environment-variable magic.

---

## Examples

Run `make example` to execute [`examples/quickstart.py`](examples/quickstart.py),
or spawn [`examples/stdio_server.py`](examples/stdio_server.py) under `passmcp check --stdio`
(`100/100`, grade `A`, `0` failures, `0` warnings).

---

## When not to use passmcp-sdk-python

- **Diagnosing an existing third-party MCP server from the CLI or CI**: use
  [`passmcp`](https://github.com/sebastienrousseau/passmcp) directly.
- **Verifying DSSE / Sigstore cryptographic signatures**: verify the outer
  envelope with `cosign` or `gh attestation verify` first, then pass the
  verified statement payload to `passmcp-sdk-python`.

---

## Development

```sh
make check
```

See [DEVELOPMENT.md](DEVELOPMENT.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Security

See [SECURITY.md](SECURITY.md) for private vulnerability reporting and security
invariants.

---

## Documentation

- [DEVELOPMENT.md](DEVELOPMENT.md)
- [ADR Index](docs/adr/README.md)
- [passmcp Ecosystem Manual](https://satellion.com/passmcp/docs/)

---

## Stability guarantees

Pre-1.0 versions move in lockstep with `passmcp` by `0.0.1` increments. Any
change to what attestation verification accepts is treated as a breaking change
requiring a tracking issue and ADR update.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
