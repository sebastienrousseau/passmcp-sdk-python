<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Governance

passmcp-sdk-python is one repository in the passmcp family and is governed the way passmcp
is ([passmcp GOVERNANCE.md](https://github.com/sebastienrousseau/passmcp/blob/main/GOVERNANCE.md)).

## Roles

**Maintainer:** Sebastien Rousseau (<sebastian.rousseau@gmail.com>, GitHub
`@sebastienrousseau`), responsible for API stability, conformance gates,
releases, and security response.

**Contributor:** anyone who opens an issue or pull request per
[CONTRIBUTING.md](CONTRIBUTING.md).

## Scope

This repository owns the Apache-2.0 Python MCP client/server SDK (`passmcp-sdk`)
and its offline `passmcp` attestation verifier. The attestation JSON Schema and
rubric remain single-sourced in `passmcp-reporting` and `passmcp`
([ADR 0013](https://github.com/sebastienrousseau/passmcp/blob/main/docs/adr/0013-language-sdks-are-apache-satellites.md)).

## Version and release

This repository carries passmcp's version in lockstep. Releases are signed tags
cut by the Maintainer.
