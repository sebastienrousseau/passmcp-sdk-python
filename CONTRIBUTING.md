<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing

Contributions to passmcp-sdk-python follow the passmcp family rules.

## Workflow

1. Branch from `main` (release work collects on `feat/vX.Y.Z` targeting `main`).
2. Keep functions within complexity ceilings (McCabe <= 10, cognitive <= 15,
   <= 60 lines per function, <= 500 lines per file).
3. Add a failing-first unit test for every behaviour or conformance change.
4. Run `make check` (`lint`, `test`, `reuse`, `family`) and verify zero warnings.
5. Sign commits (`git commit -S -s`) with Conventional Commit subjects (`<= 50`
   characters) and a `Signed-off-by:` DCO trailer.
