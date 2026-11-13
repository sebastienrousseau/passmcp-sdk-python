#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
tag="${1:-${GITHUB_REF_NAME:-}}"
[ -n "$tag" ] || { echo "usage: $0 vX.Y.Z" >&2; exit 2; }
ver="${tag#v}"
grep -Eq "^## \[$ver\]" CHANGELOG.md || { echo "CHANGELOG.md has no '## [$ver]' heading" >&2; exit 1; }
grep -Eq "^version: \"?$ver\"?$" CITATION.cff || { echo "CITATION.cff does not say version $ver" >&2; exit 1; }
grep -q "Every component is released at \*\*$ver\*\*" README.md || { echo "README.md ecosystem section does not say $ver" >&2; exit 1; }
[ -f "docs/releases/v$ver.md" ] || { echo "docs/releases/v$ver.md is missing" >&2; exit 1; }
grep -q '^## Highlights ⭐️' "docs/releases/v$ver.md" || { echo "docs/releases/v$ver.md has no Highlights section" >&2; exit 1; }
echo "release versions agree on $ver"
