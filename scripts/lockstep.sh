#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# Verify passmcp-sdk-python's CHANGELOG version matches passmcp's lockstep rule. Until the
# first release tag is cut, an Unreleased-only CHANGELOG is valid while the
# manifest lists passmcp-sdk-python as unreleased.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

mine=$(grep -Eo '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' CHANGELOG.md | head -1 | tr -d '#[] ' || true)
if [ -z "$mine" ]; then
  grep -Eq '^## \[Unreleased\]' CHANGELOG.md || { echo "lockstep: CHANGELOG.md has neither a release heading nor Unreleased" >&2; exit 1; }
  echo "lockstep: passmcp-sdk-python is unreleased (## [Unreleased] ahead of first tag)"
  exit 0
fi

api="https://api.github.com/repos/sebastienrousseau/passmcp/releases/latest"
auth=()
[ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
release=$(mktemp)
trap 'rm -f "$release"' EXIT
code=$(curl -sSL "${auth[@]}" -H "Accept: application/vnd.github+json" -w '%{http_code}' "$api" -o "$release")
[ "$code" = "200" ] || { echo "lockstep: reading passmcp's latest release returned HTTP $code" >&2; exit 1; }
theirs=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tag_name"].lstrip("v"))' "$release")
if [ "$mine" = "$theirs" ]; then
  echo "lockstep: $mine matches passmcp's latest release"
else
  echo "lockstep: passmcp-sdk-python is at $mine and passmcp's latest release is $theirs" >&2
  exit 1
fi
