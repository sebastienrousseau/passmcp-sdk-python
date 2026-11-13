#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#
# Verify passmcp-sdk-python's row in passmcp's ecosystem.json against this working tree.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

manifest="${PASSMCP_ECOSYSTEM_URL:-https://raw.githubusercontent.com/sebastienrousseau/passmcp/main/ecosystem.json}"
mf=$(mktemp)
trap 'rm -f "$mf"' EXIT
curl -fsSL "$manifest" -o "$mf"
row=$(python3 - "$mf" <<'PYEOF'
import json, sys
m = json.load(open(sys.argv[1]))
rows = [r for r in m["repositories"] if r["name"] == "passmcp-sdk-python"]
if not rows:
    sys.exit("family: passmcp-sdk-python has no row in the family manifest")
r = rows[0]
print(r["status"], r["license"], r["language"], str(r["lockstep"]).lower())
PYEOF
)
read -r status licence language lockstep <<<"$row"

fail=0
have=$(basename -s .txt LICENSES/*.txt | head -1)
if [ "$licence" != "$have" ]; then
  echo "family: the manifest says $licence and LICENSES/ holds $have" >&2; fail=1
fi
if [ "$language" != "python" ] || [ ! -f "pyproject.toml" ]; then
  echo "family: the manifest says $language and expected pyproject.toml" >&2; fail=1
fi
if [ "$lockstep" != "true" ] || [ ! -x scripts/lockstep.sh ]; then
  echo "family: the manifest says lockstep=$lockstep" >&2; fail=1
fi
[ "$fail" -eq 0 ] && echo "family: the manifest's row for passmcp-sdk-python is true of this tree ($licence, $language, lockstep=$lockstep, $status)"
exit "$fail"
