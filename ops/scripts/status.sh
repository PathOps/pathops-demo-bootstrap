#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cd "$ROOT/vagrant"
vagrant status

echo
echo "IPs:"
yq '.vms[] | "\(.name) -> \(.ip)"' config/vms.yml 2>/dev/null || true