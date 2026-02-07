#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo "[1/3] vagrant up"
cd "$ROOT/vagrant"
vagrant up

echo "[2/3] ansible apply"
cd "$ROOT/ansible"
ansible-playbook -i inventories/demo/hosts.ini playbooks/site.yml

echo "[3/3] done"
echo "Tip: corré ops/scripts/status.sh"