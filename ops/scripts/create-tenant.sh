#!/usr/bin/env bash
set -euo pipefail

TENANT="$1"

if [[ -z "${TENANT}" ]]; then
  echo "usage: $0 <tenant-name>"
  exit 1
fi

echo "Creating vcluster for tenant: ${TENANT}"

vcluster create "${TENANT}" \
  --namespace "tenant-${TENANT}" \
  --create-namespace

echo "Creating namespaces inside vcluster"

vcluster connect "${TENANT}" -- kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${TENANT}-agents
---
apiVersion: v1
kind: Namespace
metadata:
  name: ${TENANT}-preflight
---
apiVersion: v1
kind: Namespace
metadata:
  name: ${TENANT}-production
EOF

echo "Tenant ${TENANT} ready"