#!/usr/bin/env bash
set -euo pipefail

kubectl create namespace vcluster || true

helm repo add loft-sh https://charts.loft.sh
helm repo update

helm upgrade --install vcluster \
  loft-sh/vcluster \
  --namespace vcluster \
  --values values.yaml