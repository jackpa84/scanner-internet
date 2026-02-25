#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

CLUSTER_NAME="scanner"

echo ">>> Criando/garantindo cluster kind: $CLUSTER_NAME"
kind get clusters | grep -q "^${CLUSTER_NAME}\$" || \
  kind create cluster --name "$CLUSTER_NAME" --config k8s/kind-cluster.yaml

echo ">>> Buildando imagens Docker locais"
docker build -t scanner-app:latest .
docker build -t scanner-frontend:latest ./frontend

echo ">>> Carregando imagens no kind"
kind load docker-image scanner-app:latest --name "$CLUSTER_NAME"
kind load docker-image scanner-frontend:latest --name "$CLUSTER_NAME"

echo ">>> Aplicando manifests do Kubernetes"
kubectl apply -f k8s/mongo.yaml
kubectl apply -f k8s/app.yaml
kubectl apply -f k8s/frontend.yaml

if [ -f ".env" ]; then
  # Carrega HACKERONE_API_TOKEN se existir no .env, sem expor no log
  set +x
  # shellcheck disable=SC1091
  source .env || true
  set -x
  if [ "${HACKERONE_API_TOKEN-}" != "" ]; then
    echo ">>> Criando/atualizando Secret hackerone-api a partir do .env"
    kubectl create secret generic hackerone-api \
      --from-literal=token="${HACKERONE_API_TOKEN}" \
      --dry-run=client -o yaml | kubectl apply -f -
  else
    echo ">>> .env encontrado mas HACKERONE_API_TOKEN vazio; pulando Secret"
  fi
else
  echo ">>> .env não encontrado; pulando criação de Secret do HackerOne"
fi

echo ">>> Pronto! API em http://localhost:5000 e frontend em http://localhost:3000 (assim que os pods estiverem Ready)."

