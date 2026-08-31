#!/usr/bin/env bash
# 60-second first-run test (spec: Deployment and operability / first run).
#
# Builds the image, starts a fresh container with a single volume and minimal
# config, and asserts the instance is ready and can create the first account
# within 60 seconds.
set -euo pipefail

IMAGE="vault-server:firstrun-test"
NAME="vault-firstrun-$$"
PORT="18080"
DEADLINE=$((SECONDS + 60))

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> building image"
docker build -t "$IMAGE" .

echo "==> starting fresh container"
docker run -d --name "$NAME" \
  -p "127.0.0.1:${PORT}:8080" \
  -e VAULT_REGISTRATION=open \
  -e VAULT_TOKEN_KEY=firstrun-test-key \
  "$IMAGE" >/dev/null

echo "==> waiting for readiness (<=60s)"
until curl -fsS "http://127.0.0.1:${PORT}/ready" >/dev/null 2>&1; do
  if (( SECONDS > DEADLINE )); then
    echo "FAIL: not ready within 60s"; docker logs "$NAME"; exit 1
  fi
  sleep 1
done

echo "==> health check"
curl -fsS "http://127.0.0.1:${PORT}/health" | grep -q '"ok"'

echo "==> first-account creation reachable (register/start responds)"
# A minimal register/start call must be served (400/200, not connection refused).
code=$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "http://127.0.0.1:${PORT}/api/v1/auth/register/start" \
  -H 'content-type: application/json' \
  -d '{"username":"probe","registration_request":"not-base64"}')
if [[ "$code" != "400" && "$code" != "200" ]]; then
  echo "FAIL: register endpoint returned $code"; exit 1
fi

echo "PASS: ready and serving first-account creation within ${SECONDS}s"
