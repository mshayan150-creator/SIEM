#!/bin/sh
set -eu
cd "$(dirname "$0")"
docker info >/dev/null
docker run --rm --mount "type=bind,source=$(pwd),target=/work" -w /work python:3.12-slim python ops/upgrade_local.py
docker compose -f compose.yaml up --build --force-recreate -d --wait --wait-timeout 240
printf '%s\n' 'Dashboard: http://127.0.0.1:8000' 'First install/upgrade: docker compose -f compose.yaml exec api python -m ops.admin create-user admin --role admin'
