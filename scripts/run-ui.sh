#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

source .venv/bin/activate

pip install -r requirements-ui.txt

python -m playwright install chromium

uvicorn web.app:app \
  --host 127.0.0.1 \
  --port 8080 \
  --reload
