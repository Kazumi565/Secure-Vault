#!/usr/bin/env bash
set -euo pipefail

SECRET_KEY=$(python - <<'PY'
import secrets
print(secrets.token_urlsafe(64))
PY
)

MASTER_KEY=$(python - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
)

echo "SECRET_KEY=${SECRET_KEY}"
echo "MASTER_KEY=${MASTER_KEY}"
