"""Create local settings without overwriting an existing .env."""

import secrets
from pathlib import Path

from cryptography.fernet import Fernet

root = Path(__file__).resolve().parents[1]
target = root / ".env"
if target.exists():
    raise SystemExit(".env already exists. Compare it with .env.example and update it manually.")
data = (root / ".env.example").read_text().replace("GENERATE_WITH_SETUP_SCRIPT", Fernet.generate_key().decode())
data = data.replace("GENERATE_STORAGE_PASSWORD", secrets.token_urlsafe(24))
target.write_text(data, encoding="utf-8")
target.chmod(0o600)
(root / "data").mkdir(exist_ok=True)
print("Created local settings. Keep .env private and back up MASTER_KEY.")
