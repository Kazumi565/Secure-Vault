# Secure Vault

Secure Vault is a FastAPI-powered encrypted file storage API that demonstrates production-ready practices: envelope encryption of object keys, hardened configuration handling, asynchronous email dispatch, and automated CI/CD.

## Getting started
1. **Install dependencies**
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Create your environment file**
   ```bash
   cp .env.example .env
   ./scripts/generate_secret.sh >> .env
   ```
   Replace placeholders such as `DATABASE_URL`, SMTP credentials, and AWS access keys as needed.
3. **Run the API**
   ```bash
   uvicorn app.main:app --reload
   ```

### Docker Compose workflow
The repository ships with a `docker-compose.yml` that starts Postgres, MinIO (an S3-compatible store), a bootstrap container that creates the bucket, and the FastAPI app.
```bash
docker compose up --build
```
Copy `.env.example` to `.env` before starting the stack. The compose file already injects sane defaults for the services it provisions (database URL, MinIO credentials, S3 endpoint, etc.).

## Security considerations
* **Secrets stay out of the codebase** – `SECRET_KEY`, database URLs, and object storage credentials must come from the environment. The application fails fast when mandatory variables are missing or when the test flag points at a production-like database.
* **Envelope encryption** – Each uploaded file receives a unique AES-256 key. When `KMS_KEY_ID` is provided, AWS KMS generates and protects that key. Otherwise the key is encrypted with a server-side master Fernet key (`MASTER_KEY`). Only the encrypted blob is persisted in the database.
* **Safer logging** – Sensitive connection strings are no longer printed. Instead, structured logging surfaces only the backend name and database identifier.
* **Background email dispatch** – Verification and password-reset emails are queued via FastAPI `BackgroundTasks` to keep authentication endpoints responsive. SMTP and SendGrid are supported, with a `console` provider for tests/development.
* **S3 hygiene** – Client code never prints object keys containing secrets and supports a configurable endpoint URL for local MinIO usage.
* **Automated checks** – GitHub Actions runs Ruff, Flake8, Bandit, pip-audit, and the full pytest suite on every push/PR.

## How encryption works
1. When a file is uploaded, the service calls `generate_encrypted_data_key()`.
   * **KMS path** – `boto3` requests a data key from AWS KMS using the configured `KMS_KEY_ID`. KMS returns the plaintext AES key (used immediately for AES-EAX encryption) and a ciphertext blob. The ciphertext is base64-encoded and stored in the `files.encrypted_data_key` column.
   * **Local path** – If no `KMS_KEY_ID` is configured, a random AES-256 key is generated and encrypted with the server's Fernet `MASTER_KEY`. The encrypted bytes are base64-encoded before storage.
2. Downloading a file reverses the process: the encrypted data key is decoded, decrypted (via KMS or the master key), and passed to the AES-EAX decryptor. Plaintext keys are never stored or logged.
3. Tests cover both flows using Moto for S3/KMS emulation, guaranteeing parity between the two strategies.

## Testing & quality gates
```bash
pytest
ruff check .
flake8 app
bandit -r app -x app/tests
pip-audit -r requirements.txt
```
These commands mirror the GitHub Actions workflow located at `.github/workflows/ci.yml`.

## Email delivery
Set `EMAIL_PROVIDER` to one of:
* `smtp` – configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`.
* `sendgrid` – supply `SENDGRID_API_KEY`.
* `console` – useful for local development/tests; logs outbound messages.

Verification links point to the FastAPI `/verify-email` endpoint, while password reset links respect `FRONTEND_BASE_URL` so you can direct users to your UI.

## Threat model summary
* **Confidentiality** – Compromise of the relational database does not expose AES keys thanks to envelope encryption.
* **Integrity** – AES-EAX provides authenticated encryption for each object; tampering is detected before returning files.
* **Availability** – Email is dispatched asynchronously to avoid blocking auth workflows; Docker Compose provides an easy way to recreate the stack.
* **Operational hygiene** – CI guards against dependency vulnerabilities and obvious security smells.
