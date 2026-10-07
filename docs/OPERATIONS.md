# Operations

## Configuration

Copy values from `.env.example`, then keep actual credentials in `.env` or a secret manager. Do not place secrets in the frontend or commit them.

| Setting | Purpose |
| --- | --- |
| `MASTER_KEY` | Required Fernet key for wrapping file keys, authenticator secrets, and queued mail |
| `PREVIOUS_MASTER_KEYS` | Comma-separated old wrapping keys, used during rotation/import |
| `DATABASE_URL` | SQLite URL or `postgresql+psycopg2://...` |
| `STORAGE_BACKEND` | `local` or `s3` |
| `STORAGE_PATH` | Local object directory, relative to the backend working directory unless absolute |
| `S3_BUCKET_NAME`, `AWS_REGION` | Private S3 bucket and region |
| `S3_ENDPOINT_URL` | Optional endpoint for a compatible S3 service |
| `FRONTEND_URL` | Exact browser origin used in links and origin validation |
| `ALLOWED_HOSTS` | Comma-separated API/reverse-proxy hostnames |
| `COOKIE_SECURE` | Must be `true` for production HTTPS |
| `EMAIL_PROVIDER` | `console` for local development; `smtp` for production |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD` | SMTP connection and authentication |
| `SMTP_TLS`, `SMTP_SSL` | STARTTLS or implicit TLS; production requires one |
| `SESSION_HOURS` | Session lifetime; defaults to 12 hours |
| `MAX_UPLOAD_BYTES`, `MAX_STORAGE_BYTES`, `TRASH_DAYS` | Upload limit, account quota, and trash retention |
| `ENVIRONMENT` | `development`, `test`, or `production`; production validates stricter settings |

AWS credentials follow boto3's standard credential chain. Use an IAM role where possible. A runtime identity needs access to its bucket (`ListBucket` for health/metadata checks and `GetObject`, `PutObject`, `DeleteObject` for the configured objects). Keep the bucket private and block public access. Permission failures are surfaced as failures, not interpreted as an empty bucket.

## Run and monitor

Apply migrations explicitly before serving:

```powershell
.\.venv\Scripts\python.exe -m app.manage upgrade
.\.venv\Scripts\python.exe -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 --no-access-log
```

The built-in maintenance loop runs approximately once a minute while the API is running. An administrator can also trigger maintenance, or run:

```powershell
.\.venv\Scripts\python.exe -m app.manage maintenance
```

It expires sessions/action tokens/rate buckets/shares, purges expired trash, retries object cleanup, and retries queued mail. Garbage markers must be over one hour old. One cycle processes at most 1,000 expired files and 1,000 storage markers. Monitor sustained cleanup failures and outbox growth. Stopping the API pauses its built-in maintenance.

`/healthz` reports process liveness. `/readyz` tests the v2 database schema and object-store connectivity. It does not prove that every object is intact or that SMTP can deliver email. Verify an upload/download and a real email when commissioning an installation.

Use a single backend worker for the SQLite development configuration. PostgreSQL is the target for concurrent deployments. SQLite mail delivery does not have PostgreSQL's `SKIP LOCKED` behavior; duplicate sends are possible with multiple workers.

## HTTPS deployment

The Compose stack binds only to loopback and uses development defaults. For a public deployment:

1. Terminate HTTPS at a trusted reverse proxy and serve frontend and API on the same origin.
2. Set `ENVIRONMENT=production`, `COOKIE_SECURE=true`, the HTTPS `FRONTEND_URL`, explicit `ALLOWED_HOSTS`, and working SMTP/TLS settings. Set a real email sender.
3. Keep the API and database ports private. Trust forwarded IP headers only from your reverse proxy; rate limits otherwise see the proxy address. The development Compose API trusts its isolated container network and exposes no host port. Reassess this if changing the network layout.
4. Use persistent storage and a protected master key with recoverable backups. Apply migrations once before starting multiple workers; the development Docker entrypoint assumes a single API service.
5. Match reverse-proxy body limits to `MAX_UPLOAD_BYTES` plus multipart overhead. The supplied Nginx configuration allows 26 MiB for the default 25 MiB files.
6. Validate HTTPS cookies, SMTP, storage permissions, backup restoration, quotas, and cleanup in that environment.

Nginx adds a restrictive content security policy for built frontend assets and disables URL access logs. Start Uvicorn with `--no-access-log` too: shared-link URLs contain bearer tokens. Configure any upstream access logs to redact sensitive paths/query strings. Do not put action/share URLs into analytics.

## SQLite + local object backups

The helper snapshots the SQLite database and every currently referenced object, records SHA-256 checksums, and refuses to overwrite an existing backup. The database includes plaintext metadata and session records; protect the backup itself. **The archive excludes `.env` and encryption keys. Back up those separately.** Losing the matching master key prevents recovery.

Stop every API and maintenance process before taking the snapshot, so database references and objects cannot change independently:

```powershell
.\.venv\Scripts\python.exe -m app.backup backup --output "D:\VaultBackups\vault-2026-10-07.zip" --confirm-stopped
```

Restore into a new, absent directory; the helper checks paths, sizes, hashes, and SQLite integrity:

```powershell
.\.venv\Scripts\python.exe -m app.backup restore --input "D:\VaultBackups\vault-2026-10-07.zip" --destination "C:\VaultRestore\check"
```

Use a separate test configuration pointed at the restored `vault.db` and `objects/`, with the matching master key. Keep it isolated from normal users, verify sign-in and representative downloads (including older versions), and compare account/file counts. Existing sessions are part of the snapshot: revoke them before reopening a restored service after an incident. Only switch the live service to restored data after successful verification.

The confirmation flag is an acknowledgment, not a mechanism that stops processes. This helper does not back up an original legacy schema or Docker's PostgreSQL database.

## PostgreSQL / S3 recovery

The SQLite helper intentionally refuses PostgreSQL/S3. Use a coordinated database/object backup with these steps:

1. Stop application writes and maintenance.
2. Use `pg_dump --format=custom --file=<backup.dump> <database>` with securely configured PostgreSQL credentials. Avoid embedding passwords in shell history.
3. Back up local object storage or the matching S3 objects/version IDs. Keep the wrapping keys and configuration in a separate protected backup. For S3, bucket versioning alone is not a full recovery procedure; retain a database-consistent object inventory and protect against version expiry/deletion.
4. Restore the database using `pg_restore` into a **new empty database**, and objects into a **new directory/bucket**. Do not run destructive restore options against the live database.
5. Point an isolated application instance at the restored database/storage with the matching keys. Verify counts, several existing downloads and old versions, account ownership, and a new upload. Record the result before accepting the backup as recoverable.

A live PostgreSQL/S3 recovery drill is still required for your deployment. The automated recovery test covers SQLite with local encrypted objects.

## Rotate the wrapping key

Stop writes/maintenance and back up the database, objects, and existing keys. Generate a new Fernet key using Python's `cryptography.fernet.Fernet.generate_key()` and store it securely; do not post it in logs or Git.

1. Set `MASTER_KEY` to the new key.
2. Put the previous key(s) in `PREVIOUS_MASTER_KEYS`.
3. Run:

   ```powershell
   .\.venv\Scripts\python.exe -m app.manage rewrap-keys --confirm-backup
   ```

4. Verify downloads, two-factor sign-in, and queued email delivery using the new configuration.
5. Remove old keys from the active configuration after successful verification. Retain the required old keys with historical backups until those backups expire.

The command transactionally rewraps file keys, authenticator secrets (including pending setup), and outbox messages. It does not rewrite each ciphertext object. Rotation cannot undo prior exposure of a data key or file plaintext.

## Git and submodules

Keep `.env`, databases, objects, avatars, and generated files out of commits. The frontend is a separate repository: commit/push its changes first, then commit the backend with the new `frontend` pointer. `git submodule update --init --recursive` checks out the exact recorded frontend version; it does not automatically select the latest frontend branch.
