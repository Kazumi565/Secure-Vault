# Upgrading from the original application

This is a v2 schema and API transition. Deploy the backend and matching frontend together. Existing JWTs and reset/verification links are intentionally not carried over.

## Choose the right starting point

For a new local demonstration, use a new `.env`, the default SQLite database, and the default local object directory. Existing `.env` files are preserved by the update installer. Move an old configuration to a secure backup location before running `scripts/setup_dev.py`; do not overwrite it or discard old encryption keys.

For an installation with real accounts/files, use the import procedure below. Merely running `upgrade` creates new, empty v2 tables alongside legacy tables; it does not import accounts or files.

## Import existing data

1. Stop the old API, background jobs, and any process that can modify the database or stored objects.
2. Make a recoverable backup of the **entire legacy database**, **all objects**, and **all keys/settings**. Test that the backup is readable. Original database dumps may contain plaintext per-file AES keys and should be protected accordingly.
3. Create v2 settings from `.env.example`. Generate and securely save `MASTER_KEY`. Set `DATABASE_URL` to the existing database, and select the same object store used by the old installation. Standard AWS credentials come from the normal boto3 credential chain.
4. Install the new dependencies and run:

   ```powershell
   .\.venv\Scripts\python.exe -m app.manage upgrade
   .\.venv\Scripts\python.exe -m app.manage import-legacy --confirm-backup
   ```

5. Start the new backend and frontend. Verify account counts, ownership, sign-in, existing downloads, upload/download of a new version, and administrator access before reopening the service.

The importer supports the original `users`/`files` schema, hexadecimal AES keys, and authenticated AES-EAX objects at `<owner_id>/<stored_filename>`. It also accepts the later branch's base64-encoded Fernet-wrapped data keys if the corresponding wrapping key is configured as the current or a previous master key. AWS KMS data-key blobs require a separate migration; they are not supported by this importer.

The import authenticates every stored object before committing, preserves account/file IDs and password hashes, calculates quota usage from decrypted sizes, and wraps raw per-file keys. A missing/corrupt object, unusable key, duplicate normalized email, or invalid owner aborts the transaction. Imported bcrypt passwords are rehashed with Argon2 at the next successful login.

On success, old plaintext `files.encryption_key` values become `[migrated]`. This happens in the same database transaction as the new records. The importer refuses to run against populated v2 account tables. Do not register accounts in v2 before import.

Legacy avatars are not imported; users can upload replacements. Old audit messages are retained as `legacy.event` records, without inventing file IDs that were never recorded. Existing verification state is preserved; unverified users can request a new link. Account quota includes every imported file even if an account already exceeds the configured limit.

## Storage and rollback

Original local `encrypted_files/` copies are not automatically treated as the live object store. Inspect how the old installation stored files. The importer expects the owner-prefixed key layout; if local objects use another layout, prepare and verify a separate storage copy first.

Never run the old application against the database after a successful import: its raw key column has been scrubbed. To roll back, stop v2 and restore the **complete matching legacy database/object/key backup**, then run the old code. Any writes made after that backup would be lost. Keep the backup until the new installation has been exercised and a new backup has been restored successfully.

Database logs, WAL files, snapshots, and historical backups can retain earlier key values. Scrubbing the live column is not secure erasure of those copies.

## Repository cleanup

The update stops tracking bytecode, stored files, avatars, the duplicate frontend backup, shell artifacts, and `.env.test`. The installer retains their local contents; they remain excluded by `.gitignore`. The original committed database credentials remain in Git history and should be rotated. No history rewrite is part of this update.

The frontend remains its own repository. Commit/push it first, then commit the parent's updated submodule pointer.
