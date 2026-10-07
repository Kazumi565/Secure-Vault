# Security model

## Protected data

New uploads are encrypted server-side using AES-256-GCM, a fresh random 256-bit key, and a random nonce for each version. The object key is authenticated as associated data. Data keys are Fernet-wrapped under `MASTER_KEY`; old wrapping keys can be supplied during rotation. Imported legacy objects retain authenticated AES-EAX until replaced by new versions.

Database access alone should not reveal file contents without the external wrapping key. Compromise of the running server or its master key can expose files. This is not end-to-end encryption or a zero-knowledge design. Filenames, tags, account details, audit data, and avatar images are not encrypted by this layer. Protect the database, object store, host, network, and backups as well.

## Accounts and authorization

- Argon2 hashes new passwords; legacy bcrypt hashes are accepted and upgraded at successful sign-in.
- Opaque session/reset/verification/share tokens are stored as hashes. Session cookies are HttpOnly and SameSite=Lax; production requires Secure cookies and HTTPS.
- Unsafe authenticated requests require a session-bound CSRF token. Unexpected browser origins are rejected, including on login and registration.
- The server checks file ownership and email verification. Administrator authorization is enforced by the API, not only by the interface.
- Password changes and resets revoke all sessions and outstanding action tokens. A password reset leaves existing two-factor authentication enabled.
- Two-factor setup requires the current password. Enabling it revokes other sessions; disabling it requires a second factor and revokes all sessions. Recovery codes are hashed and single-use. Used TOTP time steps cannot be reused for subsequent sign-ins/sensitive operations.
- Persistent rate limits cover registration, login, recovery, two-factor operations, and share creation/downloads. They are not a replacement for network-level abuse controls.

An administrator can list account/file metadata and permanently delete files or non-admin accounts. The ordinary download route still requires file ownership. A host/database administrator with the encryption keys has broader powers than the application's administrator UI.

## Files, quotas, and links

Uploads are bounded before encryption and charged atomically against the owner's quota. The quota includes all retained versions and trash. Database failure or object-store failure does not charge the logical quota; durable cleanup markers allow orphaned objects to be removed later.

Physical deletion is asynchronous. Cleanup processes markers older than one hour and retries failed removals. Current file-version and avatar references are checked before deletion. S3 versioning, provider backups, and external snapshots may retain prior object versions after an application deletion.

Only a small list of inert image/audio/video MIME types can be previewed. Other content, including HTML and SVG, downloads as attachments. Image uploads for avatars are decoded, size/dimension checked, re-encoded, and stripped of their original metadata.

Share URLs are bearer secrets. Anyone holding a valid link and its optional password can download the current version until expiry, revocation, or the download limit. A successful server response consumes a download even if the recipient closes the connection. Trashing a file revokes its links; restoring it does not recreate those links.

## Operational boundaries

Files are processed in bounded memory, not as arbitrarily large streaming encrypted uploads. Tune upload limits, worker concurrency, and memory together. The default single-process local setup is intended for personal use and development.

The mail outbox encrypts payloads and retries delivery. An interrupted send can deliver the same email twice; consumers should treat links as single-use. Development console email exposes action links in terminal logs by design. Do not use console delivery or the test fixture on a public service.

Audit history retains the actor's email and event details after account deletion, while account foreign keys are cleared. Define a retention policy appropriate to your deployment; deletion of an account is not a promise to erase external logs or backups.

The automated tests exercise specific security properties. They do not establish the absence of vulnerabilities or replace an independent deployment/security review.
