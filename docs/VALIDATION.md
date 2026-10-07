# Validation of the v2 update

Validated on 7 October 2026 against an isolated copy of backend commit `c741bb9f7c0a8daff2dded7b910037816bf13d9a` and frontend commit `277eae7e4956bc65ebee9d4f00030c0b97da0312`.

## Completed locally

| Check | Result |
| --- | --- |
| Backend regression suite, temporary SQLite/local storage | 36 passed |
| Frontend component/API tests | 6 passed |
| Chromium browser workflows, desktop and mobile | 2 passed |
| Python Ruff lint and formatting | Passed |
| Frontend ESLint and Prettier | Passed |
| Vite production build | Passed |
| Runtime Python dependency audit | No known vulnerabilities reported |
| npm dependency audit | No known vulnerabilities reported |

Backend coverage includes ownership/admin denial, verified-user restrictions, CSRF/origin checks, session revocation, reset token reuse, concurrent password reset/login, concurrent admin demotion safeguards, MFA/recovery codes, authenticated ciphertext tamper rejection, key wrapping/rotation, numeric sorting, quota concurrency, failed-upload rollback, durable orphan cleanup, versions/trash, shared-link passwords/counts/revocation, avatar decoding, migration/import rollback, outbox retries, SMTP certificate verification, and SQLite backup/restore integrity.

S3 operations were tested with Moto and an injected permission error, not a live AWS account. SMTP transport/certificate configuration was tested with controlled transports; real email delivery was not exercised.

The desktop browser test performs a real upload, tags/metadata update, version upload, protected anonymous share download, download-limit rejection, search, trash/restore, and sign-out. The mobile test exercises responsive controls, dark mode, Romanian labels, sessions, and sign-out. Screenshots in this directory are from that running application with fictional fixture files.

Playwright ran against Chromium 153 in this environment. The usual Playwright browser download returned an invalid archive here, so the successful local run selected a separately packaged Chromium executable through `CHROMIUM_EXECUTABLE_PATH`. That temporary browser package is not part of the project dependencies.

## Checks requiring another environment

- The PostgreSQL service job is defined in GitHub Actions; it has not been run here. It creates a unique schema per test in a local dedicated `secure_vault_test` database and refuses arbitrary database targets.
- Docker builds, Compose startup, and the Nginx deployment configuration need a smoke test with Docker available.
- The Windows PowerShell apply script was reviewed and its payload/manifest were checked; it was not executed on Windows here.
- Live AWS IAM, SMTP deliverability, HTTPS/proxy behavior, and PostgreSQL/S3 backup recovery need commissioning checks in the actual deployment.
- These are regression tests and dependency checks, not an independent security audit or a production-readiness certification.

## Scope of the changes

The update replaces the original API/frontend integration together. It fixes the reviewed upload failure, plaintext database file-key storage, hardcoded signing configuration, unsafe test bootstrap, incorrect unit sorting, filename-based admin deletion, server-side verification gaps, reset/session behavior, avatar validation, object cleanup, browser credential storage, stale preview URLs, missing dependencies, and fresh-database migrations.

The v2 schema has an explicit legacy import path. Old JWTs and action tokens do not carry over; legacy avatars require replacement. SQLAlchemy models now store byte counts as 64-bit values, and SQLite account/file identifiers are not reused after deletion.

Git authorship, contributor history, and prior pull requests were not rewritten.
