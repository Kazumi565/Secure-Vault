"""Offline SQLite/local-storage snapshots. Keys are backed up separately."""

import argparse
import hashlib
import json
import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from sqlalchemy.engine import make_url

from app.config import Settings


def checksum(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def backup(settings, output, *, stopped=False):
    if not stopped:
        raise ValueError("Stop every API/maintenance process, then pass --confirm-stopped")
    url = make_url(settings.database_url)
    if url.get_backend_name() != "sqlite" or settings.storage_backend != "local":
        raise ValueError("This helper supports SQLite with local objects. See docs/OPERATIONS.md for PostgreSQL/S3.")
    database = Path(url.database).resolve()
    objects = settings.storage_path.resolve()
    output = Path(output).resolve()
    if not database.is_file() or not objects.is_dir():
        raise ValueError("Database or object directory is missing")
    if output.is_relative_to(objects) or output == database:
        raise ValueError("Choose a backup location outside the live object directory and database")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vault-backup-") as temporary:
        snapshot = Path(temporary) / "vault.db"
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as source, sqlite3.connect(snapshot) as target:
            source.backup(target)
            keys = {r[0] for r in target.execute("SELECT storage_key FROM file_versions")}
            keys.update(r[0] for r in target.execute("SELECT avatar_key FROM accounts WHERE avatar_key IS NOT NULL"))
        paths = {"vault.db": snapshot}
        for key in sorted(keys):
            parts = PurePosixPath(key)
            if parts.is_absolute() or ".." in parts.parts or "\\" in key or ":" in key:
                raise ValueError("Invalid stored object path")
            source = (objects / key).resolve()
            if not source.is_relative_to(objects) or not source.is_file():
                raise ValueError(f"Referenced object is missing: {key}")
            paths["objects/" + key] = source
        manifest = {
            "format": 1,
            "files": {name: {"bytes": path.stat().st_size, "sha256": checksum(path)} for name, path in paths.items()},
        }
        # Exclusive creation prevents overwriting an existing backup.
        with output.open("xb") as stream:
            output.chmod(0o600)
            try:
                with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                    archive.writestr("manifest.json", json.dumps(manifest, indent=2))
                    for name, path in paths.items():
                        archive.write(path, name)
            except Exception:
                stream.close()
                output.unlink(missing_ok=True)
                raise
    return {"files": len(keys), "backup": str(output)}


def restore(archive_path, destination):
    destination = Path(destination).resolve()
    with zipfile.ZipFile(archive_path) as archive:
        if archive.getinfo("manifest.json").file_size > 20 * 1024 * 1024:
            raise ValueError("Backup manifest is too large")
        manifest = json.loads(archive.read("manifest.json"))
        if manifest.get("format") != 1 or not isinstance(manifest.get("files"), dict):
            raise ValueError("Unsupported backup format")
        entries = manifest["files"]
        names = archive.namelist()
        if "vault.db" not in entries or len(set(names)) != len(names) or set(names) != set(entries) | {"manifest.json"}:
            raise ValueError("Archive contents do not match the manifest")
        for name, metadata in entries.items():
            parts = PurePosixPath(name)
            if (
                parts.is_absolute()
                or ".." in parts.parts
                or "\\" in name
                or ":" in name
                or (name != "vault.db" and (len(parts.parts) < 2 or parts.parts[0] != "objects"))
            ):
                raise ValueError("Invalid backup path")
            if archive.getinfo(name).file_size != metadata["bytes"]:
                raise ValueError("Backup size does not match the manifest")
        destination.mkdir(parents=True, exist_ok=False)
        try:
            (destination / "objects").mkdir()
            for name, metadata in entries.items():
                target = destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(name) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o600)
                if checksum(target) != metadata["sha256"]:
                    raise ValueError("Backup checksum mismatch")
            with sqlite3.connect(destination / "vault.db") as connection:
                if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("Restored database failed its integrity check")
        except Exception:
            shutil.rmtree(destination)
            raise
    return {"restored": str(destination), "objects": len(entries) - 1}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("backup")
    export.add_argument("--output", required=True)
    export.add_argument("--confirm-stopped", action="store_true")
    recover = sub.add_parser("restore")
    recover.add_argument("--input", required=True)
    recover.add_argument("--destination", required=True)
    args = parser.parse_args()
    result = (
        backup(Settings(), args.output, stopped=args.confirm_stopped)
        if args.command == "backup"
        else restore(args.input, args.destination)
    )
    print(json.dumps(result))


if __name__ == "__main__":
    main()
