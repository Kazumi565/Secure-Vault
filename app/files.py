import mimetypes
import secrets
import unicodedata
from datetime import timedelta
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError

from app.auth import locked_user
from app.dependencies import db_session, rate_limit, record, verified_user
from app.models import Account, FileVersion, Folder, ShareLink, StorageGarbage, VaultFile, now
from app.security import digest, hash_password, random_token, verify_password

router = APIRouter(tags=["Files"])


def clean_filename(value):
    value = unicodedata.normalize("NFC", value or "").strip()
    if (
        not value
        or value in {".", ".."}
        or len(value) > 240
        or any(ord(c) < 32 or c in "/\\" or ord(c) == 127 for c in value)
    ):
        raise HTTPException(400, "Filename is invalid or too long")
    return value


def owned_file(db, user, file_id, include_trash=False):
    item = db.scalar(select(VaultFile).where(VaultFile.id == file_id, VaultFile.owner_id == user.id))
    if not item or (item.deleted_at and not include_trash):
        raise HTTPException(404, "File not found")
    return item


def check_folder(db, user, folder_id):
    if folder_id is not None and not db.scalar(
        select(Folder.id).where(Folder.id == folder_id, Folder.owner_id == user.id)
    ):
        raise HTTPException(404, "Folder not found")


def file_json(item):
    return {
        "id": item.id,
        "filename": item.filename,
        "folder_id": item.folder_id,
        "tags": item.tags,
        "size_bytes": item.size_bytes,
        "mime_type": item.mime_type,
        "version": item.current_version,
        "updated_at": item.updated_at.isoformat() + "Z",
        "deleted_at": item.deleted_at.isoformat() + "Z" if item.deleted_at else None,
    }


def read_version(request, version):
    try:
        blob = request.app.state.storage.get(version.storage_key)
        return request.app.state.crypto.decrypt(blob, version.wrapped_key, version.storage_key, version.format)
    except Exception:
        raise HTTPException(503, "File is temporarily unavailable or failed its integrity check") from None


def download_response(data, filename, mime="application/octet-stream", inline=False):
    # Only inert image and media formats are previewed. HTML/SVG are always attachments.
    safe = {"image/jpeg", "image/png", "image/gif", "image/webp", "video/mp4", "video/webm", "audio/mpeg", "audio/ogg"}
    preview = inline and mime in safe
    disposition = "inline" if preview else "attachment"
    return Response(
        data,
        media_type=mime if preview else "application/octet-stream",
        headers={
            "Content-Disposition": f"{disposition}; filename=\"download\"; filename*=UTF-8''{quote(filename, safe='')}",
            "Content-Security-Policy": "sandbox; default-src 'none'",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/storage")
def usage(request: Request, user=Depends(verified_user), db=Depends(db_session)):
    trashed = db.scalar(
        select(func.coalesce(func.sum(FileVersion.size_bytes), 0))
        .join(VaultFile)
        .where(VaultFile.owner_id == user.id, VaultFile.deleted_at.is_not(None))
    )
    return {
        "used_bytes": user.used_bytes,
        "trash_bytes": trashed,
        "limit_bytes": request.app.state.settings.max_storage_bytes,
        "max_upload_bytes": request.app.state.settings.max_upload_bytes,
        "trash_days": request.app.state.settings.trash_days,
    }


@router.get("/files")
def list_files(
    search: str = Query("", max_length=200),
    tag: str = Query("", max_length=30),
    folder_id: int | None = None,
    trash: bool = False,
    sort: str = Query("date", pattern="^(name|date|size)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    offset: int = Query(0, ge=0),
    limit: int = Query(30, ge=1, le=100),
    user=Depends(verified_user),
    db=Depends(db_session),
):
    filters = [
        VaultFile.owner_id == user.id,
        VaultFile.deleted_at.is_not(None) if trash else VaultFile.deleted_at.is_(None),
    ]
    if search:
        filters.append(
            VaultFile.filename.ilike(
                "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%", escape="\\"
            )
        )
    if folder_id is not None:
        check_folder(db, user, folder_id)
        filters.append(VaultFile.folder_id == folder_id)
    # JSON membership varies between SQLite/PostgreSQL. A bounded tag array is small;
    # use a portable correlated JSON iterator in each supported backend.
    if tag:
        if db.bind.dialect.name == "sqlite":
            from sqlalchemy import exists

            values = func.json_each(VaultFile.tags).table_valued("value")
            filters.append(exists(select(1).select_from(values).where(values.c.value == tag.lower())))
        else:
            from sqlalchemy import cast
            from sqlalchemy.dialects.postgresql import JSONB

            filters.append(cast(VaultFile.tags, JSONB).contains([tag.lower()]))
    column = {"name": func.lower(VaultFile.filename), "date": VaultFile.updated_at, "size": VaultFile.size_bytes}[sort]
    ordering = column.desc() if order == "desc" else column.asc()
    total = db.scalar(select(func.count()).select_from(VaultFile).where(*filters))
    items = db.scalars(
        select(VaultFile).where(*filters).order_by(ordering, VaultFile.id).offset(offset).limit(limit)
    ).all()
    return {"items": [file_json(x) for x in items], "total": total}


def store_upload(request, upload, user, db, folder_id=None, item=None):
    settings = request.app.state.settings
    raw = upload.file.read(settings.max_upload_bytes + 1)
    if len(raw) > settings.max_upload_bytes:
        raise HTTPException(413, "File exceeds the upload limit")
    filename = clean_filename(upload.filename)
    key = f"{user.id}/{secrets.token_hex(24)}.bin"
    blob, wrapped = request.app.state.crypto.encrypt(raw, key)
    # A durable cleanup marker survives object-store or DB failures and process crashes.
    # Maintenance only processes markers older than an hour to protect active uploads.
    with request.app.state.sessions.begin() as journal:
        journal.add(StorageGarbage(key=key))
    try:
        user = locked_user(db, user.id)
        check_folder(db, user, folder_id)
        changed = db.execute(
            update(Account)
            .where(Account.id == user.id, Account.used_bytes + len(raw) <= settings.max_storage_bytes)
            .values(used_bytes=Account.used_bytes + len(raw))
        )
        if changed.rowcount != 1:
            raise HTTPException(413, "Storage quota exceeded. Empty trash or remove older versions.")
        if item is None:
            item = VaultFile(
                owner_id=user.id,
                filename=filename,
                folder_id=folder_id,
                size_bytes=len(raw),
                mime_type=mimetypes.guess_type(filename)[0] or "application/octet-stream",
            )
            db.add(item)
            db.flush()
            number = 1
        else:
            # Refresh after locking the owner to serialize simultaneous version uploads.
            db.refresh(item)
            if item.deleted_at:
                raise HTTPException(409, "Restore this file before adding a version")
            number = item.version_counter + 1
            item.version_counter = number
            item.current_version = number
            item.size_bytes = len(raw)
            item.updated_at = now()
        request.app.state.storage.put(key, blob)
        db.add(FileVersion(file_id=item.id, number=number, storage_key=key, wrapped_key=wrapped, size_bytes=len(raw)))
        record(db, user, "file.uploaded" if number == 1 else "version.uploaded", item, f"Version {number}")
        db.execute(delete(StorageGarbage).where(StorageGarbage.key == key))
        db.commit()
        return file_json(item)
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise HTTPException(503, "Upload failed. No storage quota was charged. Please retry.") from None


@router.post("/files", status_code=201)
def upload(
    request: Request,
    file: UploadFile = File(...),
    folder_id: int | None = Form(None),
    user=Depends(verified_user),
    db=Depends(db_session),
):
    return store_upload(request, file, user, db, folder_id=folder_id)


@router.post("/files/{file_id}/versions", status_code=201)
def upload_version(
    file_id: int, request: Request, file: UploadFile = File(...), user=Depends(verified_user), db=Depends(db_session)
):
    item = owned_file(db, user, file_id)
    return store_upload(request, file, user, db, folder_id=item.folder_id, item=item)


@router.get("/files/{file_id}/download")
def download(
    file_id: int,
    request: Request,
    inline: bool = False,
    version: int | None = None,
    user=Depends(verified_user),
    db=Depends(db_session),
):
    item = owned_file(db, user, file_id)
    ver = db.scalar(
        select(FileVersion).where(
            FileVersion.file_id == item.id, FileVersion.number == (version or item.current_version)
        )
    )
    if not ver:
        raise HTTPException(404, "Version not found")
    data = read_version(request, ver)
    if not inline:
        record(db, user, "file.downloaded", item, f"Version {ver.number}")
        db.commit()
    return download_response(data, item.filename, item.mime_type, inline)


class MetadataInput(BaseModel):
    filename: str = Field(min_length=1, max_length=240)
    folder_id: int | None = None
    tags: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, values):
        tags = sorted({v.strip().lower() for v in values if v.strip()})
        if any(len(v) > 30 or any(ord(c) < 32 for c in v) for v in tags):
            raise ValueError("Tags must be shorter than 31 characters")
        return tags


@router.patch("/files/{file_id}")
def metadata(file_id: int, data: MetadataInput, user=Depends(verified_user), db=Depends(db_session)):
    locked_user(db, user.id)
    item = owned_file(db, user, file_id)
    check_folder(db, user, data.folder_id)
    item.filename = clean_filename(data.filename)
    item.folder_id = data.folder_id
    item.tags = data.tags
    item.mime_type = mimetypes.guess_type(item.filename)[0] or "application/octet-stream"
    item.updated_at = now()
    record(db, user, "file.updated", item)
    db.commit()
    return file_json(item)


@router.delete("/files/{file_id}", status_code=204)
def trash(file_id: int, user=Depends(verified_user), db=Depends(db_session)):
    locked_user(db, user.id)
    item = owned_file(db, user, file_id)
    item.deleted_at = now()
    db.execute(delete(ShareLink).where(ShareLink.file_id == item.id))
    record(db, user, "file.trashed", item)
    db.commit()


@router.post("/files/{file_id}/restore")
def restore(file_id: int, user=Depends(verified_user), db=Depends(db_session)):
    locked_user(db, user.id)
    item = owned_file(db, user, file_id, include_trash=True)
    item.deleted_at = None
    item.updated_at = now()
    record(db, user, "file.restored", item)
    db.commit()
    return file_json(item)


def purge_file(db, item, actor):
    versions = db.scalars(select(FileVersion).where(FileVersion.file_id == item.id)).all()
    total = sum(v.size_bytes for v in versions)
    for v in versions:
        db.merge(StorageGarbage(key=v.storage_key))
    db.execute(update(Account).where(Account.id == item.owner_id).values(used_bytes=Account.used_bytes - total))
    record(db, actor, "file.purged", item)
    db.flush()
    db.delete(item)


@router.delete("/files/{file_id}/permanent", status_code=204)
def permanent(file_id: int, user=Depends(verified_user), db=Depends(db_session)):
    locked_user(db, user.id)
    item = owned_file(db, user, file_id, include_trash=True)
    if not item.deleted_at:
        raise HTTPException(409, "Move the file to trash first")
    purge_file(db, item, user)
    db.commit()


@router.get("/files/{file_id}/versions")
def versions(file_id: int, user=Depends(verified_user), db=Depends(db_session)):
    item = owned_file(db, user, file_id)
    rows = db.scalars(
        select(FileVersion).where(FileVersion.file_id == item.id).order_by(FileVersion.number.desc())
    ).all()
    return [
        {
            "number": v.number,
            "size_bytes": v.size_bytes,
            "created_at": v.created_at.isoformat() + "Z",
            "current": v.number == item.current_version,
        }
        for v in rows
    ]


@router.post("/files/{file_id}/versions/{number}/restore")
def restore_version(file_id: int, number: int, user=Depends(verified_user), db=Depends(db_session)):
    locked_user(db, user.id)
    item = owned_file(db, user, file_id)
    version = db.scalar(select(FileVersion).where(FileVersion.file_id == item.id, FileVersion.number == number))
    if not version:
        raise HTTPException(404, "Version not found")
    item.current_version = number
    item.size_bytes = version.size_bytes
    item.updated_at = now()
    record(db, user, "version.restored", item, f"Version {number}")
    db.commit()
    return file_json(item)


@router.delete("/files/{file_id}/versions/{number}", status_code=204)
def delete_version(file_id: int, number: int, user=Depends(verified_user), db=Depends(db_session)):
    locked_user(db, user.id)
    item = owned_file(db, user, file_id)
    if number == item.current_version:
        raise HTTPException(409, "Restore another version before deleting this one")
    version = db.scalar(select(FileVersion).where(FileVersion.file_id == item.id, FileVersion.number == number))
    if not version:
        raise HTTPException(404, "Version not found")
    db.merge(StorageGarbage(key=version.storage_key))
    db.execute(update(Account).where(Account.id == user.id).values(used_bytes=Account.used_bytes - version.size_bytes))
    record(db, user, "version.deleted", item, f"Version {number}")
    db.delete(version)
    db.commit()


class FolderInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)


@router.get("/folders")
def folders(user=Depends(verified_user), db=Depends(db_session)):
    return [
        {"id": f.id, "name": f.name}
        for f in db.scalars(select(Folder).where(Folder.owner_id == user.id).order_by(Folder.name))
    ]


@router.post("/folders", status_code=201)
def new_folder(data: FolderInput, user=Depends(verified_user), db=Depends(db_session)):
    item = Folder(owner_id=user.id, name=clean_filename(data.name))
    db.add(item)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "A folder with that name already exists") from None
    return {"id": item.id, "name": item.name}


@router.delete("/folders/{folder_id}", status_code=204)
def delete_folder(folder_id: int, user=Depends(verified_user), db=Depends(db_session)):
    locked_user(db, user.id)
    check_folder(db, user, folder_id)
    db.execute(delete(Folder).where(Folder.id == folder_id, Folder.owner_id == user.id))
    db.commit()


class ShareInput(BaseModel):
    hours: int = Field(default=24, ge=1, le=168)
    max_downloads: int = Field(default=5, ge=1, le=100)
    password: str = Field(default="", max_length=128)


@router.post("/files/{file_id}/shares", status_code=201)
def share(file_id: int, data: ShareInput, request: Request, user=Depends(verified_user), db=Depends(db_session)):
    rate_limit(request, "share-create", user.email, limit=30, seconds=3600)
    locked_user(db, user.id)
    item = owned_file(db, user, file_id)
    token = random_token()
    link = ShareLink(
        token_hash=digest(token),
        file_id=item.id,
        expires_at=now() + timedelta(hours=data.hours),
        max_downloads=data.max_downloads,
        password_hash=hash_password(data.password) if data.password else None,
    )
    db.add(link)
    record(db, user, "share.created", item)
    db.commit()
    return {"id": link.id, "url": f"{request.app.state.settings.frontend_url.rstrip('/')}/share/{token}"}


@router.get("/files/{file_id}/shares")
def shares(file_id: int, user=Depends(verified_user), db=Depends(db_session)):
    owned_file(db, user, file_id)
    return [
        {
            "id": x.id,
            "expires_at": x.expires_at.isoformat() + "Z",
            "downloads": x.downloads,
            "max_downloads": x.max_downloads,
            "password_protected": bool(x.password_hash),
        }
        for x in db.scalars(select(ShareLink).where(ShareLink.file_id == file_id).order_by(ShareLink.created_at.desc()))
    ]


@router.delete("/files/{file_id}/shares/{share_id}", status_code=204)
def revoke_share(file_id: int, share_id: str, user=Depends(verified_user), db=Depends(db_session)):
    item = owned_file(db, user, file_id, include_trash=True)
    db.execute(delete(ShareLink).where(ShareLink.id == share_id, ShareLink.file_id == file_id))
    record(db, user, "share.revoked", item)
    db.commit()


class SharePassword(BaseModel):
    password: str = Field(default="", max_length=128)


@router.post("/shared/{token}/download")
def shared_download(token: str, data: SharePassword, request: Request, db=Depends(db_session)):
    rate_limit(request, "share-download", limit=20)
    if len(token) > 100:
        raise HTTPException(404, "Link unavailable")
    link = db.scalar(select(ShareLink).where(ShareLink.token_hash == digest(token)))
    if not link:
        raise HTTPException(404, "Link unavailable")
    if link.password_hash and not verify_password(data.password, link.password_hash):
        raise HTTPException(403, "Incorrect link password")
    item = db.get(VaultFile, link.file_id)
    if not item or item.deleted_at:
        raise HTTPException(404, "Link unavailable")
    locked_user(db, item.owner_id)
    db.refresh(item)
    if item.deleted_at:
        raise HTTPException(404, "Link unavailable")
    claim = db.execute(
        update(ShareLink)
        .where(ShareLink.id == link.id, ShareLink.expires_at > now(), ShareLink.downloads < ShareLink.max_downloads)
        .values(downloads=ShareLink.downloads + 1)
    )
    if claim.rowcount != 1:
        raise HTTPException(404, "Link expired or download limit reached")
    version = db.scalar(
        select(FileVersion).where(FileVersion.file_id == item.id, FileVersion.number == item.current_version)
    )
    content = read_version(request, version)
    record(db, None, "share.downloaded", item)
    db.commit()
    return download_response(content, item.filename)
