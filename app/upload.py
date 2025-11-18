import csv
import datetime
import io
import logging
import mimetypes
import uuid
from io import BytesIO

from botocore.exceptions import ClientError
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session, joinedload
from Crypto.Cipher import AES

from app.database import SessionLocal
from app.models import File as FileModel, User, AuditLog
from app.auth import get_current_user, get_admin_user
from app.utils.s3_utils import upload_to_s3, download_from_s3, delete_from_s3, get_file_size_s3
from app.utils.key_manager import generate_encrypted_data_key, decrypt_data_key

router = APIRouter()
logger = logging.getLogger(__name__)
MAX_STORAGE_BYTES = 100 * 1024 * 1024  # 100 MB / user


def _encrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext  # 16 nonce + 16 tag + payload


def _decrypt(blob: bytes, key: bytes) -> bytes:
    nonce, tag, ciphertext = blob[:16], blob[16:32], blob[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def _db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _hr(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def _used(user_id: int, db: Session) -> int:
    total = 0
    rows = db.query(FileModel).filter(FileModel.owner_id == user_id)
    for record in rows:
        key = f"{user_id}/{record.stored_filename}"
        try:
            total += get_file_size_s3(key)
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.warning("Could not determine size for %s: %s", key, exc)
    return total


@router.post("/upload")
async def upload_file(
    upload_file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(_db),
):
    raw_bytes = await upload_file.read()
    used = _used(current_user.id, db)
    if used + len(raw_bytes) > MAX_STORAGE_BYTES:
        raise HTTPException(status_code=400, detail="Storage limit exceeded (100 MB)")

    aes_key, encrypted_data_key = generate_encrypted_data_key()
    blob = _encrypt(raw_bytes, aes_key)
    object_key = f"{uuid.uuid4().hex}.bin"
    upload_to_s3(object_key, blob, current_user.id)

    record = FileModel(
        filename=upload_file.filename,
        stored_filename=object_key,
        upload_time=datetime.datetime.utcnow(),
        owner_id=current_user.id,
        encrypted_data_key=encrypted_data_key,
    )
    db.add(record)
    db.add(
        AuditLog(
            action=(
                f"Uploaded file: {record.filename} | "
                f"Used {(used + len(raw_bytes)) / 1_048_576:.2f} MB"
            ),
            user_id=current_user.id,
        )
    )
    db.commit()
    db.refresh(record)
    return {"file_id": record.id, "message": "File uploaded."}


@router.get("/files")
def list_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(_db),
    search: str | None = Query(None),
    sort_by: str = Query("date", pattern="^(name|date|size)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
):
    files = []
    rows = db.query(FileModel).filter(FileModel.owner_id == current_user.id)
    for record in rows:
        key = f"{current_user.id}/{record.stored_filename}"
        try:
            size_bytes = get_file_size_s3(key)
        except Exception:  # pragma: no cover - cleanup path
            db.delete(record)
            db.commit()
            continue

        if search and search.lower() not in record.filename.lower():
            continue

        mime, _ = mimetypes.guess_type(record.filename)
        files.append(
            {
                "id": record.id,
                "filename": record.filename,
                "uploaded_at": record.upload_time,
                "size": _hr(size_bytes),
                "file_type": mime or "application/octet-stream",
            }
        )

    reverse = order == "desc"
    if sort_by == "name":
        files.sort(key=lambda item: item["filename"].lower(), reverse=reverse)
    elif sort_by == "size":
        files.sort(key=lambda item: float(item["size"].split()[0]), reverse=reverse)
    else:
        files.sort(key=lambda item: item["uploaded_at"], reverse=reverse)
    return files


@router.get("/download/{file_id}")
def download_file(
    file_id: int,
    inline: bool = Query(False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(_db),
):
    record = (
        db.query(FileModel)
        .filter(FileModel.id == file_id, FileModel.owner_id == current_user.id)
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="File not found")

    try:
        blob = download_from_s3(record.stored_filename, current_user.id)
        data_key = decrypt_data_key(record.encrypted_data_key)
        data = _decrypt(blob, data_key)
        if not inline:
            db.add(
                AuditLog(action=f"Downloaded file: {record.filename}", user_id=current_user.id)
            )
            db.commit()
    except Exception as exc:
        logger.error("Failed to decrypt file %s: %s", record.id, exc)
        raise HTTPException(status_code=500, detail="Decryption failed") from exc

    mime, _ = mimetypes.guess_type(record.filename)
    disposition = "inline" if inline else "attachment"
    return StreamingResponse(
        BytesIO(data),
        media_type=mime or "application/octet-stream",
        headers={"Content-Disposition": f'{disposition}; filename="{record.filename}"'},
    )


@router.delete("/files/{file_id}", status_code=204)
def delete_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(_db),
):
    record = (
        db.query(FileModel)
        .filter(FileModel.id == file_id, FileModel.owner_id == current_user.id)
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="File not found")

    delete_from_s3(record.stored_filename, current_user.id)
    db.delete(record)
    db.add(AuditLog(action=f"Deleted file: {record.filename}", user_id=current_user.id))
    db.commit()


@router.get("/storage-usage")
def storage_usage(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(_db),
):
    return {"used_mb": round(_used(current_user.id, db) / 1_048_576, 2)}


@router.get("/admin/audit")
def audit(
    db: Session = Depends(_db),
    admin: User = Depends(get_admin_user),
):
    logs = (
        db.query(AuditLog)
        .options(joinedload(AuditLog.user))
        .order_by(AuditLog.timestamp.desc())
        .all()
    )
    return [
        {
            "timestamp": log_entry.timestamp,
            "user": log_entry.user.email if log_entry.user else "(deleted user)",
            "action": log_entry.action,
        }
        for log_entry in logs
    ]


@router.get("/admin/audit/export")
def export_audit(
    db: Session = Depends(_db),
    admin: User = Depends(get_admin_user),
):
    logs = (
        db.query(AuditLog)
        .options(joinedload(AuditLog.user))
        .order_by(AuditLog.timestamp)
        .all()
    )

    string_buffer = io.StringIO(newline="")
    writer = csv.writer(string_buffer)
    writer.writerow(["timestamp", "user", "action"])
    for row in logs:
        user_email = row.user.email if row.user else "(deleted user)"
        writer.writerow([row.timestamp.isoformat(), user_email, row.action])

    byte_buffer = io.BytesIO(string_buffer.getvalue().encode("utf-8"))
    string_buffer.close()

    today = datetime.date.today().isoformat()
    return StreamingResponse(
        byte_buffer,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="audit-{today}.csv"'},
    )


@router.get("/admin/files")
def admin_list_files(
    db: Session = Depends(_db),
    admin: User = Depends(get_admin_user),
):
    rows = db.query(FileModel).all()
    return [
        {
            "id": record.id,
            "filename": record.filename,
            "owner_id": record.owner_id,
            "uploaded": record.upload_time.isoformat(),
        }
        for record in rows
    ]


@router.delete("/admin/files/{file_id}")
def admin_delete_file(
    file_id: int,
    db: Session = Depends(_db),
    admin: User = Depends(get_admin_user),
):
    record = db.query(FileModel).filter(FileModel.id == file_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="File not found")

    try:
        delete_from_s3(record.stored_filename, record.owner_id)
    except ClientError as exc:
        code = exc.response["Error"].get("Code")
        if code not in {"NoSuchKey", "404", "NotFound"}:
            raise HTTPException(status_code=502, detail=f"S3 delete failed: {code}") from exc

    db.delete(record)
    db.add(AuditLog(action=f"ADMIN deleted {record.filename}", user_id=admin.id))
    db.commit()

    return {"status": "ok", "message": f"{record.filename} purged"}
