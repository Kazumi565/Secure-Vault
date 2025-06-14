import os
import uuid
from datetime import datetime
from io import BytesIO

from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from fastapi.responses import StreamingResponse
import csv
from io import StringIO

from app.database import SessionLocal
from app.models import File as FileModel, User, AuditLog
from app.auth import get_current_user, get_admin_user

router = APIRouter()

UPLOAD_FOLDER = "encrypted_files"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ───────────────────────── AES helpers ────────────────────────────
def encrypt_file(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ct                      # 16 + 16 + ciphertext

def decrypt_file(blob: bytes, key: bytes) -> bytes:
    nonce, tag, ct = blob[:16], blob[16:32], blob[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

# ───────────────────────── DB dependency ──────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ───────────────────────── Upload ─────────────────────────────────
@router.post("/upload")
async def upload_file(
    upload_file: UploadFile = File(...),
    current_user: User      = Depends(get_current_user),
    db: Session             = Depends(get_db)
):
    raw = await upload_file.read()
    key = get_random_bytes(32)                      # AES-256
    blob = encrypt_file(raw, key)

    stored_name = f"{uuid.uuid4().hex}.bin"
    with open(os.path.join(UPLOAD_FOLDER, stored_name), "wb") as f:
        f.write(blob)

    new = FileModel(
        filename       = upload_file.filename,
        stored_filename= stored_name,
        upload_time    = datetime.utcnow(),
        owner_id       = current_user.id,
        encryption_key = key.hex()
    )
    db.add(new)
    db.add(AuditLog(action=f"Uploaded file: {upload_file.filename}",
                    user_id=current_user.id))
    db.commit(); db.refresh(new)

    return {"message": "File uploaded.", "file_id": new.id}

# ───────────────────────── List files ─────────────────────────────
@router.get("/files")
def list_user_files(
    current_user: User = Depends(get_current_user),
    db: Session        = Depends(get_db)
):
    files = db.query(FileModel).filter(
        FileModel.owner_id == current_user.id).all()
    return [
        {"id": f.id, "filename": f.filename,
         "uploaded_at": f.upload_time}
        for f in files
    ]

# ───────────────────────── Download ───────────────────────────────
@router.get("/download/{file_id}")
def download_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session        = Depends(get_db)
):
    f = db.query(FileModel).filter(
        FileModel.id == file_id,
        FileModel.owner_id == current_user.id).first()
    if not f:
        raise HTTPException(404, "File not found")

    path = os.path.join(UPLOAD_FOLDER, f.stored_filename)
    if not os.path.exists(path):
        raise HTTPException(500, "Encrypted blob missing")

    try:
        with open(path, "rb") as fh:
            decrypted = decrypt_file(fh.read(), bytes.fromhex(f.encryption_key))
        db.add(AuditLog(action=f"Downloaded file: {f.filename}",
                        user_id=current_user.id))
        db.commit()
    except Exception:
        raise HTTPException(500, "Decryption failed")

    return StreamingResponse(
        BytesIO(decrypted),
        media_type="application/octet-stream",
        headers={"Content-Disposition":
                 f'attachment; filename="{f.filename}"'}
    )

# ───────────────────────── Delete ─────────────────────────────────
@router.delete("/files/{file_id}", status_code=204)
def delete_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session        = Depends(get_db)
):
    f = db.query(FileModel).filter(
        FileModel.id == file_id,
        FileModel.owner_id == current_user.id).first()
    if not f:
        raise HTTPException(404, "File not found")

    # remove blob
    path = os.path.join(UPLOAD_FOLDER, f.stored_filename)
    if os.path.exists(path):
        os.remove(path)

    db.delete(f)
    db.add(AuditLog(action=f"Deleted file: {f.filename}",
                    user_id=current_user.id))
    db.commit()                                  # 204 → no body

    # ───────── ADMIN: delete any user's file ──────────────────────────
@router.delete("/admin/files/{file_id}", status_code=204)
def admin_delete_file(
    file_id: int,
    admin: User        = Depends(get_admin_user),   # only admins
    db: Session        = Depends(get_db)
):
    f = db.query(FileModel).filter(FileModel.id == file_id).first()
    if not f:
        raise HTTPException(404, "File not found")

    # remove encrypted blob
    path = os.path.join(UPLOAD_FOLDER, f.stored_filename)
    if os.path.exists(path):
        os.remove(path)

    db.delete(f)
    db.add(
        AuditLog(
            action=f"ADMIN deleted file: {f.filename}",
            user_id=admin.id,              # who performed the delete
        )
    )
    db.commit()


# ───────────────────────── Admin audit ────────────────────────────
@router.get("/admin/audit")
def view_audit_logs(
    db: Session        = Depends(get_db),
    admin: User        = Depends(get_admin_user)
):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).all()
    return [
        {"timestamp": l.timestamp, "user": l.user.email, "action": l.action}
        for l in logs
    ]
@router.get("/admin/audit/export")
def export_audit_csv(
    db: Session = Depends(get_db),
    admin: User = Depends(get_admin_user)
):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp).all()

    sio = StringIO()
    writer = csv.writer(sio)
    writer.writerow(["timestamp", "user", "action"])
    for l in logs:
        writer.writerow([l.timestamp.isoformat(), l.user.email, l.action])

    sio.seek(0)
    return StreamingResponse(
        sio,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit.csv"}
    )