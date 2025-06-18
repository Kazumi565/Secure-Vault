# app/upload.py
import io
import csv, mimetypes, uuid
from botocore.exceptions import ClientError
import datetime
from io import BytesIO, StringIO
from sqlalchemy.orm import joinedload


from fastapi import (
    APIRouter, UploadFile, File, Depends, HTTPException, Query
)
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from app.database import SessionLocal
from app.models  import File as FileModel, User, AuditLog
from app.auth    import get_current_user, get_admin_user
from app.utils.s3_utils import (
    upload_to_s3, download_from_s3,
    delete_from_s3, get_file_size_s3
)

router = APIRouter()
MAX_STORAGE_BYTES = 100 * 1024 * 1024          # 100 MB / user

# ────────────────── helpers ──────────────────
def _encrypt(data: bytes, key: bytes) -> bytes:
    c      = AES.new(key, AES.MODE_EAX)
    ct, tg = c.encrypt_and_digest(data)
    return c.nonce + tg + ct                 # 16 nonce + 16 tag + payload

def _decrypt(blob: bytes, key: bytes) -> bytes:
    nonce, tag, ct = blob[:16], blob[16:32], blob[32:]
    return AES.new(key, AES.MODE_EAX, nonce).decrypt_and_verify(ct, tag)

def _db():
    db = SessionLocal()
    try:    yield db
    finally: db.close()

def _hr(b: int) -> str:
    for u in ['B','KB','MB','GB','TB']:
        if b < 1024: return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"

def _used(uid: int, db: Session) -> int:
    total = 0
    for f in db.query(FileModel).filter(FileModel.owner_id == uid):
        try:    total += get_file_size_s3(f"{uid}/{f.stored_filename}")
        except: pass
    return total

# ────────────────── upload ───────────────────
@router.post("/upload")
async def upload_file(
    upload_file: UploadFile = File(...),
    current_user: User      = Depends(get_current_user),
    db: Session             = Depends(_db)
):
    raw  = await upload_file.read()
    used = _used(current_user.id, db)
    if used + len(raw) > MAX_STORAGE_BYTES:
        raise HTTPException(400, "Storage limit exceeded (100 MB)")

    aes   = get_random_bytes(32)
    blob  = _encrypt(raw, aes)
    key   = f"{uuid.uuid4().hex}.bin"
    upload_to_s3(key, blob, current_user.id)

    rec = FileModel(
        filename        = upload_file.filename,
        stored_filename = key,
        upload_time     = datetime.utcnow(),
        owner_id        = current_user.id,
        encryption_key  = aes.hex()
    )
    db.add_all([
        rec,
        AuditLog(
            action  = f"Uploaded file: {rec.filename} | "
                      f"Used {(used+len(raw))/1_048_576:.2f} MB",
            user_id = current_user.id
        )
    ])
    db.commit(); db.refresh(rec)
    return {"file_id": rec.id, "message": "File uploaded."}

# ────────────────── list / search ────────────
@router.get("/files")
def list_files(
    current_user: User = Depends(get_current_user),
    db: Session        = Depends(_db),
    search: str = Query(None),
    sort_by: str = Query("date", regex="^(name|date|size)$"),
    order:   str = Query("desc", regex="^(asc|desc)$")
):
    out = []
    for f in db.query(FileModel).filter(FileModel.owner_id == current_user.id):
        key = f"{current_user.id}/{f.stored_filename}"
        try:
            size_b = get_file_size_s3(key)
        except:               # orphan row → drop it
            db.delete(f); db.commit(); continue

        if search and search.lower() not in f.filename.lower():
            continue

        mime, _ = mimetypes.guess_type(f.filename)
        out.append({
            "id"        : f.id,
            "filename"  : f.filename,
            "uploaded_at": f.upload_time,
            "size"      : _hr(size_b),
            "file_type" : mime or "application/octet-stream"
        })

    rev = (order == "desc")
    if   sort_by == "name": out.sort(key=lambda x: x["filename"].lower(), reverse=rev)
    elif sort_by == "size": out.sort(key=lambda x: float(x["size"].split()[0]), reverse=rev)
    else:                   out.sort(key=lambda x: x["uploaded_at"],        reverse=rev)
    return out

# ────────────────── download ─────────────────
@router.get("/download/{file_id}")
def download_file(
    file_id: int,
    inline: bool = Query(False),
    current_user: User = Depends(get_current_user),
    db: Session        = Depends(_db)
):
    f = db.query(FileModel).filter(
        FileModel.id == file_id,
        FileModel.owner_id == current_user.id
    ).first()
    if not f:
        raise HTTPException(404, "File not found")

    try:
        blob = download_from_s3(f.stored_filename, current_user.id)
        data = _decrypt(blob, bytes.fromhex(f.encryption_key))
        if not inline:               # only log real downloads
            db.add(AuditLog(
                action  = f"Downloaded file: {f.filename}",
                user_id = current_user.id
            ))
            db.commit()
    except Exception:
        raise HTTPException(500, "Decryption failed")

    mime, _ = mimetypes.guess_type(f.filename)
    disp = "inline" if inline else "attachment"
    return StreamingResponse(
        BytesIO(data),
        media_type=mime or "application/octet-stream",
        headers={"Content-Disposition": f'{disp}; filename="{f.filename}"'}
    )

# ────────────────── delete (user) ───────────
@router.delete("/files/{file_id}", status_code=204)
def delete_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session        = Depends(_db)
):
    f = db.query(FileModel).filter(
        FileModel.id==file_id, FileModel.owner_id==current_user.id
    ).first()
    if not f: raise HTTPException(404, "File not found")

    delete_from_s3(f.stored_filename, current_user.id)
    db.delete(f)
    db.add(AuditLog(action=f"Deleted file: {f.filename}", user_id=current_user.id))
    db.commit()

# ────────────────── usage ────────────────────
@router.get("/storage-usage")
def storage_usage(
    current_user: User = Depends(get_current_user),
    db: Session        = Depends(_db)
):
    return {"used_mb": round(_used(current_user.id, db)/1_048_576, 2)}

# ────────────────── admin audit (unchanged) ─
@router.get("/admin/audit")
def audit(
    db: Session = Depends(_db),
    admin: User = Depends(get_admin_user)
):
    logs = (
        db.query(AuditLog)
          .options(joinedload(AuditLog.user))    # eager-load user if present
          .order_by(AuditLog.timestamp.desc())
          .all()
    )
    return [
        {
            "timestamp": l.timestamp,
            "user":     l.user.email if l.user else "(deleted user)",
            "action":   l.action
        }
        for l in logs
    ]

@router.get("/admin/audit/export")
def export_audit(
        db: Session = Depends(_db),
        admin: User = Depends(get_admin_user)):

    # ── fetch with user join ──
    logs = (
        db.query(AuditLog)
          .options(joinedload(AuditLog.user))
          .order_by(AuditLog.timestamp)
          .all()
    )

    # ── build CSV in memory ──
    sio = io.StringIO(newline="")
    w   = csv.writer(sio)
    w.writerow(["timestamp", "user", "action"])

    for row in logs:
        user_email = row.user.email if row.user else "(deleted user)"
        w.writerow([row.timestamp.isoformat(), user_email, row.action])

    # ── convert to bytes ──
    byte_io = io.BytesIO(sio.getvalue().encode("utf-8"))
    sio.close()

    # ── stream it out ──
    today = datetime.date.today().isoformat()
    return StreamingResponse(
        byte_io,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="audit-{today}.csv"'
        },
    )

@router.get("/admin/files")
def admin_list_files(
    db   : Session = Depends(_db),
    admin: User    = Depends(get_admin_user)        # ⬅ requires admin
):
    rows = db.query(FileModel).all()
    return [
        {
            "id"       : f.id,
            "filename" : f.filename,
            "owner_id" : f.owner_id,
            "uploaded" : f.upload_time.isoformat(),
        }
        for f in rows
    ]


@router.delete("/admin/files/{file_id}")
def admin_delete_file(
    file_id: int,
    db   : Session = Depends(_db),
    admin: User    = Depends(get_admin_user)
):
    f = db.query(FileModel).filter(FileModel.id == file_id).first()
    if not f:
        raise HTTPException(404, "File not found")

    # try to drop the object from S3 — ignore “already gone”
    try:
        delete_from_s3(f.stored_filename, f.owner_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("NoSuchKey", "404", "NotFound"):
            # any *other* S3 error bubbles up as 502
            raise HTTPException(502, f"S3 delete failed: {code}")

    # wipe DB row + audit
    db.delete(f)
    db.add(
        AuditLog(action=f"ADMIN deleted {f.filename}", user_id=admin.id)
    )
    db.commit()

    return {"status": "ok", "message": f"{f.filename} purged"}