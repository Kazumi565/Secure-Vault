import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel
from sqlalchemy import func, select, update

from app.auth import delete_account_records, locked_user
from app.dependencies import admin_user, db_session, record, user_json, verified_user
from app.files import file_json, purge_file
from app.models import Account, AuditEvent, VaultFile

router = APIRouter(tags=["Activity and administration"])


def events(db, filters, offset, limit):
    count = db.scalar(select(func.count()).select_from(AuditEvent).where(*filters))
    rows = db.scalars(select(AuditEvent).where(*filters).order_by(AuditEvent.id.desc()).offset(offset).limit(limit))
    return {
        "total": count,
        "items": [
            {
                "id": r.id,
                "actor": r.actor_email,
                "owner_id": r.owner_id,
                "file_id": r.file_id,
                "filename": r.filename,
                "action": r.action,
                "detail": r.detail,
                "created_at": r.created_at.isoformat() + "Z",
            }
            for r in rows
        ],
    }


@router.get("/activity")
def activity(
    action: str = Query("", max_length=60),
    offset: int = Query(0, ge=0),
    limit: int = Query(30, ge=1, le=100),
    user=Depends(verified_user),
    db=Depends(db_session),
):
    filters = [AuditEvent.owner_id == user.id]
    if action:
        filters.append(AuditEvent.action == action)
    return events(db, filters, offset, limit)


@router.get("/admin/activity")
def admin_activity(
    action: str = Query("", max_length=60),
    owner_id: int | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(30, ge=1, le=100),
    admin=Depends(admin_user),
    db=Depends(db_session),
):
    filters = []
    if action:
        filters.append(AuditEvent.action == action)
    if owner_id is not None:
        filters.append(AuditEvent.owner_id == owner_id)
    return events(db, filters, offset, limit)


def csv_safe(value):
    value = str(value or "")
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value


@router.get("/admin/activity/export")
def export(admin=Depends(admin_user), db=Depends(db_session)):
    rows = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(10000))
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(["Timestamp (UTC)", "Actor", "Owner ID", "File ID", "Filename", "Action", "Detail"])
    for r in rows:
        writer.writerow(
            [
                csv_safe(v)
                for v in [
                    r.created_at.isoformat() + "Z",
                    r.actor_email,
                    r.owner_id,
                    r.file_id,
                    r.filename,
                    r.action,
                    r.detail,
                ]
            ]
        )
    return Response(
        stream.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="vault-activity.csv"'},
    )


@router.get("/admin/users")
def users(
    offset: int = Query(0, ge=0),
    limit: int = Query(30, ge=1, le=100),
    admin=Depends(admin_user),
    db=Depends(db_session),
):
    rows = db.scalars(select(Account).order_by(Account.id).offset(offset).limit(limit))
    return {
        "total": db.scalar(select(func.count()).select_from(Account)),
        "items": [user_json(u) | {"used_bytes": u.used_bytes} for u in rows],
    }


class RoleInput(BaseModel):
    role: str


def lock_administrators(db):
    if db.bind.dialect.name == "sqlite":
        db.execute(update(Account).where(Account.role == "admin").values(used_bytes=Account.used_bytes))
    return db.scalars(
        select(Account)
        .where(Account.role == "admin")
        .order_by(Account.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).all()


@router.patch("/admin/users/{user_id}/role")
def role(user_id: int, data: RoleInput, admin=Depends(admin_user), db=Depends(db_session)):
    if data.role not in {"user", "admin"}:
        raise HTTPException(400, "Role must be user or admin")
    if user_id == admin.id:
        raise HTTPException(400, "Another administrator must change your role")
    # Lock all administrators consistently so simultaneous demotions cannot remove all admins.
    administrators = lock_administrators(db)
    if not any(account.id == admin.id for account in administrators):
        raise HTTPException(403, "Administrator access required")
    user = locked_user(db, user_id)
    if not user:
        raise HTTPException(404, "Account not found")
    user.role = data.role
    record(db, admin, "role.changed", detail=f"Account {user.id}: {data.role}", owner_id=user.id)
    db.commit()
    return user_json(user)


@router.delete("/admin/users/{user_id}", status_code=204)
def delete_user(user_id: int, admin=Depends(admin_user), db=Depends(db_session)):
    user = db.get(Account, user_id)
    if not user:
        raise HTTPException(404, "Account not found")
    user = locked_user(db, user.id)
    if user.role == "admin":
        raise HTTPException(400, "Demote the administrator before deleting the account")
    delete_account_records(db, user, admin)
    db.commit()


@router.get("/admin/files")
def files(
    owner_id: int | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(30, ge=1, le=100),
    admin=Depends(admin_user),
    db=Depends(db_session),
):
    filters = [VaultFile.owner_id == owner_id] if owner_id is not None else []
    rows = db.scalars(select(VaultFile).where(*filters).order_by(VaultFile.id.desc()).offset(offset).limit(limit))
    return {
        "total": db.scalar(select(func.count()).select_from(VaultFile).where(*filters)),
        "items": [file_json(f) | {"owner_id": f.owner_id} for f in rows],
    }


@router.delete("/admin/files/{file_id}", status_code=204)
def delete_file(file_id: int, admin=Depends(admin_user), db=Depends(db_session)):
    item = db.get(VaultFile, file_id)
    if not item:
        raise HTTPException(404, "File not found")
    locked_user(db, item.owner_id)
    db.refresh(item)
    purge_file(db, item, admin)
    db.commit()


@router.post("/admin/maintenance")
def maintenance(request: Request, admin=Depends(admin_user)):
    from app.maintenance import run_maintenance

    return run_maintenance(request.app)
