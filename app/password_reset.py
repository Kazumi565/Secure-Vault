from fastapi import APIRouter, HTTPException, Body, Depends
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models import User, PasswordResetToken
from app.database import get_db
from app.auth import hash_password, verify_password  # reused from auth
from app.utils.email_utils import send_password_reset_email
from pydantic import BaseModel
import uuid

router = APIRouter()

# ✅ Input model for forgot password
class EmailInput(BaseModel):
    email: str

# ✅ Input model for reset password
class ResetPasswordInput(BaseModel):
    token: str
    new_password: str

@router.post("/forgot-password")
def forgot_password(data: EmailInput, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if user:
        token = str(uuid.uuid4())
        expires = datetime.utcnow() + timedelta(hours=1)
        db_token = PasswordResetToken(user_id=user.id, token=token, expires_at=expires)
        db.add(db_token)
        db.commit()

        reset_link = f"http://localhost:3000/reset-password?token={token}"
        send_password_reset_email(user.email, reset_link)

    return {"message": "If this email is registered, you will receive a reset link."}

@router.post("/reset-password")
def reset_password(
    data: ResetPasswordInput,
    db: Session = Depends(get_db)
):
    record = db.query(PasswordResetToken).filter(PasswordResetToken.token == data.token).first()
    if not record or record.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = db.query(User).filter(User.id == record.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # ✅ Prevent resetting to the same password
    if verify_password(data.new_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="New password must be different from the old one")

    user.hashed_password = hash_password(data.new_password)
    db.delete(record)
    db.commit()

    return {"message": "Password reset successfully"}
