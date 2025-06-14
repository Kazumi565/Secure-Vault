from fastapi import APIRouter, HTTPException, Depends, status, UploadFile, File, Body
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
import os
import uuid

from app import models, schemas, database

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ───────────── JWT config ─────────────
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ───────────── DB dependency ──────────
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ───────────── password utils ─────────
def hash_password(p: str): return pwd_context.hash(p)
def verify_password(p: str, h: str): return pwd_context.verify(p, h)

# ───────────── token helpers ──────────
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ───────────── current user helper ────
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> models.User:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise cred_exc
        token_data = schemas.TokenData(email=email)
    except JWTError:
        raise cred_exc

    user = db.query(models.User).filter(models.User.email == token_data.email).first()
    if user is None:
        raise cred_exc
    return user

# ───────────── register ───────────────
@router.post("/register", response_model=schemas.UserOut)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.email == user.email).first():
        raise HTTPException(400, "Email already registered")

    new_user = models.User(
        email=user.email,
        hashed_password=hash_password(user.password),
        full_name=user.full_name,
        role="user"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# ───────────── login ───────────────────
@router.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(401, "Invalid credentials")

    access_token = create_access_token(data={"sub": user.email, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

# ───────────── /me ─────────────────────
@router.get("/me", response_model=schemas.UserOut)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user

# ───────────── /me/profile-picture ─────
@router.patch("/me/profile-picture", response_model=schemas.UserOut)
def upload_profile_picture(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user)
):
    ext = os.path.splitext(file.filename)[-1]
    if ext.lower() not in (".jpg", ".jpeg", ".png", ".webp"):
        raise HTTPException(400, "Unsupported file type")

    avatar_id = f"{uuid.uuid4().hex}{ext}"
    avatar_path = os.path.join("static", "avatars", avatar_id)

    os.makedirs(os.path.dirname(avatar_path), exist_ok=True)

    with open(avatar_path, "wb") as f:
        f.write(file.file.read())

    user.profile_picture = f"/static/avatars/{avatar_id}"
    db.commit()
    db.refresh(user)
    return user

# ───────────── update full name ────────
class FullNameUpdate(BaseModel):
    full_name: str

@router.patch("/me/full-name", response_model=schemas.UserOut)
def update_full_name(
    update: FullNameUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user)
):
    user.full_name = update.full_name
    db.commit()
    db.refresh(user)
    return user

# ───────────── admin guard ─────────────
def get_admin_user(current_user: models.User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return current_user

# ───────────── admin user ops ──────────
@router.get("/admin/users", response_model=list[schemas.UserOut])
def get_all_users(db: Session = Depends(get_db), admin: models.User = Depends(get_admin_user)):
    return db.query(models.User).all()

@router.delete("/admin/users/{user_id}", status_code=204)
def delete_user(user_id: int, db: Session = Depends(get_db), admin: models.User = Depends(get_admin_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    db.delete(user)
    db.commit()

class RoleUpdate(BaseModel):
    role: str

@router.patch("/admin/users/{user_id}/role", response_model=schemas.UserOut)
def update_user_role(user_id: int, update: RoleUpdate, db: Session = Depends(get_db), admin: models.User = Depends(get_admin_user)):
    if update.role not in ("admin", "user"):
        raise HTTPException(400, "Invalid role")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    user.role = update.role
    db.commit()
    db.refresh(user)
    return user

# ───────────── delete own account ────────
class PasswordInput(BaseModel):
    password: str

@router.delete("/me", status_code=204)
def delete_own_account(
    data: PasswordInput,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    if not verify_password(data.password, current_user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect password")
    db.delete(current_user)
    db.commit()

# ───────────── change password ────────────
class PasswordChange(BaseModel):
    current_password: str
    new_password: str

@router.patch("/me/password", status_code=204)
def change_password(
    data: PasswordChange,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user)
):
    if not verify_password(data.current_password, user.hashed_password):
        raise HTTPException(400, "Incorrect current password")

    user.hashed_password = hash_password(data.new_password)
    db.commit()
