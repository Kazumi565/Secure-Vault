# app/main.py
import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from app import auth, upload, password_reset, models
from app.database import engine, SessionLocal

logger = logging.getLogger(__name__)

app = FastAPI()
models.Base.metadata.create_all(bind=engine)

# 👇 add every host/port you actually use locally
DEV_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",       # vite
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=DEV_ORIGINS,     # or ["*"] while developing
    allow_credentials=True,        # keeps Authorization header
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(auth.router)
app.include_router(password_reset.router)
app.include_router(upload.router)


@app.get("/healthz")
def health_check():
    """
    Health check endpoint that verifies DB and S3 connectivity.
    Returns 200 if healthy, 503 if any dependency is unavailable.
    """
    health_status = {"status": "healthy", "checks": {}}

    # Check database connectivity
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        health_status["checks"]["database"] = "ok"
    except Exception as exc:
        logger.error("Health check: Database connection failed: %s", exc)
        health_status["checks"]["database"] = "failed"
        health_status["status"] = "unhealthy"

    # Check S3 connectivity
    try:
        from app.utils.s3_utils import s3, S3_BUCKET_NAME
        s3.head_bucket(Bucket=S3_BUCKET_NAME)
        health_status["checks"]["s3"] = "ok"
    except Exception as exc:
        logger.error("Health check: S3 connection failed: %s", exc)
        health_status["checks"]["s3"] = "failed"
        health_status["status"] = "unhealthy"

    if health_status["status"] == "unhealthy":
        raise HTTPException(status_code=503, detail=health_status)

    return health_status
