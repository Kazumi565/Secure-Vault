# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app import auth, upload, password_reset, models
from app.database import engine

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
