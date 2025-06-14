from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app import auth, upload, models
from app.database import engine
from fastapi.staticfiles import StaticFiles

# Create tables
models.Base.metadata.create_all(bind=engine)

# ✅ Create the FastAPI app
app = FastAPI()

# ✅ Add CORS middleware after app is defined
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Correct static mount
app.mount("/static", StaticFiles(directory="static"), name="static")

# ✅ Include routers
app.include_router(auth.router)
app.include_router(upload.router)
