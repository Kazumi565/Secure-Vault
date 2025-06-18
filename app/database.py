import os

# Force this before loading .env so TESTING is read from the actual system env
testing = os.getenv("TESTING") == "1"

# Emergency hardcoded override
if testing:
    DATABASE_URL = "postgresql://postgres:testpass@localhost:5432/securevault_test"
else:
    from dotenv import load_dotenv
    load_dotenv(".env")
    DATABASE_URL = os.getenv("DATABASE_URL")

# Confirm the connection string
print("📦 TESTING =", testing)
print("📦 DATABASE_URL =", DATABASE_URL)

# 🔐 Final safety check
if testing and "securevault_db" in DATABASE_URL:
    raise RuntimeError("🚨 TESTING is enabled but using production DB — aborting!")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
