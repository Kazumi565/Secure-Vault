import logging
import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker

logger = logging.getLogger(__name__)

testing = os.getenv("TESTING") == "1"

if not testing:
    load_dotenv(".env")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")

url_obj = make_url(DATABASE_URL)
safe_db_identifier = url_obj.database or "unknown"
logger.info("Connecting to %s database '%s'", url_obj.get_backend_name(), safe_db_identifier)

if testing and safe_db_identifier and "securevault" in safe_db_identifier:
    raise RuntimeError("TESTING is enabled but attempting to use a production-like database")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
