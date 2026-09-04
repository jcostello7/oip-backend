"""
OIP Backend — database connection setup.

Kept in its own file rather than bolted onto main.py, since every
future step (opportunities, journal) will import `get_db` from here
without needing to know anything about connection details.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set. Set it in Render's Environment tab.")

# Render (and several other hosts) sometimes hand out a connection string
# starting with postgres:// — SQLAlchemy's modern driver requires
# postgresql://. Same value, just a naming mismatch between tools.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a session, always closes it after,
    even if the request raised an error."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
