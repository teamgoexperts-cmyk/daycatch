"""Database engine + session, shared by the app and the migration script.

Intentionally free of FastAPI / Firebase imports so `migrate.py` can use it
standalone without spinning up the web app.
"""

import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

load_dotenv()

# Railway provides DATABASE_URL (internal, in-cluster) and DATABASE_PUBLIC_URL
# (proxy, reachable from your laptop). Prefer DATABASE_URL, but when it points
# at *.railway.internal and a public URL is available, use the public one.
_raw = os.getenv("DATABASE_URL", "").strip() or os.getenv("DATABASE_PUBLIC_URL", "").strip()
if "railway.internal" in _raw and os.getenv("DATABASE_PUBLIC_URL", "").strip():
    _raw = os.getenv("DATABASE_PUBLIC_URL", "").strip()
DATABASE_URL = _raw or "sqlite:///./daycatch.db"

if not DATABASE_URL.startswith("sqlite") and "sslmode=" not in DATABASE_URL:
    sep = "&" if "?" in DATABASE_URL else "?"
    DATABASE_URL = f"{DATABASE_URL}{sep}sslmode=require"

# Railway/Heroku hand out bare "postgres://" or "postgresql://" URLs. SQLAlchemy
# maps those to the psycopg2 driver, which we don't ship (we use psycopg3). Force
# the psycopg3 dialect so the deployed DATABASE_URL works as-is, no +psycopg
# prefix required in the env var.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgres://"):]
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql://"):]

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
