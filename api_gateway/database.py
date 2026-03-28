"""
Database module for ZTForensics API Gateway.
Manages PostgreSQL connections and the AccessLog ORM model.
"""
import logging
import os
from datetime import datetime
from typing import Generator

from dotenv import load_dotenv
from sqlalchemy import Column, DateTime, Float, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

load_dotenv()

logger = logging.getLogger(__name__)

DATABASE_URL: str = os.getenv(
    "DATABASE_URL", "postgresql://ztf:ztfpass@localhost:5432/ztfdb"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


class AccessLog(Base):
    """ORM model representing a single access log entry."""

    __tablename__ = "access_logs"

    id: int = Column(Integer, primary_key=True, index=True)
    timestamp: datetime = Column(DateTime, default=datetime.utcnow, nullable=False)
    user_id: str = Column(String, nullable=False, index=True)
    resource: str = Column(String, nullable=False)
    action: str = Column(String, nullable=False)
    decision: str = Column(String, nullable=False)
    risk_score: float = Column(Float, nullable=False, default=0.0)
    ip_address: str = Column(String, nullable=True)
    user_agent: str = Column(String, nullable=True)
    chain_hash: str = Column(String, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<AccessLog(id={self.id}, user_id={self.user_id!r}, "
            f"resource={self.resource!r}, decision={self.decision!r})>"
        )


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a SQLAlchemy session and ensures cleanup."""
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all database tables if they do not already exist."""
    logger.info("Initialising database tables…")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables ready.")
