"""
Database module for ZTForensics API Gateway.
Manages PostgreSQL connections and ORM models.
"""
import logging
import os
from datetime import datetime
from typing import Generator

from dotenv import load_dotenv
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

load_dotenv()
logger = logging.getLogger(__name__)

DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://ztf:ztfpass@localhost:5432/ztfdb")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class AccessLog(Base):
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


class AdminUser(Base):
    __tablename__ = "admin_users"

    id: int = Column(Integer, primary_key=True, index=True)
    username: str = Column(String, unique=True, nullable=False, index=True)
    email: str = Column(String, nullable=False, index=True)
    role: str = Column(String, nullable=False, default="USER")
    is_active: bool = Column(Boolean, nullable=False, default=True)
    created_at: datetime = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by: str = Column(String, nullable=True)


class AdminPolicy(Base):
    __tablename__ = "admin_policies"

    id: int = Column(Integer, primary_key=True, index=True)
    name: str = Column(String, nullable=False, index=True)
    risk_threshold: int = Column(Integer, nullable=False, default=50)
    action: str = Column(String, nullable=False, default="DENY")
    is_active: bool = Column(Boolean, nullable=False, default=True)
    created_at: datetime = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by: str = Column(String, nullable=True)


class WhitelistLocation(Base):
    __tablename__ = "whitelist_locations"

    id: int = Column(Integer, primary_key=True, index=True)
    name: str = Column(String, nullable=False)
    ip_range: str = Column(String, nullable=False, index=True)
    location: str = Column(String, nullable=False)
    is_active: bool = Column(Boolean, nullable=False, default=True)
    expires_at: datetime = Column(DateTime, nullable=True)
    created_at: datetime = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by: str = Column(String, nullable=True)


class WhitelistDevice(Base):
    __tablename__ = "whitelist_devices"

    id: int = Column(Integer, primary_key=True, index=True)
    user_id: str = Column(String, nullable=False, index=True)
    device_name: str = Column(String, nullable=False)
    fingerprint: str = Column(String, nullable=True, index=True)
    is_active: bool = Column(Boolean, nullable=False, default=True)
    expires_at: datetime = Column(DateTime, nullable=True)
    created_at: datetime = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by: str = Column(String, nullable=True)


class AdminAuditLog(Base):
    __tablename__ = "admin_audit_logs"

    id: int = Column(Integer, primary_key=True, index=True)
    actor_user_id: str = Column(String, nullable=False, index=True)
    action: str = Column(String, nullable=False, index=True)
    target_type: str = Column(String, nullable=False, index=True)
    target_id: str = Column(String, nullable=True)
    details_json: str = Column(Text, nullable=True)
    created_at: datetime = Column(DateTime, default=datetime.utcnow, nullable=False)


def get_db() -> Generator[Session, None, None]:
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    logger.info("Initialising database tables…")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables ready.")