"""
Database module for ZTForensics API Gateway.
Manages PostgreSQL connections and ORM models.
"""
import logging
import os
from datetime import datetime, timezone
from typing import Generator

from dotenv import load_dotenv
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

load_dotenv()
logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    """Timezone-aware UTC now."""
    return datetime.now(timezone.utc)


DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://ztf:ztfpass@localhost:5432/ztfdb")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
    max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
    pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", "30")),
    pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "1800")),
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class AccessLog(Base):
    __tablename__ = "access_logs"
    __table_args__ = (
        Index("ix_access_logs_timestamp", "timestamp"),
        Index("ix_access_logs_decision_timestamp", "decision", "timestamp"),
    )

    id: int = Column(Integer, primary_key=True, index=True)
    timestamp: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    user_id: str = Column(String, nullable=False, index=True)
    resource: str = Column(String, nullable=False)
    action: str = Column(String, nullable=False)
    decision: str = Column(String, nullable=False)
    risk_score: float = Column(Float, nullable=False, default=0.0)
    ip_address: str = Column(String, nullable=True)
    user_agent: str = Column(String, nullable=True)
    chain_hash: str = Column(String, nullable=True, index=True)


class OTPChallenge(Base):
    __tablename__ = "otp_challenges"
    __table_args__ = (
        Index("ix_otp_user_status", "user_id", "status"),
    )

    id: int = Column(Integer, primary_key=True, index=True)
    user_id: str = Column(String, nullable=False, index=True)
    resource: str = Column(String, nullable=False)
    action: str = Column(String, nullable=False)
    ip_address: str = Column(String, nullable=True)
    otp_code: str = Column(String, nullable=False)  # demo plaintext; hash in production
    status: str = Column(String, nullable=False, default="pending", index=True)  # pending|verified|expired|failed
    attempts: int = Column(Integer, nullable=False, default=0)
    max_attempts: int = Column(Integer, nullable=False, default=5)
    expires_at: datetime = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    verified_at: datetime = Column(DateTime(timezone=True), nullable=True)
    metadata_json: str = Column(Text, nullable=True)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    __table_args__ = (
        Index("ix_security_alerts_status_created", "status", "created_at"),
        Index("ix_security_alerts_severity_created", "severity", "created_at"),
    )

    id: int = Column(Integer, primary_key=True, index=True)
    user_id: str = Column(String, nullable=False, index=True)
    alert_type: str = Column(String, nullable=False, index=True)  # hard_deny|very_suspicious|forbidden_action
    severity: str = Column(String, nullable=False, default="HIGH", index=True)  # LOW|MEDIUM|HIGH|CRITICAL
    decision: str = Column(String, nullable=False, default="deny", index=True)
    reason: str = Column(String, nullable=False)
    resource: str = Column(String, nullable=True)
    action: str = Column(String, nullable=True)
    ip_address: str = Column(String, nullable=True)
    status: str = Column(String, nullable=False, default="open", index=True)  # open|acknowledged|resolved
    details_json: str = Column(Text, nullable=True)
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    acknowledged_at: datetime = Column(DateTime(timezone=True), nullable=True)
    resolved_at: datetime = Column(DateTime(timezone=True), nullable=True)


class AdminUser(Base):
    __tablename__ = "admin_users"
    __table_args__ = (
        UniqueConstraint("username", name="uq_admin_users_username"),
        Index("ix_admin_users_role_active", "role", "is_active"),
    )

    id: int = Column(Integer, primary_key=True, index=True)
    username: str = Column(String, unique=True, nullable=False, index=True)
    email: str = Column(String, nullable=False, index=True)
    role: str = Column(String, nullable=False, default="USER")
    is_active: bool = Column(Boolean, nullable=False, default=True)
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_by: str = Column(String, nullable=True)


class AdminPolicy(Base):
    __tablename__ = "admin_policies"
    __table_args__ = (
        Index("ix_admin_policies_active_threshold", "is_active", "risk_threshold"),
    )

    id: int = Column(Integer, primary_key=True, index=True)
    name: str = Column(String, nullable=False, index=True)
    risk_threshold: int = Column(Integer, nullable=False, default=50)
    action: str = Column(String, nullable=False, default="DENY")
    is_active: bool = Column(Boolean, nullable=False, default=True)
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_by: str = Column(String, nullable=True)


class WhitelistLocation(Base):
    __tablename__ = "whitelist_locations"
    __table_args__ = (
        Index("ix_whitelist_locations_active_expiry", "is_active", "expires_at"),
    )

    id: int = Column(Integer, primary_key=True, index=True)
    name: str = Column(String, nullable=False)
    ip_range: str = Column(String, nullable=False, index=True)
    location: str = Column(String, nullable=False)
    is_active: bool = Column(Boolean, nullable=False, default=True)
    expires_at: datetime = Column(DateTime(timezone=True), nullable=True)
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_by: str = Column(String, nullable=True)


class WhitelistDevice(Base):
    __tablename__ = "whitelist_devices"
    __table_args__ = (
        Index("ix_whitelist_devices_active_expiry", "is_active", "expires_at"),
    )

    id: int = Column(Integer, primary_key=True, index=True)
    user_id: str = Column(String, nullable=False, index=True)
    device_name: str = Column(String, nullable=False)
    fingerprint: str = Column(String, nullable=True, index=True)
    is_active: bool = Column(Boolean, nullable=False, default=True)
    expires_at: datetime = Column(DateTime(timezone=True), nullable=True)
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_by: str = Column(String, nullable=True)


class AdminAuditLog(Base):
    __tablename__ = "admin_audit_logs"
    __table_args__ = (
        Index("ix_admin_audit_actor_created", "actor_user_id", "created_at"),
        Index("ix_admin_audit_action_created", "action", "created_at"),
    )

    id: int = Column(Integer, primary_key=True, index=True)
    actor_user_id: str = Column(String, nullable=False, index=True)
    action: str = Column(String, nullable=False, index=True)
    target_type: str = Column(String, nullable=False, index=True)
    target_id: str = Column(String, nullable=True)
    details_json: str = Column(Text, nullable=True)
    created_at: datetime = Column(DateTime(timezone=True), default=utcnow, nullable=False)


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