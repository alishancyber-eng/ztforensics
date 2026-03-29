"""
ZTForensics API Gateway – main FastAPI application.
"""
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Optional

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth_middleware import get_current_user
from auth_routes import router as auth_router
from blockchain import BlockchainManager
from database import AccessLog, get_db, init_db
from risk_scoring import RiskScorer
from schemas import UserContext
from storage import StorageManager
from config_manager import config_manager

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

OPA_URL: str = os.getenv("OPA_URL", "http://localhost:8181")

# Module-level singletons
blockchain_manager = BlockchainManager()
risk_scorer = RiskScorer()

try:
    storage_manager: Optional[StorageManager] = StorageManager()
except Exception:
    storage_manager = None
    logger.warning("StorageManager unavailable – storage features disabled.")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup / shutdown lifecycle handler."""
    logger.info("Starting ZTForensics API Gateway…")
    init_db()
    yield
    logger.info("ZTForensics API Gateway shutting down.")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="ZTForensics API Gateway",
    version="1.0.0",
    description="Zero Trust Forensic Gateway",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class AccessRequest(BaseModel):
    """Incoming access-control request payload."""

    user_id: str = Field(..., min_length=1)
    resource: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    ip_address: str = Field(default="")
    user_agent: str = Field(default="")
    metadata: Optional[dict[str, Any]] = Field(default=None)


class AccessResponse(BaseModel):
    """Response returned after an access-control decision."""

    decision: str
    risk_score: float
    reason: str
    chain_hash: str


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

async def _query_opa(request: AccessRequest) -> dict[str, Any]:
    """Send the request to OPA and return the parsed decision.

    Falls back to *allow* when OPA is unreachable.
    """
    payload = {
        "input": {
            "user_id": request.user_id,
            "resource": request.resource,
            "action": request.action,
            "ip_address": request.ip_address,
            "user_agent": request.user_agent,
            "metadata": request.metadata or {},
        }
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{OPA_URL}/v1/data/ztf/authz",
                json=payload,
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
            return result
    except Exception as exc:
        logger.warning("OPA unreachable (%s); defaulting to allow.", exc)
        return {"allow": True}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint – service identification."""
    return {"message": "ZTForensics API Gateway", "version": "1.0.0"}


@app.get("/health")
async def health(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Health-check endpoint."""
    db_status = "up"
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
    except Exception:
        db_status = "down"

    storage_status = "up" if storage_manager is not None else "down"

    return {
        "status": "healthy",
        "services": {
            "database": db_status,
            "blockchain": "up",
            "storage": storage_status,
        },
    }


@app.post("/access", response_model=AccessResponse)
async def access(request: AccessRequest, db: Session = Depends(get_db)) -> AccessResponse:
    """Evaluate an access request through OPA and log the decision."""
    # 1. Calculate risk score
    risk_score = risk_scorer.calculate_risk(
        {
            "ip_address": request.ip_address,
            "user_agent": request.user_agent,
            "resource": request.resource,
            "action": request.action,
            "user_id": request.user_id,
        }
    )

    # 2. Query OPA
    opa_result = await _query_opa(request)
    allowed: bool = bool(opa_result.get("allow", True))

    if not allowed:
        risk_scorer.record_failure(request.user_id)

    decision = "allow" if allowed else "deny"
    reason = opa_result.get("deny_reason", "Policy decision") if not allowed else "Access granted"

    # 3. Build chain entry
    log_entry = {
        "user_id": request.user_id,
        "resource": request.resource,
        "action": request.action,
        "decision": decision,
        "risk_score": risk_score,
        "ip_address": request.ip_address,
        "user_agent": request.user_agent,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    chain_hash = blockchain_manager.add_block(log_entry)

    # 4. Persist to database
    access_log = AccessLog(
        user_id=request.user_id,
        resource=request.resource,
        action=request.action,
        decision=decision,
        risk_score=risk_score,
        ip_address=request.ip_address,
        user_agent=request.user_agent,
        chain_hash=chain_hash,
    )
    db.add(access_log)
    db.commit()

    logger.info(
        "Access %s: user=%s resource=%s action=%s risk=%.2f",
        decision,
        request.user_id,
        request.resource,
        request.action,
        risk_score,
    )

    return AccessResponse(
        decision=decision,
        risk_score=risk_score,
        reason=reason,
        chain_hash=chain_hash,
    )


@app.get("/forensics/verify-chain")
async def verify_chain(
    _user: UserContext = Depends(get_current_user),
) -> dict[str, Any]:
    """Verify the integrity of the forensic blockchain."""
    result = blockchain_manager.verify_chain()
    stats = blockchain_manager.get_chain_stats()
    return {**result, **stats}


@app.get("/forensics/summary")
async def forensics_summary(
    db: Session = Depends(get_db),
    _user: UserContext = Depends(get_current_user),
) -> dict[str, Any]:
    """Return aggregate statistics from the access log database."""
    from sqlalchemy import func

    total = db.query(func.count(AccessLog.id)).scalar() or 0
    allowed = db.query(func.count(AccessLog.id)).filter(AccessLog.decision == "allow").scalar() or 0
    denied = db.query(func.count(AccessLog.id)).filter(AccessLog.decision == "deny").scalar() or 0
    high_risk = (
        db.query(func.count(AccessLog.id)).filter(AccessLog.risk_score >= 0.75).scalar() or 0
    )

    recent_logs = (
        db.query(AccessLog).order_by(AccessLog.timestamp.desc()).limit(10).all()
    )

    recent = [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "user_id": log.user_id,
            "resource": log.resource,
            "action": log.action,
            "decision": log.decision,
            "risk_score": log.risk_score,
        }
        for log in recent_logs
    ]

    return {
        "total_requests": total,
        "allowed": allowed,
        "denied": denied,
        "high_risk_events": high_risk,
        "recent_logs": recent,
    }


@app.get("/forensics/export")
async def forensics_export(
    db: Session = Depends(get_db),
    _user: UserContext = Depends(get_current_user),
) -> dict[str, Any]:
    """Export all forensic evidence as a JSON structure."""
    logs = db.query(AccessLog).order_by(AccessLog.timestamp.asc()).all()
    chain_stats = blockchain_manager.get_chain_stats()

    evidence = [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            "user_id": log.user_id,
            "resource": log.resource,
            "action": log.action,
            "decision": log.decision,
            "risk_score": log.risk_score,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "chain_hash": log.chain_hash,
        }
        for log in logs
    ]

    return {
        "export_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_records": len(evidence),
        "chain_stats": chain_stats,
        "evidence": evidence,
    }



@app.get("/config/current")
async def get_current_config(
    _user: UserContext = Depends(get_current_user),
) -> dict[str, Any]:
    """Get current environment configuration"""
    return {
        "environment": config_manager.current_env,
        "organization": config_manager.get_organization_name(),
        "sector": config_manager.get_sector(),
        "risk_factors": config_manager.get_risk_factors(),
        "thresholds": {
            "low": config_manager.get_risk_threshold('low'),
            "medium": config_manager.get_risk_threshold('medium'),
            "high": config_manager.get_risk_threshold('high'),
            "critical": config_manager.get_risk_threshold('critical')
        },
        "audit_retention_days": config_manager.get_audit_retention_days(),
        "hipaa_compliant": config_manager.is_hipaa_compliant(),
        "pci_compliant": config_manager.is_pci_compliant()
    }