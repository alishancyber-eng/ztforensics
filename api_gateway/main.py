from datetime import datetime, timezone
from uuid import uuid4

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from auth import get_current_subject
from config import settings
from opa_client import evaluate_policy
from risk_scorer import calculate_risk


class AccessRequest(BaseModel):
    resource: str = Field(..., examples=["/api/documents"])
    action: str = Field(..., examples=["read"])
    ip_address: str = Field(..., examples=["192.168.1.100"])
    user_agent: str = Field(..., examples=["Mozilla/5.0"])


app = FastAPI(
    title="ZTForensics API Gateway",
    version="2.1.0",
    description="Zero Trust API Gateway with forensic evidence chaining.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.app_env == "development" else [],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "api-gateway", "env": settings.app_env}


@app.get("/")
def root():
    return {"message": "ZTForensics API Gateway running", "docs": "/docs"}


@app.post("/access")
def access_decision(
    req: AccessRequest,
    subject: dict = Depends(get_current_subject)
):
    now = datetime.now(timezone.utc)
    risk = calculate_risk(req.model_dump())

    opa_input = {
        "user": subject["sub"],
        "role": subject["role"],
        "resource": req.resource,
        "action": req.action,
        "ip_address": req.ip_address,
        "risk_score": risk["risk_score"],
        "hour": now.hour
    }
    decision = evaluate_policy(opa_input)

    return {
        "trace_id": str(uuid4()),
        "timestamp": now.isoformat(),
        "user": subject["sub"],
        "role": subject["role"],
        "resource": req.resource,
        "action": req.action,
        "ip_address": req.ip_address,
        "risk_score": risk["risk_score"],
        "risk_factors": risk["risk_factors"],
        "decision": "ALLOW" if decision["allow"] else "DENY",
        "reason": decision["reason"],
        "record_hash": None
    }