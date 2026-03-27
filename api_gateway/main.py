from datetime import datetime, timezone
from uuid import uuid4
import json

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text

from auth import get_current_subject
from config import settings
from opa_client import evaluate_policy
from risk_scorer import calculate_risk
from forensic_engine import build_evidence_payload, make_record_hash, verify_chain

app = FastAPI(
    title="ZTForensics API Gateway",
    version="2.3.0",
    description="Zero Trust API Gateway with forensic evidence chaining.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.app_env == "development" else [],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = None
DB_READY = False


class AccessRequest(BaseModel):
    resource: str = Field(..., examples=["/api/documents"])
    action: str = Field(..., examples=["read"])
    ip_address: str = Field(..., examples=["192.168.1.100"])
    user_agent: str = Field(..., examples=["Mozilla/5.0"])


def init_db() -> bool:
    global engine
    try:
        engine = create_engine(settings.database_url, future=True, pool_pre_ping=True)
        ddl = """
        CREATE TABLE IF NOT EXISTS evidence_records (
            id BIGSERIAL PRIMARY KEY,
            timestamp TEXT NOT NULL,
            trace_id TEXT NOT NULL,
            user_name TEXT NOT NULL,
            role TEXT NOT NULL,
            resource TEXT NOT NULL,
            action TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            risk_score INT NOT NULL,
            risk_factors TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            record_hash TEXT NOT NULL
        );
        """
        with engine.begin() as conn:
            conn.execute(text(ddl))
        print("[DB] initialized successfully")
        return True
    except Exception as e:
        print(f"[DB] init failed: {e}")
        return False


@app.on_event("startup")
def on_startup():
    global DB_READY
    DB_READY = init_db()
    print(f"[DB] ready={DB_READY}")


@app.get("/health")
def health():
    return {"status": "ok", "service": "api-gateway", "env": settings.app_env, "db_ready": DB_READY}


@app.get("/")
def root():
    return {"message": "ZTForensics API Gateway running", "docs": "/docs"}


@app.post("/access")
def access_decision(req: AccessRequest, subject: dict = Depends(get_current_subject)):
    now = datetime.now(timezone.utc)
    trace_id = str(uuid4())
    risk = calculate_risk(req.model_dump())

    opa_input = {
        "user": subject["sub"],
        "role": subject["role"],
        "resource": req.resource,
        "action": req.action,
        "ip_address": req.ip_address,
        "user_agent": req.user_agent,
        "risk_score": risk["risk_score"],
        "risk_factors": risk["risk_factors"],
        "hour": now.hour,
    }

    decision_obj = evaluate_policy(opa_input)
    allow = bool(decision_obj.get("allow", False))
    reason = decision_obj.get("reason", "DENY_BY_DEFAULT")
    decision = "ALLOW" if allow else "DENY"

    previous_hash = "0"
    record_hash = None

    if DB_READY and engine is not None:
        try:
            with engine.begin() as conn:
                prev = conn.execute(text("SELECT record_hash FROM evidence_records ORDER BY id DESC LIMIT 1")).fetchone()
                previous_hash = prev[0] if prev else "0"

                payload = build_evidence_payload(
                    user=subject["sub"],
                    role=subject["role"],
                    resource=req.resource,
                    action=req.action,
                    ip_address=req.ip_address,
                    user_agent=req.user_agent,
                    risk_score=risk["risk_score"],
                    risk_factors=risk["risk_factors"],
                    decision=decision,
                    reason=reason,
                    previous_hash=previous_hash,
                    trace_id=trace_id,
                )
                record_hash = make_record_hash(payload)

                conn.execute(
                    text(
                        """
                        INSERT INTO evidence_records (
                            timestamp, trace_id, user_name, role, resource, action,
                            ip_address, user_agent, risk_score, risk_factors,
                            decision, reason, previous_hash, record_hash
                        ) VALUES (
                            :timestamp, :trace_id, :user_name, :role, :resource, :action,
                            :ip_address, :user_agent, :risk_score, :risk_factors,
                            :decision, :reason, :previous_hash, :record_hash
                        )
                        """
                    ),
                    {
                        "timestamp": payload["timestamp"],
                        "trace_id": payload["trace_id"],
                        "user_name": payload["user"],
                        "role": payload["role"],
                        "resource": payload["resource"],
                        "action": payload["action"],
                        "ip_address": payload["ip_address"],
                        "user_agent": payload["user_agent"],
                        "risk_score": payload["risk_score"],
                        "risk_factors": json.dumps(payload["risk_factors"]),
                        "decision": payload["decision"],
                        "reason": payload["reason"],
                        "previous_hash": payload["previous_hash"],
                        "record_hash": record_hash,
                    },
                )
        except Exception as e:
            print(f"[DB] write failed: {e}")

    return {
        "trace_id": trace_id,
        "timestamp": now.isoformat(),
        "user": subject["sub"],
        "role": subject["role"],
        "resource": req.resource,
        "action": req.action,
        "ip_address": req.ip_address,
        "risk_score": risk["risk_score"],
        "risk_factors": risk["risk_factors"],
        "decision": decision,
        "reason": reason,
        "previous_hash": previous_hash,
        "record_hash": record_hash,
    }


@app.get("/forensics/verify-chain")
def verify_forensic_chain():
    if not DB_READY or engine is None:
        return {"ok": False, "error": "DB_NOT_READY", "total_records": 0}

    try:
        with engine.begin() as conn:
            rows = conn.execute(
                text(
                    """
                    SELECT id, timestamp, trace_id, user_name, role, resource, action,
                           ip_address, user_agent, risk_score, risk_factors,
                           decision, reason, previous_hash, record_hash
                    FROM evidence_records
                    ORDER BY id ASC
                    """
                )
            ).mappings().all()

        records = []
        for r in rows:
            d = dict(r)
            try:
                d["risk_factors"] = json.loads(d["risk_factors"]) if isinstance(d["risk_factors"], str) else d["risk_factors"]
            except Exception:
                d["risk_factors"] = []
            records.append(d)

        result = verify_chain(records)
        result["total_records"] = len(records)
        return result
    except Exception as e:
        return {"ok": False, "error": f"VERIFY_FAILED: {e}", "total_records": 0}