from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings

app = FastAPI(
    title="ZTForensics API Gateway",
    version="2.0.0",
    description="Zero Trust API Gateway with forensic evidence chaining.",
)

# Dev-friendly CORS for now; tighten in prod phase
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.app_env == "development" else [],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "api-gateway",
        "env": settings.app_env,
    }


@app.get("/")
def root():
    return {
        "message": "ZTForensics API Gateway running",
        "docs": "/docs",
    }