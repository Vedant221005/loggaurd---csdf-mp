from fastapi import APIRouter
from datetime import datetime, timezone

router = APIRouter()

@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "logguard-api", "timestamp": datetime.now(timezone.utc)}
