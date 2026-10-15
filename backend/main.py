import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes.analysis import router as analysis_router
from api.routes.health import router as health_router
from services.history_service import store
from config import FRONTEND_ORIGIN

logging.basicConfig(level=logging.INFO)
app = FastAPI(title="LogGuard API", version="1.0.0", description="Local system log forensic analysis API")
app.add_middleware(CORSMiddleware, allow_origins=[FRONTEND_ORIGIN], allow_credentials=False, allow_methods=["GET", "POST", "DELETE"], allow_headers=["*"])
app.include_router(health_router, prefix="/api")
app.include_router(analysis_router, prefix="/api")

@app.get("/api/history")
def history():
    return {"items": [item.model_dump(mode="json", exclude={"events", "findings"}) for item in store.list()]}

@app.delete("/api/history", status_code=204)
def clear_history():
    store.clear()
    return None
