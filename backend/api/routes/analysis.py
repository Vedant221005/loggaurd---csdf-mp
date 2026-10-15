from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status
from fastapi.responses import Response
from models.schemas import AnalysisConfig, HashVerificationRequest
from services.analysis_service import analyze_bytes
from services.history_service import store
from forensic.report_generator import json_report, txt_report
from forensic.timeline import build_timeline
from config import ALLOWED_EXTENSIONS, MAX_UPLOAD_BYTES

router = APIRouter()

def get_analysis_or_404(analysis_id: str):
    analysis = store.get(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis was not found or has expired.")
    return analysis

@router.post("/analyze", status_code=status.HTTP_201_CREATED)
async def analyze(file: UploadFile = File(...), failed_login_threshold: int = Query(5, ge=2, le=100),
                  window_minutes: int = Query(5, ge=1, le=1440), service_failure_threshold: int = Query(3, ge=2, le=100)):
    filename = file.filename or ""
    suffix = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail="Unsupported file type. Use .log, .txt, .csv, or .json.")
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if not data:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="The uploaded file exceeds the 10 MB limit.")
    analysis = analyze_bytes(data, filename, AnalysisConfig(failed_login_threshold=failed_login_threshold, window_minutes=window_minutes, service_failure_threshold=service_failure_threshold))
    store.put(analysis)
    return analysis.model_dump(exclude={"events", "findings"})

@router.get("/analysis/{analysis_id}")
def get_analysis(analysis_id: str):
    return get_analysis_or_404(analysis_id).model_dump(exclude={"events", "findings"})

@router.get("/analysis/{analysis_id}/events")
def get_events(analysis_id: str, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
               search: str | None = None, severity: str | None = None, category: str | None = None):
    analysis = get_analysis_or_404(analysis_id)
    events = analysis.events
    if search: events = [e for e in events if search.lower() in (e.message + " " + str(e.username) + " " + str(e.source_ip)).lower()]
    if severity: events = [e for e in events if e.severity == severity.lower()]
    if category: events = [e for e in events if e.category == category.lower()]
    start = (page - 1) * page_size
    return {"items": [e.model_dump(mode="json") for e in events[start:start + page_size]], "page": page, "page_size": page_size, "total": len(events)}

@router.get("/analysis/{analysis_id}/timeline")
def get_timeline(analysis_id: str):
    return {"items": [e.model_dump(mode="json") for e in build_timeline(get_analysis_or_404(analysis_id).events)]}

@router.get("/analysis/{analysis_id}/findings")
def get_findings(analysis_id: str):
    return {"items": [f.model_dump(mode="json") for f in get_analysis_or_404(analysis_id).findings]}

@router.get("/analysis/{analysis_id}/report/json")
def download_json(analysis_id: str):
    analysis = get_analysis_or_404(analysis_id)
    return Response(json_report(analysis), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{analysis.filename}.report.json"'})

@router.get("/analysis/{analysis_id}/report/txt")
def download_txt(analysis_id: str):
    analysis = get_analysis_or_404(analysis_id)
    return Response(txt_report(analysis), media_type="text/plain", headers={"Content-Disposition": f'attachment; filename="{analysis.filename}.report.txt"'})

@router.post("/analysis/{analysis_id}/verify-hash")
def verify_hash(analysis_id: str, request: HashVerificationRequest):
    analysis = get_analysis_or_404(analysis_id)
    match = analysis.sha256.lower() == request.reference_sha256.lower()
    return {"status": "Hash Match" if match else "Hash Mismatch", "match": match, "calculated_sha256": analysis.sha256,
            "explanation": "A match demonstrates byte-for-byte equality with the supplied digest, not that the source is inherently trustworthy."}
