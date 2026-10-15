import hashlib
from pathlib import Path
from fastapi.testclient import TestClient
from main import app
from forensic.log_parser import parse_log
from forensic.detection_engine import detect_findings
from models.schemas import AnalysisConfig

client = TestClient(app)
SAMPLES = Path(__file__).parents[1] / "sample_logs"

def test_linux_parser_and_detection():
    data = (SAMPLES / "sample_auth.log").read_bytes()
    events = parse_log(data, "sample_auth.log", 2026)
    assert len(events) == 9
    assert sum(e.category == "authentication" for e in events) >= 8
    findings = detect_findings(events, AnalysisConfig())
    assert any(f.rule_name == "Repeated failed login attempts" for f in findings)

def test_upload_and_reports():
    response = client.post("/api/analyze", files={"file": ("sample_auth.log", (SAMPLES / "sample_auth.log").read_bytes(), "text/plain")})
    assert response.status_code == 201
    analysis_id = response.json()["analysis_id"]
    summary = client.get(f"/api/analysis/{analysis_id}")
    assert summary.status_code == 200
    assert summary.json()["sha256"] == hashlib.sha256((SAMPLES / "sample_auth.log").read_bytes()).hexdigest()
    assert client.get(f"/api/analysis/{analysis_id}/report/json").status_code == 200
    assert client.get(f"/api/analysis/{analysis_id}/report/txt").status_code == 200

def test_rejects_invalid_and_empty_uploads():
    assert client.post("/api/analyze", files={"file": ("bad.exe", b"no", "application/octet-stream")}).status_code == 415
    assert client.post("/api/analyze", files={"file": ("empty.log", b"", "text/plain")}).status_code == 400

def test_windows_csv_parser():
    events = parse_log((SAMPLES / "sample_windows.csv").read_bytes(), "sample_windows.csv", 2026)
    assert len(events) == 6
    assert any(e.event_id_code == "4672" and e.category == "authentication" for e in events)
