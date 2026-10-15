from collections import Counter
from datetime import datetime, timezone
from uuid import uuid4
from forensic.detection_engine import detect_findings
from forensic.hash_utils import sha256_bytes
from forensic.log_parser import parse_log
from models.schemas import Analysis, AnalysisConfig

def analyze_bytes(data: bytes, filename: str, config: AnalysisConfig | None = None) -> Analysis:
    config = config or AnalysisConfig()
    events = parse_log(data, filename)
    findings = detect_findings(events, config)
    parsed = sum(event.parsed for event in events)
    categories = Counter(event.category for event in events)
    severities = Counter(event.severity for event in events)
    high_findings = sum(f.severity in {"critical", "high"} for f in findings)
    return Analysis(analysis_id=str(uuid4()), filename=filename, file_size=len(data), file_type=filename.rsplit(".", 1)[-1].lower() if "." in filename else "unknown",
        analyzed_at=datetime.now(timezone.utc), sha256=sha256_bytes(data), total_events=len(events), parsed_events=parsed,
        unparsed_events=len(events) - parsed, suspicious_findings=len(findings), high_severity_findings=high_findings,
        statistics={"categories": dict(categories), "severity": dict(severities), "failed_logins": sum("failed" in e.message.lower() or e.event_id_code == "4625" for e in events)},
        events=events, findings=findings, config=config,
        limitations=["Syslog years without a year use the current server year.", "Binary EVTX files are not supported; export them to CSV or JSON first."])
