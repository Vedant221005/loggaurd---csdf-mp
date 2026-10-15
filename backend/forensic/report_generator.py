import html
import json
from models.schemas import Analysis

def report_payload(analysis: Analysis) -> dict:
    categories: dict[str, int] = {}
    severities: dict[str, int] = {}
    for event in analysis.events:
        categories[event.category] = categories.get(event.category, 0) + 1
        severities[event.severity] = severities.get(event.severity, 0) + 1
    return {
        "project": "LogGuard — System Log Forensic Analyzer", "analysis_id": analysis.analysis_id,
        "analysis_timestamp": analysis.analyzed_at.isoformat(), "original_filename": analysis.filename,
        "file_size": analysis.file_size, "file_format": analysis.file_type, "sha256": analysis.sha256,
        "statistics": {"total_events": analysis.total_events, "parsed_events": analysis.parsed_events,
                       "unparsed_events": analysis.unparsed_events, "categories": categories, "severity": severities},
        "detection_configuration": analysis.config.model_dump(), "suspicious_findings": [f.model_dump(mode="json") for f in analysis.findings],
        "timeline": [e.model_dump(mode="json") for e in analysis.events],
        "limitations": analysis.limitations,
        "disclaimer": "This educational tool supports triage and does not establish attribution, intent, or legal conclusions.",
    }

def json_report(analysis: Analysis) -> bytes:
    return json.dumps(report_payload(analysis), indent=2, ensure_ascii=False).encode("utf-8")

def txt_report(analysis: Analysis) -> bytes:
    payload = report_payload(analysis)
    lines = [payload["project"], "=" * 60]
    for key in ("analysis_id", "analysis_timestamp", "original_filename", "file_size", "file_format", "sha256"):
        lines.append(f"{key.replace('_', ' ').title()}: {payload[key]}")
    lines += ["", "Statistics", "----------", json.dumps(payload["statistics"], indent=2),
              "", "Findings", "--------"]
    for finding in analysis.findings:
        lines.append(f"[{finding.severity.upper()}] {finding.rule_name}: {finding.description}")
        lines.append(f"  {finding.explanation}")
        lines.append(f"  Evidence events: {', '.join(finding.related_event_ids)}")
    lines += ["", "Forensic disclaimer: " + payload["disclaimer"]]
    return "\n".join(lines).encode("utf-8")

def html_report(analysis: Analysis) -> bytes:
    payload = report_payload(analysis)
    findings = "".join(f"<li><strong>{html.escape(f.severity.upper())}</strong> {html.escape(f.rule_name)} — {html.escape(f.description)}</li>" for f in analysis.findings)
    return f"<html><head><title>LogGuard Report</title></head><body><h1>{html.escape(payload['project'])}</h1><p>Analysis ID: {html.escape(analysis.analysis_id)}</p><p>SHA-256: {html.escape(analysis.sha256)}</p><h2>Findings</h2><ul>{findings}</ul></body></html>".encode("utf-8")
