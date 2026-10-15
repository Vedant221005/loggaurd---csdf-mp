from collections import defaultdict
from datetime import timedelta
import uuid
from models.schemas import AnalysisConfig, Event, Finding

def _finding(rule: str, severity: str, description: str, explanation: str, events: list[Event], source_ip=None, username=None) -> Finding:
    ordered = sorted((e for e in events if e.timestamp), key=lambda e: e.timestamp)
    return Finding(finding_id=str(uuid.uuid4()), rule_name=rule, severity=severity, description=description,
                   explanation=explanation, source_ip=source_ip, username=username,
                   first_timestamp=ordered[0].timestamp if ordered else None, last_timestamp=ordered[-1].timestamp if ordered else None,
                   related_event_ids=[e.event_id for e in events])

def detect_findings(events: list[Event], config: AnalysisConfig) -> list[Finding]:
    findings: list[Finding] = []
    failed = [e for e in events if e.category == "authentication" and ("failed" in e.message.lower() or e.event_id_code == "4625")]
    grouped_ip: dict[str, list[Event]] = defaultdict(list)
    grouped_user: dict[str, list[Event]] = defaultdict(list)
    for event in failed:
        if event.source_ip: grouped_ip[event.source_ip].append(event)
        if event.username: grouped_user[event.username].append(event)
    for ip, group in grouped_ip.items():
        ordered = sorted((e for e in group if e.timestamp), key=lambda e: e.timestamp)
        for start in range(0, len(ordered)):
            window = [e for e in ordered[start:] if e.timestamp <= ordered[start].timestamp + timedelta(minutes=config.window_minutes)]
            if len(window) >= config.failed_login_threshold:
                findings.append(_finding("Repeated failed login attempts", "high", f"{len(window)} failed logins from {ip}.",
                    f"At least {config.failed_login_threshold} failed authentication attempts occurred within {config.window_minutes} minutes.",
                    window, source_ip=ip)); break
    for user, group in grouped_user.items():
        if len(group) >= config.failed_login_threshold:
            findings.append(_finding("Multiple failures against one account", "high", f"Repeated authentication failures targeted {user}.",
                "The same account identifier appears in repeated failed authentication records.", group, username=user))
    for event in events:
        if event.category == "authentication" and ("accepted" in event.message.lower() or event.event_id_code == "4624"):
            related = [e for e in failed if (event.username and e.username == event.username) or (event.source_ip and e.source_ip == event.source_ip)]
            if len(related) >= config.failed_login_threshold:
                findings.append(_finding("Successful login after repeated failures", "high", "A successful login followed repeated failures.",
                    "A success was correlated with a source or account that had repeated failures.", related + [event], event.source_ip, event.username))
    privileged = [e for e in events if e.event_id_code == "4672" or "sudo" in e.message.lower() or "privilege" in e.message.lower()]
    if privileged:
        findings.append(_finding("Privileged account activity", "medium", "Administrative activity was recorded.",
            "This is an auditable administrative observation, not proof of malicious behavior.", privileged,
            privileged[0].source_ip, privileged[0].username))
    service = [e for e in events if e.category == "service" and any(x in e.message.lower() for x in ("failed", "error", "failure"))]
    if len(service) >= config.service_failure_threshold:
        findings.append(_finding("Repeated service failures", "medium", f"{len(service)} service failures were recorded.",
            f"At least {config.service_failure_threshold} service failure records were present.", service))
    outside = [e for e in events if e.timestamp and e.category == "authentication" and not config.operating_start_hour <= e.timestamp.hour < config.operating_end_hour]
    if outside:
        findings.append(_finding("Unusual activity hours", "medium", "Authentication activity occurred outside expected hours.",
            f"Expected activity window is {config.operating_start_hour:02d}:00 to {config.operating_end_hour:02d}:00.", outside))
    malformed = [e for e in events if not e.parsed or not e.timestamp]
    if malformed:
        findings.append(_finding("Malformed log records", "low", f"{len(malformed)} records need data-quality review.",
            "Missing timestamps or unsupported record structure limits chronological analysis.", malformed))
    return findings
