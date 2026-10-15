import csv
import io
import json
import re
import uuid
from datetime import datetime
from typing import Any
from .event_classifier import classify_event
from models.schemas import Event

SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ISO_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")

def _timestamp(value: Any, year: int) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    try:
        return datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

def _event(raw: str, line: int, timestamp: datetime | None, **fields: Any) -> Event:
    message = fields.pop("message", raw).strip()
    event = Event(event_id=str(uuid.uuid4()), timestamp=timestamp, original_timestamp=fields.pop("original_timestamp", None),
                  message=message, raw=raw, line_number=line, **fields)
    severity, reason = classify_event(event)
    event.severity, event.severity_reason = severity, reason
    return event

def _linux_line(raw: str, line: int, year: int) -> Event:
    match = SYSLOG_RE.match(raw)
    if not match:
        iso = ISO_RE.search(raw)
        return _event(raw, line, _timestamp(iso.group(0), year) if iso else None, parsed=bool(iso), category="other",
                      message=raw, original_timestamp=iso.group(0) if iso else None)
    data = match.groupdict()
    msg = data["msg"]
    lower = msg.lower()
    category = "authentication" if any(x in lower for x in ("failed password", "accepted password", "failed publickey", "accepted publickey", "invalid user", "authentication", "session opened", "session closed")) else ("service" if any(x in lower for x in ("service", "systemd", "start")) else "system")
    username_match = re.search(r"(?:for (?:invalid user )?|user[=: ]+)([\w.@-]+)", msg, re.I)
    ip_match = IP_RE.search(msg)
    return _event(raw, line, _timestamp(data["ts"], year), original_timestamp=data["ts"], hostname=data["host"],
                  process=data["proc"], process_id=data["pid"], username=username_match.group(1) if username_match else None,
                  source_ip=ip_match.group(0) if ip_match else None, category=category, message=msg)

def _structured_record(record: dict[str, Any], line: int, year: int) -> Event:
    code = str(record.get("Event ID", record.get("EventId", record.get("event_id", ""))) or "") or None
    timestamp_value = record.get("TimeCreated", record.get("Timestamp", record.get("timestamp", record.get("Date"))))
    message = str(record.get("Message", record.get("message", record.get("Description", ""))) or "")
    provider = record.get("Provider", record.get("ProviderName", record.get("Source")))
    username = record.get("TargetUserName", record.get("Username", record.get("user")))
    hostname = record.get("Computer", record.get("ComputerName", record.get("HostName")))
    ip = record.get("IpAddress", record.get("SourceNetworkAddress", record.get("SourceIP")))
    category = "authentication" if code in {"4624", "4625", "4634", "4672", "4740"} else "other"
    if code == "4625": message = message or "Windows failed logon"
    if code == "4624": message = message or "Windows successful logon"
    event = _event(json.dumps(record, ensure_ascii=False), line, _timestamp(timestamp_value, year),
                   original_timestamp=str(timestamp_value) if timestamp_value else None, hostname=str(hostname) if hostname else None,
                   username=str(username) if username else None, source_ip=str(ip) if ip else None, category=category,
                   event_id_code=code, provider=str(provider) if provider else None, message=message or "Structured event")
    return event

def parse_log(data: bytes, filename: str, year: int | None = None) -> list[Event]:
    year = year or datetime.now().year
    text = data.decode("utf-8-sig", errors="replace")
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    events: list[Event] = []
    if suffix == "json":
        try:
            payload = json.loads(text)
            records = payload if isinstance(payload, list) else payload.get("Records", payload.get("records", [payload]))
            for i, record in enumerate(records, 1):
                events.append(_structured_record(record, i, year) if isinstance(record, dict) else _event(str(record), i, None, parsed=False, message=str(record)))
        except (json.JSONDecodeError, AttributeError):
            return [_event(line, i, None, parsed=False, message=line) for i, line in enumerate(text.splitlines(), 1) if line]
    elif suffix == "csv":
        try:
            for i, record in enumerate(csv.DictReader(io.StringIO(text)), 2):
                events.append(_structured_record(dict(record), i, year))
        except csv.Error:
            return [_event(line, i, None, parsed=False, message=line) for i, line in enumerate(text.splitlines(), 1) if line]
    else:
        events = [_linux_line(line, i, year) for i, line in enumerate(text.splitlines(), 1) if line.strip()]
    return sorted(events, key=lambda event: (event.timestamp is None, event.timestamp or datetime.max))
