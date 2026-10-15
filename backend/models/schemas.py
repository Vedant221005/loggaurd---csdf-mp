from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "informational"]

class Event(BaseModel):
    event_id: str
    timestamp: datetime | None = None
    original_timestamp: str | None = None
    hostname: str | None = None
    process: str | None = None
    process_id: str | None = None
    username: str | None = None
    source_ip: str | None = None
    category: str = "other"
    severity: Severity = "informational"
    severity_reason: str = ""
    message: str
    line_number: int
    parsed: bool = True
    event_id_code: str | None = None
    provider: str | None = None
    raw: str

class Finding(BaseModel):
    finding_id: str
    rule_name: str
    severity: Severity
    description: str
    explanation: str
    source_ip: str | None = None
    username: str | None = None
    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None
    related_event_ids: list[str] = Field(default_factory=list)

class AnalysisConfig(BaseModel):
    failed_login_threshold: int = Field(default=5, ge=2, le=100)
    window_minutes: int = Field(default=5, ge=1, le=1440)
    service_failure_threshold: int = Field(default=3, ge=2, le=100)
    operating_start_hour: int = Field(default=7, ge=0, le=23)
    operating_end_hour: int = Field(default=19, ge=0, le=23)

class AnalysisSummary(BaseModel):
    analysis_id: str
    filename: str
    file_size: int
    file_type: str
    analyzed_at: datetime
    sha256: str
    total_events: int
    parsed_events: int
    unparsed_events: int
    unsupported_records: int = 0
    suspicious_findings: int
    high_severity_findings: int
    statistics: dict[str, Any] = Field(default_factory=dict)

class Analysis(AnalysisSummary):
    events: list[Event] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    config: AnalysisConfig = Field(default_factory=AnalysisConfig)
    limitations: list[str] = Field(default_factory=list)

class HistoryItem(AnalysisSummary):
    pass

class HashVerificationRequest(BaseModel):
    reference_sha256: str = Field(min_length=64, max_length=64, pattern=r"^[a-fA-F0-9]{64}$")
