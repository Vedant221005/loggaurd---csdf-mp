# LogGuard — System Log Forensic Analyzer

LogGuard is a local-first Cyber Security and Digital Forensics mini-project for turning system logs into reviewable evidence. It parses Linux syslog/authentication text and Windows Event Viewer CSV/JSON exports, normalizes records, applies explainable detection rules, reconstructs a timeline, calculates SHA-256, and creates JSON/TXT forensic reports.

## Problem and objectives

Manual review of authentication and service logs is slow and makes repeated attack indicators easy to miss. LogGuard supports evidence intake, normalized event extraction, suspicious-activity triage, searchable event review, integrity verification, and reproducible reporting without a database, cloud API, or machine learning.

## Architecture

```mermaid
flowchart LR
  UI[Next.js + TypeScript] -->|REST / JSON| API[FastAPI]
  API --> Parser[Parser + normalizer]
  Parser --> Rules[Rule detection + classifier]
  Rules --> Store[Bounded in-memory store]
  Store --> Reports[JSON/TXT reports]
```

The browser stores no log content. Analysis history is temporary, bounded, and lost when the backend restarts or records expire.

## Setup on Windows

### Backend

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

If PowerShell activation is blocked, run `.\venv\Scripts\python.exe -m pip install -r requirements.txt` and `.\venv\Scripts\python.exe -m uvicorn main:app --reload --port 8000`.

Backend: http://127.0.0.1:8000 · OpenAPI: http://127.0.0.1:8000/docs

### Frontend

```powershell
cd frontend
copy .env.example .env.local
npm install
npm run dev
```

Frontend: http://localhost:3000. The default `NEXT_PUBLIC_API_URL` points to `http://127.0.0.1:8000`; Axios adds the `/api` prefix.

## Modules

- `backend/forensic/log_parser.py`: Linux syslog, generic text, Windows CSV/JSON normalization.
- `backend/forensic/detection_engine.py`: repeated failures, account targeting, success-after-failure, privilege, service, unusual-hours, and malformed-record rules.
- `backend/services/history_service.py`: UUID analysis store, TTL cleanup, and maximum record bound.
- `backend/forensic/report_generator.py`: evidence-backed JSON, TXT, and safe HTML helpers.
- `frontend/app/analysis/[id]`: summary, event search, findings, downloads, hash verification, and timeline link.

## Detection rules

Defaults are five failed logins from one source within five minutes, three service failures, and expected hours 07:00–19:00. Every finding includes a reason and related event IDs. Administrative activity is treated as auditable activity, not automatically malicious.

## Supported formats and limitations

Supported uploads are `.log`, `.txt`, `.csv`, and `.json`, up to 10 MB. Syslog records without a year use the backend server year. Binary `.evtx` files are not parsed; export them to CSV or JSON. This is a triage and educational tool, not a replacement for validated forensic tooling, chain-of-custody procedures, or legal review.

## Testing

```powershell
cd backend
pytest tests -q
cd ..\frontend
npm test
npm run build
```

The backend tests cover parsing, detection, upload validation, hashing, reports, and Windows CSV handling. Use `backend/sample_logs` for a faculty demonstration.

## Expected demonstration

`sample_auth.log` produces repeated-failure, success-after-failure, privileged-activity, and unusual-hours-capable evidence depending on the configured server time. `sample_system.log` produces repeated service failures and a malformed/data-quality finding. `sample_windows.csv` demonstrates event IDs 4624, 4625, 4634, 4672, and 4740.

## Future enhancements

Authenticated multi-user deployments, immutable evidence storage, timezone metadata, EVTX parsing through a vetted offline library, richer exported HTML, role-based access, and SIEM integration can be added without changing the normalized event contract.

## Viva questions

1. **Why hash before parsing?** To identify the exact uploaded byte stream independently of normalization.
2. **Why use rules instead of ML?** Rules are explainable and appropriate for a small, deterministic educational analyzer.
3. **What does a hash match prove?** Equality with the supplied digest, not source authenticity.
4. **How are missing timestamps handled?** The record is retained and placed after timestamped records.
5. **Why no binary EVTX claim?** Parsing is limited to implemented CSV/JSON exports.
6. **How is brute force detected?** A configurable threshold within a configurable time window, grouped by source IP.
7. **Why distinguish event severity and finding severity?** One event can be low-risk while an aggregate pattern is high-risk.
8. **How is privacy addressed?** Processing is local and logs are not sent to third-party APIs.
9. **What happens after restart?** In-memory history disappears by design.
10. **What is the main forensic limitation?** LogGuard supports triage and evidence references, not attribution or legal conclusions.
