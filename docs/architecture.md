# Architecture

```mermaid
flowchart TB
  Browser[Browser] --> Next[Next.js App Router]
  Next --> Axios[Axios REST client]
  Axios --> FastAPI[FastAPI API]
  FastAPI --> Analysis[Analysis service]
  Analysis --> Parser[Log parser]
  Analysis --> Detector[Detection engine]
  Analysis --> Store[Bounded in-memory history]
  Analysis --> Hash[SHA-256]
  FastAPI --> Reports[JSON/TXT report generator]
```

The API is intentionally stateless with respect to permanent storage. The store is protected by a lock and performs TTL and maximum-count cleanup. The frontend receives only normalized JSON and report downloads.
