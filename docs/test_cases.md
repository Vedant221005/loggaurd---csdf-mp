# Test cases

| ID | Scenario | Expected result |
|---|---|---|
| LG-01 | Linux auth sample | Normalized authentication events and repeated-failure finding |
| LG-02 | Windows CSV sample | Event IDs and user/IP fields are extracted |
| LG-03 | Empty upload | HTTP 400 with a safe validation message |
| LG-04 | Unsupported extension | HTTP 415 |
| LG-05 | Repeated service failures | Medium service finding |
| LG-06 | Missing timestamp | Record retained, data-quality finding, timeline tail |
| LG-07 | SHA-256 reference | Match or mismatch response without revealing internals |
| LG-08 | Expired/unknown UUID | HTTP 404 |
| LG-09 | JSON report | Contains hash, statistics, configuration, findings, and timeline |
| LG-10 | Clear history | Temporary records are removed |

Run backend tests with `cd backend; pytest tests -q`, then build the frontend with `cd frontend; npm run build`.
