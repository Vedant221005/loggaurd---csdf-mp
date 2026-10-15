from models.schemas import Event

def classify_event(event: Event) -> tuple[str, str]:
    text = event.message.lower()
    if event.category == "authentication":
        if "failed" in text or "failure" in text or event.event_id_code == "4625":
            return "low", "A single authentication failure is a low-severity observation."
        if event.event_id_code == "4672" or "sudo" in text or "privilege" in text:
            return "medium", "Administrative or privileged activity requires review."
        return "informational", "Authentication activity was recorded without a failure indicator."
    if "critical" in text:
        return "high", "The record explicitly reports a critical condition."
    if "failed to start" in text or "service failure" in text:
        return "medium", "A service startup failure may affect system availability."
    if "error" in text:
        return "low", "The record reports an operational error."
    if not event.timestamp:
        return "low", "Missing timestamp reduces the evidentiary timeline quality."
    return "informational", "No suspicious indicator was identified in this individual event."
