from models.schemas import Event

def build_timeline(events: list[Event]) -> list[Event]:
    return sorted(events, key=lambda event: (event.timestamp is None, event.timestamp or 0))
