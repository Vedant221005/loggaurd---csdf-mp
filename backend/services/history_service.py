from datetime import datetime, timezone
from threading import Lock
from models.schemas import Analysis
from config import ANALYSIS_TTL_SECONDS, MAX_ANALYSES

class AnalysisStore:
    def __init__(self) -> None:
        self._items: dict[str, Analysis] = {}
        self._lock = Lock()

    def cleanup(self) -> None:
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            expired = [key for key, value in self._items.items() if now - value.analyzed_at.timestamp() > ANALYSIS_TTL_SECONDS]
            for key in expired:
                del self._items[key]

    def put(self, analysis: Analysis) -> None:
        self.cleanup()
        with self._lock:
            self._items[analysis.analysis_id] = analysis
            while len(self._items) > MAX_ANALYSES:
                oldest = min(self._items, key=lambda key: self._items[key].analyzed_at)
                del self._items[oldest]

    def get(self, analysis_id: str) -> Analysis | None:
        self.cleanup()
        return self._items.get(analysis_id)

    def list(self) -> list[Analysis]:
        self.cleanup()
        return sorted(self._items.values(), key=lambda item: item.analyzed_at, reverse=True)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

store = AnalysisStore()
