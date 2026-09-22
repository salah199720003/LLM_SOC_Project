from __future__ import annotations

from datetime import timezone

from .schemas import EventRecord


def build_timeline(events: list[EventRecord]) -> list[dict]:
    """Return a stable UTC-ordered timeline while preserving provenance."""
    ordered = sorted(events, key=lambda e: (e.timestamp.astimezone(timezone.utc), e.event_id))
    return [
        {
            "event_id": event.event_id,
            "timestamp_utc": event.timestamp.astimezone(timezone.utc).isoformat(),
            "timestamp_source": event.timestamp_source,
            "source_type": event.source_type,
            "source_name": event.source_name,
            "host": event.host,
            "user": event.user,
            "event_code": event.event_code,
            "category": event.category,
            "action": event.action,
            "message": event.message,
            "evidence_refs": [ref.model_dump(mode="json") for ref in event.evidence_refs],
        }
        for event in ordered
    ]
