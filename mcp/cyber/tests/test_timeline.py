from datetime import datetime, timezone

from cybercopilot.schemas import EventRecord
from cybercopilot.timeline import build_timeline


def test_timeline_orders_by_absolute_time():
    later = EventRecord(
        event_id="evt-b",
        case_id="case-1",
        timestamp=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
        timestamp_source="event.system_time",
        source_type="sysmon",
        source_name="fixture",
    )
    earlier = EventRecord(
        event_id="evt-a",
        case_id="case-1",
        timestamp=datetime(2026, 1, 1, 11, 0, tzinfo=timezone.utc),
        timestamp_source="event.system_time",
        source_type="sysmon",
        source_name="fixture",
    )
    timeline = build_timeline([later, earlier])
    assert [x["event_id"] for x in timeline] == ["evt-a", "evt-b"]
