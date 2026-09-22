from datetime import datetime, timezone

import pytest

from cybercopilot.schemas import EventRecord
from cybercopilot.tool_service import (
    CyberToolInputError,
    CyberToolService,
)


def make_event(event_id: str, case_id: str, event_code: str, **event_data):
    return EventRecord(
        event_id=event_id,
        case_id=case_id,
        timestamp=datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc),
        timestamp_source="fixture",
        source_type="sysmon",
        source_name="fixture.xml",
        host="LAB-WS01",
        event_code=event_code,
        category="fixture",
        action="fixture",
        fields={"event_data": event_data},
    )


class FakeStore:
    def __init__(self, events):
        self.events = {event.event_id: event for event in events}

    def get_event(self, event_id):
        return self.events.get(event_id)


def make_service(events):
    service = object.__new__(CyberToolService)
    service.store = FakeStore(events)
    return service


def test_correlate_activity_uses_only_requested_case_events():
    events = [
        make_event(
            "evt-parent",
            "case-1",
            "1",
            ProcessId="7000",
            Image="WINWORD.EXE",
        ),
        make_event(
            "evt-child",
            "case-1",
            "1",
            ProcessId="7010",
            ParentProcessId="7000",
            ParentImage="WINWORD.EXE",
            Image="powershell.exe",
        ),
        make_event(
            "evt-dns",
            "case-1",
            "22",
            ProcessId="7010",
            QueryName="example.com",
        ),
    ]

    result = make_service(events).correlate_activity(
        case_id="case-1",
        event_ids=["evt-parent", "evt-child", "evt-dns"],
    )

    assert result["case_id"] == "case-1"
    assert result["associated_activity_count"] == 1

    child = next(
        item for item in result["processes"]
        if item["process_event_id"] == "evt-child"
    )

    assert child["parent"]["process_event_id"] == "evt-parent"
    assert child["activities"][0]["event_id"] == "evt-dns"


def test_correlate_activity_rejects_event_from_another_case():
    events = [
        make_event(
            "evt-other",
            "case-2",
            "1",
            ProcessId="100",
            Image="other.exe",
        ),
    ]

    with pytest.raises(
        CyberToolInputError,
        match="does not belong to requested case",
    ):
        make_service(events).correlate_activity(
            case_id="case-1",
            event_ids=["evt-other"],
        )


def test_correlate_activity_rejects_missing_event():
    service = make_service([])

    with pytest.raises(
        CyberToolInputError,
        match="event not found",
    ):
        service.correlate_activity(
            case_id="case-1",
            event_ids=["evt-missing"],
        )


def test_correlate_activity_rejects_empty_event_ids():
    with pytest.raises(
        CyberToolInputError,
        match="event_ids must not be empty",
    ):
        make_service([]).correlate_activity(
            case_id="case-1",
            event_ids=[],
        )
