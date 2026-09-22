from datetime import datetime, timezone

import pytest

from cybercopilot.query import query_events
from cybercopilot.schemas import EventRecord


def make_event(
    *,
    event_id: str,
    event_code: str,
    host: str,
    second: int,
    image: str,
) -> EventRecord:
    return EventRecord(
        event_id=event_id,
        case_id="case-1",
        timestamp=datetime(
            2026,
            9,
            17,
            20,
            0,
            second,
            tzinfo=timezone.utc,
        ),
        timestamp_source="fixture",
        source_type="sysmon",
        source_name="fixture.xml",
        host=host,
        event_code=event_code,
        category="process",
        action="process_create",
        fields={
            "event_data": {
                "Image": image,
            }
        },
    )


def test_query_by_host_and_event_code():
    events = [
        make_event(
            event_id="evt-2",
            event_code="3",
            host="WS02",
            second=2,
            image="other.exe",
        ),
        make_event(
            event_id="evt-1",
            event_code="1",
            host="WS01",
            second=1,
            image="powershell.exe",
        ),
    ]

    result = query_events(
        events,
        hosts={"WS01"},
        event_codes={"1"},
    )

    assert [e.event_id for e in result] == [
        "evt-1"
    ]


def test_query_nested_field():
    events = [
        make_event(
            event_id="evt-1",
            event_code="1",
            host="WS01",
            second=1,
            image="powershell.exe",
        ),
        make_event(
            event_id="evt-2",
            event_code="1",
            host="WS01",
            second=2,
            image="cmd.exe",
        ),
    ]

    result = query_events(
        events,
        field_equals={
            "event_data.Image": "powershell.exe"
        },
    )

    assert [e.event_id for e in result] == [
        "evt-1"
    ]


def test_query_is_stably_ordered_and_limited():
    events = [
        make_event(
            event_id="evt-3",
            event_code="1",
            host="WS01",
            second=3,
            image="c.exe",
        ),
        make_event(
            event_id="evt-1",
            event_code="1",
            host="WS01",
            second=1,
            image="a.exe",
        ),
        make_event(
            event_id="evt-2",
            event_code="1",
            host="WS01",
            second=2,
            image="b.exe",
        ),
    ]

    result = query_events(
        events,
        limit=2,
    )

    assert [e.event_id for e in result] == [
        "evt-1",
        "evt-2",
    ]


def test_query_rejects_unbounded_limit():
    with pytest.raises(ValueError):
        query_events(
            [],
            limit=5000,
        )