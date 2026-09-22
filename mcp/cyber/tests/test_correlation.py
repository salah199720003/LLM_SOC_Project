from datetime import datetime, timedelta, timezone

from cybercopilot.correlation import correlate_process_activity
from cybercopilot.schemas import EventRecord


BASE = datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc)


def event(
    *,
    event_id: str,
    event_code: str,
    seconds: int,
    host: str = "LAB-WS01",
    **event_data,
) -> EventRecord:
    action_by_code = {
        "1": "process_create",
        "3": "network_connect",
        "11": "file_create",
        "22": "dns_query",
    }
    return EventRecord(
        event_id=event_id,
        case_id="case-1",
        timestamp=BASE + timedelta(seconds=seconds),
        timestamp_source="fixture",
        source_type="sysmon",
        source_name="fixture.xml",
        host=host,
        event_code=event_code,
        category="fixture",
        action=action_by_code[event_code],
        fields={"event_data": event_data},
    )


def process_by_id(result, event_id):
    return next(
        item for item in result["processes"]
        if item["process_event_id"] == event_id
    )


def test_correlates_parent_and_activity_with_pid_fallback():
    events = [
        event(
            event_id="evt-word",
            event_code="1",
            seconds=0,
            ProcessId="7000",
            Image=r"C:\Office\WINWORD.EXE",
        ),
        event(
            event_id="evt-ps",
            event_code="1",
            seconds=3,
            ProcessId="7010",
            ParentProcessId="7000",
            ParentImage=r"C:\Office\WINWORD.EXE",
            Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ),
        event(
            event_id="evt-dns",
            event_code="22",
            seconds=5,
            ProcessId="7010",
            QueryName="example.com",
        ),
        event(
            event_id="evt-net",
            event_code="3",
            seconds=6,
            ProcessId="7010",
            DestinationIp="203.0.113.25",
            DestinationPort="443",
        ),
    ]

    result = correlate_process_activity(events)
    ps = process_by_id(result, "evt-ps")

    assert ps["parent"]["process_event_id"] == "evt-word"
    assert ps["parent"]["basis"] == "pid_temporal_fallback"
    assert [item["event_id"] for item in ps["activities"]] == [
        "evt-dns",
        "evt-net",
    ]
    assert all(
        item["basis"] == "pid_temporal_fallback"
        for item in ps["activities"]
    )


def test_process_guid_is_preferred_over_reused_pid():
    events = [
        event(
            event_id="evt-old",
            event_code="1",
            seconds=0,
            ProcessGuid="{OLD}",
            ProcessId="9000",
            Image="old.exe",
        ),
        event(
            event_id="evt-new",
            event_code="1",
            seconds=10,
            ProcessGuid="{NEW}",
            ProcessId="9000",
            Image="new.exe",
        ),
        event(
            event_id="evt-dns",
            event_code="22",
            seconds=11,
            ProcessGuid="{OLD}",
            ProcessId="9000",
            QueryName="example.com",
        ),
    ]

    result = correlate_process_activity(events)

    old = process_by_id(result, "evt-old")
    new = process_by_id(result, "evt-new")

    assert [item["event_id"] for item in old["activities"]] == ["evt-dns"]
    assert old["activities"][0]["basis"] == "process_guid"
    assert new["activities"] == []


def test_pid_fallback_uses_most_recent_prior_process():
    events = [
        event(
            event_id="evt-old",
            event_code="1",
            seconds=0,
            ProcessId="9000",
            Image="old.exe",
        ),
        event(
            event_id="evt-new",
            event_code="1",
            seconds=10,
            ProcessId="9000",
            Image="new.exe",
        ),
        event(
            event_id="evt-file",
            event_code="11",
            seconds=11,
            ProcessId="9000",
            TargetFilename=r"C:\Temp\a.txt",
        ),
    ]

    result = correlate_process_activity(events)

    assert process_by_id(result, "evt-old")["activities"] == []
    assert [
        item["event_id"]
        for item in process_by_id(result, "evt-new")["activities"]
    ] == ["evt-file"]


def test_unassociated_activity_is_not_forced_onto_a_process():
    result = correlate_process_activity([
        event(
            event_id="evt-dns",
            event_code="22",
            seconds=5,
            ProcessId="9999",
            QueryName="example.com",
        ),
    ])

    assert result["process_count"] == 0
    assert result["associated_activity_count"] == 0
    assert result["unassociated_event_ids"] == ["evt-dns"]


def test_parent_metadata_is_preserved_without_parent_process_event():
    result = correlate_process_activity([
        event(
            event_id="evt-ps",
            event_code="1",
            seconds=3,
            ProcessId="7010",
            ParentProcessId="4880",
            ParentImage=r"C:\Windows\System32\cmd.exe",
            Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ),
    ])

    ps = process_by_id(result, "evt-ps")

    assert ps["parent"]["process_event_id"] is None
    assert ps["parent"]["pid"] == "4880"
    assert ps["parent"]["image"].endswith("cmd.exe")
    assert ps["parent"]["basis"] == "child_event_metadata_only"
