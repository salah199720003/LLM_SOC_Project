import pytest

from cybercopilot.parsers.sysmon import (
    SysmonParseError,
    parse_sysmon_xml,
)


PROCESS_CREATE_XML = r"""
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-09-17T20:14:15.1234567Z" />
    <EventRecordID>4242</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WS01.example.local</Computer>
  </System>

  <EventData>
    <Data Name="UtcTime">2026-09-17 20:14:15.120</Data>
    <Data Name="ProcessGuid">{11111111-2222-3333-4444-555555555555}</Data>
    <Data Name="ProcessId">8120</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -NoProfile -Command Get-Process</Data>
    <Data Name="User">EXAMPLE\analyst</Data>
  </EventData>
</Event>
"""


def test_parse_process_create():
    events = parse_sysmon_xml(
        PROCESS_CREATE_XML,
        case_id="case-1",
        source_name="fixtures/sysmon.xml",
        artifact_id="art-123",
        artifact_sha256="a" * 64,
    )

    assert len(events) == 1

    event = events[0]

    assert event.source_type == "sysmon"
    assert event.event_code == "1"
    assert event.category == "process"
    assert event.action == "process_create"
    assert event.host == "WS01.example.local"
    assert event.user == r"EXAMPLE\analyst"

    assert (
        event.fields["event_data"]["Image"]
        .endswith("powershell.exe")
    )

    assert event.evidence_refs[0].artifact_id == "art-123"
    assert event.evidence_refs[0].event_id == event.event_id

    assert event.timestamp.isoformat() == (
        "2026-09-17T20:14:15.123456+00:00"
    )


def test_event_id_is_stable():
    first = parse_sysmon_xml(
        PROCESS_CREATE_XML,
        case_id="case-1",
        source_name="fixtures/sysmon.xml",
    )[0]

    second = parse_sysmon_xml(
        PROCESS_CREATE_XML,
        case_id="case-1",
        source_name="fixtures/sysmon.xml",
    )[0]

    assert first.event_id == second.event_id


def test_rejects_wrong_provider():
    xml = PROCESS_CREATE_XML.replace(
        'Name="Microsoft-Windows-Sysmon"',
        'Name="Some-Other-Provider"',
    )

    with pytest.raises(
        SysmonParseError,
        match="unexpected provider",
    ):
        parse_sysmon_xml(
            xml,
            case_id="case-1",
            source_name="fixture.xml",
        )