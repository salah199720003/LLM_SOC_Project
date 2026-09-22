import pytest
from cybercopilot.tool_service import ArtifactIntegrityError, CyberToolService

SYSMON_XML = r'''
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-09-17T20:14:15.123456Z" />
    <EventRecordID>4242</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WS01.example.local</Computer>
  </System>
  <EventData>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -c Invoke-WebRequest https://example.com/a -UseBasicParsing</Data>
    <Data Name="User">EXAMPLE\analyst</Data>
    <Data Name="DestinationIp">8.8.8.8</Data>
  </EventData>
</Event>
'''

def make_service(tmp_path):
    project=tmp_path/"project"; evidence=project/"evidence"; evidence.mkdir(parents=True); service=CyberToolService(project_root=project, db_path=project/"cases.sqlite3"); service.create_case(case_id="case-1", title="Test investigation"); return project, service

def test_end_to_end_tool_service(tmp_path):
    project,service=make_service(tmp_path); sample=project/"evidence"/"sysmon.xml"; sample.write_text(SYSMON_XML,encoding="utf-8"); ingested=service.ingest_evidence(case_id="case-1",path="evidence/sysmon.xml"); artifact_id=ingested["artifact"]["artifact_id"]; parsed=service.parse_events(case_id="case-1",artifact_id=artifact_id); assert parsed["parsed_count"]==1; queried=service.query_events(case_id="case-1",host="WS01.example.local"); assert queried["count"]==1; event_id=queried["events"][0]["event_id"]; iocs=service.extract_iocs(case_id="case-1",event_ids=[event_id]); values={item["normalized_value"] for item in iocs["observables"]}; assert "8.8.8.8" in values; assert "https://example.com/a" in values; timeline=service.build_timeline(case_id="case-1"); assert timeline["count"]==1; assert timeline["timeline"][0]["event_id"]==event_id

def test_reingest_is_idempotent(tmp_path):
    project,service=make_service(tmp_path); sample=project/"evidence"/"sysmon.xml"; sample.write_text(SYSMON_XML,encoding="utf-8"); first=service.ingest_evidence(case_id="case-1",path="evidence/sysmon.xml"); second=service.ingest_evidence(case_id="case-1",path="evidence/sysmon.xml"); assert first["artifact"]["artifact_id"]==second["artifact"]["artifact_id"]

def test_tampering_after_ingest_is_rejected(tmp_path):
    project,service=make_service(tmp_path); sample=project/"evidence"/"sysmon.xml"; sample.write_text(SYSMON_XML,encoding="utf-8"); result=service.ingest_evidence(case_id="case-1",path="evidence/sysmon.xml"); artifact_id=result["artifact"]["artifact_id"]; sample.write_text("<Event>tampered</Event>",encoding="utf-8")
    with pytest.raises(ArtifactIntegrityError, match="SHA-256"): service.parse_events(case_id="case-1",artifact_id=artifact_id)
