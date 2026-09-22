from datetime import datetime, timezone
import pytest
from cybercopilot.case_store import CaseStore, CaseStoreConflictError
from cybercopilot.schemas import CaseRecord, EvidenceArtifact, EventRecord

def make_store(tmp_path):
    store=CaseStore(tmp_path/"cases.sqlite3"); store.initialize(); store.create_case(CaseRecord(case_id="case-1", title="Sysmon investigation")); return store

def make_event(*, event_id="evt-1", host="WS01", second=1):
    return EventRecord(event_id=event_id,case_id="case-1",timestamp=datetime(2026,9,17,20,0,second,tzinfo=timezone.utc),timestamp_source="fixture",source_type="sysmon",source_name="fixture.xml",host=host,event_code="1",category="process",action="process_create",fields={"event_data":{"Image":"powershell.exe"}})

def test_store_round_trip(tmp_path):
    store=make_store(tmp_path); artifact=EvidenceArtifact(artifact_id="art-1",case_id="case-1",kind="xml",path="evidence/sysmon.xml",sha256="a"*64,size_bytes=123); event=make_event(); store.put_artifact(artifact); store.put_event(event); loaded=store.load_case("case-1"); assert loaded.case_id=="case-1"; assert loaded.artifacts==[artifact]; assert loaded.events==[event]

def test_duplicate_event_is_idempotent(tmp_path):
    store=make_store(tmp_path); event=make_event(); store.put_event(event); store.put_event(event); result=store.query_events(case_id="case-1"); assert len(result)==1; assert result[0]==event

def test_conflicting_event_is_rejected(tmp_path):
    store=make_store(tmp_path); original=make_event(event_id="evt-fixed",host="WS01"); conflicting=make_event(event_id="evt-fixed",host="WS99"); store.put_event(original)
    with pytest.raises(CaseStoreConflictError, match="different content"): store.put_event(conflicting)

def test_db_query_is_filtered_and_bounded(tmp_path):
    store=make_store(tmp_path); store.put_events([make_event(event_id="evt-3",host="WS02",second=3),make_event(event_id="evt-1",host="WS01",second=1),make_event(event_id="evt-2",host="WS01",second=2)]); result=store.query_events(case_id="case-1",host="WS01",limit=1); assert len(result)==1; assert result[0].event_id=="evt-1"
