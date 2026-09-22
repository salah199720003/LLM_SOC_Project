from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Iterator

from cybercopilot.schemas import AttackMapping, CaseRecord, Claim, DetectionArtifact, EvidenceArtifact, EventRecord, Observable, SourceCitation

MAX_DB_QUERY_RESULTS = 1000
DEFAULT_DB_QUERY_RESULTS = 200

class CaseStoreError(RuntimeError): pass
class CaseStoreConflictError(CaseStoreError): pass
class CaseNotFoundError(CaseStoreError): pass

def _canonical_json(model) -> str:
    return json.dumps(model.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None: raise ValueError("database timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat()

class CaseStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.db_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback(); raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._connect() as db:
            db.execute("PRAGMA journal_mode = WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS cases (case_id TEXT PRIMARY KEY, schema_version TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, payload_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS artifacts (artifact_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL, kind TEXT NOT NULL, size_bytes INTEGER NOT NULL, payload_json TEXT NOT NULL, FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE RESTRICT);
                CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id);
                CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);
                CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, timestamp_utc TEXT NOT NULL, host TEXT, user_name TEXT, event_code TEXT, category TEXT, action TEXT, payload_json TEXT NOT NULL, FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE RESTRICT);
                CREATE INDEX IF NOT EXISTS idx_events_case_time ON events(case_id, timestamp_utc);
                CREATE INDEX IF NOT EXISTS idx_events_case_host ON events(case_id, host);
                CREATE INDEX IF NOT EXISTS idx_events_case_code ON events(case_id, event_code);
                CREATE TABLE IF NOT EXISTS case_objects (object_type TEXT NOT NULL, object_id TEXT NOT NULL, case_id TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(object_type, object_id), FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE RESTRICT);
                CREATE INDEX IF NOT EXISTS idx_case_objects_case_type ON case_objects(case_id, object_type);
            """)

    def create_case(self, case: CaseRecord) -> None:
        header = case.model_copy(update={"artifacts": [], "events": [], "observables": [], "citations": [], "claims": [], "attack_mappings": [], "detections": []})
        payload = _canonical_json(header)
        with self._connect() as db:
            existing = db.execute("SELECT payload_json FROM cases WHERE case_id = ?", (case.case_id,)).fetchone()
            if existing is not None:
                if existing["payload_json"] != payload: raise CaseStoreConflictError("case ID already exists with different content")
                return
            db.execute("INSERT INTO cases (case_id, schema_version, title, status, created_at, payload_json) VALUES (?, ?, ?, ?, ?, ?)", (header.case_id, header.schema_version, header.title, header.status, _utc_text(header.created_at), payload))

    def _require_case(self, db: sqlite3.Connection, case_id: str) -> None:
        if db.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone() is None: raise CaseNotFoundError(f"case not found: {case_id}")

    def put_artifact(self, artifact: EvidenceArtifact) -> None:
        payload = _canonical_json(artifact)
        with self._connect() as db:
            self._require_case(db, artifact.case_id)
            existing = db.execute("SELECT case_id, payload_json FROM artifacts WHERE artifact_id = ?", (artifact.artifact_id,)).fetchone()
            if existing is not None:
                stored = EvidenceArtifact.model_validate_json(existing["payload_json"])
                stored_identity = stored.model_dump(mode="json", exclude={"ingested_at"})
                incoming_identity = artifact.model_dump(mode="json", exclude={"ingested_at"})
                if existing["case_id"] != artifact.case_id or stored_identity != incoming_identity:
                    raise CaseStoreConflictError("artifact ID already exists with different content")
                return
            db.execute("INSERT INTO artifacts (artifact_id, case_id, path, sha256, kind, size_bytes, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)", (artifact.artifact_id, artifact.case_id, artifact.path, artifact.sha256, artifact.kind, artifact.size_bytes, payload))

    def put_event(self, event: EventRecord) -> None: self.put_events([event])
    def put_events(self, events: list[EventRecord]) -> None:
        if not events: return
        with self._connect() as db:
            checked_cases: set[str] = set()
            for event in events:
                if event.case_id not in checked_cases:
                    self._require_case(db, event.case_id); checked_cases.add(event.case_id)
                payload = _canonical_json(event)
                existing = db.execute("SELECT case_id, payload_json FROM events WHERE event_id = ?", (event.event_id,)).fetchone()
                if existing is not None:
                    if existing["case_id"] != event.case_id or existing["payload_json"] != payload: raise CaseStoreConflictError("event ID already exists with different content")
                    continue
                db.execute("INSERT INTO events (event_id, case_id, timestamp_utc, host, user_name, event_code, category, action, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (event.event_id, event.case_id, _utc_text(event.timestamp), event.host, event.user, event.event_code, event.category, event.action, payload))

    def get_artifact(self, artifact_id: str) -> EvidenceArtifact | None:
        with self._connect() as db: row = db.execute("SELECT payload_json FROM artifacts WHERE artifact_id = ?", (artifact_id,)).fetchone()
        return None if row is None else EvidenceArtifact.model_validate_json(row["payload_json"])
    def get_event(self, event_id: str) -> EventRecord | None:
        with self._connect() as db: row = db.execute("SELECT payload_json FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return None if row is None else EventRecord.model_validate_json(row["payload_json"])

    def query_events(self, *, case_id: str, start: datetime | None = None, end: datetime | None = None, host: str | None = None, user: str | None = None, event_code: str | None = None, category: str | None = None, action: str | None = None, limit: int = DEFAULT_DB_QUERY_RESULTS) -> list[EventRecord]:
        if limit < 1 or limit > MAX_DB_QUERY_RESULTS: raise ValueError(f"limit must be between 1 and {MAX_DB_QUERY_RESULTS}")
        start_text = _utc_text(start) if start is not None else None; end_text = _utc_text(end) if end is not None else None
        if start is not None and end is not None and start > end: raise ValueError("start must be earlier than or equal to end")
        clauses=["case_id = ?"]; params: list[object]=[case_id]
        for clause, value in (("timestamp_utc >= ?", start_text), ("timestamp_utc <= ?", end_text), ("host = ?", host), ("user_name = ?", user), ("event_code = ?", event_code), ("category = ?", category), ("action = ?", action)):
            if value is not None: clauses.append(clause); params.append(value)
        params.append(limit)
        sql = f"SELECT payload_json FROM events WHERE {' AND '.join(clauses)} ORDER BY timestamp_utc ASC, event_id ASC LIMIT ?"
        with self._connect() as db:
            self._require_case(db, case_id); rows = db.execute(sql, params).fetchall()
        return [EventRecord.model_validate_json(row["payload_json"]) for row in rows]

    def _put_object(self, *, case_id: str, object_type: str, object_id: str, model) -> None:
        payload = _canonical_json(model); model_case_id = getattr(model, "case_id", case_id)
        if model_case_id != case_id: raise CaseStoreConflictError("object case_id does not match target case")
        with self._connect() as db:
            self._require_case(db, case_id)
            existing = db.execute("SELECT case_id, payload_json FROM case_objects WHERE object_type = ? AND object_id = ?", (object_type, object_id)).fetchone()
            if existing is not None:
                if existing["case_id"] != case_id or existing["payload_json"] != payload: raise CaseStoreConflictError(f"{object_type} ID already exists with different content")
                return
            db.execute("INSERT INTO case_objects (object_type, object_id, case_id, payload_json) VALUES (?, ?, ?, ?)", (object_type, object_id, case_id, payload))

    def put_observable(self, observable: Observable) -> None: self._put_object(case_id=observable.case_id, object_type="observable", object_id=observable.observable_id, model=observable)
    def put_claim(self, claim: Claim) -> None: self._put_object(case_id=claim.case_id, object_type="claim", object_id=claim.claim_id, model=claim)
    def put_attack_mapping(self, mapping: AttackMapping) -> None: self._put_object(case_id=mapping.case_id, object_type="attack_mapping", object_id=mapping.mapping_id, model=mapping)
    def put_detection(self, detection: DetectionArtifact) -> None: self._put_object(case_id=detection.case_id, object_type="detection", object_id=detection.detection_id, model=detection)
    def put_citation(self, *, case_id: str, citation: SourceCitation) -> None: self._put_object(case_id=case_id, object_type="citation", object_id=citation.citation_id, model=citation)

    def _load_objects(self, *, case_id: str, object_type: str, model_class) -> list:
        with self._connect() as db: rows = db.execute("SELECT payload_json FROM case_objects WHERE case_id = ? AND object_type = ? ORDER BY object_id ASC", (case_id, object_type)).fetchall()
        return [model_class.model_validate_json(row["payload_json"]) for row in rows]

    def load_case(self, case_id: str) -> CaseRecord:
        with self._connect() as db:
            row = db.execute("SELECT payload_json FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            if row is None: raise CaseNotFoundError(f"case not found: {case_id}")
            artifact_rows = db.execute("SELECT payload_json FROM artifacts WHERE case_id = ? ORDER BY artifact_id ASC", (case_id,)).fetchall()
            event_rows = db.execute("SELECT payload_json FROM events WHERE case_id = ? ORDER BY timestamp_utc ASC, event_id ASC", (case_id,)).fetchall()
        header = CaseRecord.model_validate_json(row["payload_json"])
        return header.model_copy(update={"artifacts": [EvidenceArtifact.model_validate_json(x["payload_json"]) for x in artifact_rows], "events": [EventRecord.model_validate_json(x["payload_json"]) for x in event_rows], "observables": self._load_objects(case_id=case_id, object_type="observable", model_class=Observable), "citations": self._load_objects(case_id=case_id, object_type="citation", model_class=SourceCitation), "claims": self._load_objects(case_id=case_id, object_type="claim", model_class=Claim), "attack_mappings": self._load_objects(case_id=case_id, object_type="attack_mapping", model_class=AttackMapping), "detections": self._load_objects(case_id=case_id, object_type="detection", model_class=DetectionArtifact)})
