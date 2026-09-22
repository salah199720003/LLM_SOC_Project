from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ClaimKind(str, Enum):
    FACT = "fact"
    HYPOTHESIS = "hypothesis"
    UNKNOWN = "unknown"


class EvidenceRef(StrictModel):
    artifact_id: str
    locator: str | None = None
    event_id: str | None = None
    sha256: str | None = None


class EvidenceArtifact(StrictModel):
    artifact_id: str = Field(default_factory=lambda: f"art-{uuid4()}")
    case_id: str
    kind: str
    path: str
    sha256: str
    size_bytes: int = Field(ge=0)
    collected_at: datetime | None = None
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    read_only: bool = True
    parser: str | None = None
    parser_version: str | None = None
    notes: str | None = None


class EventRecord(StrictModel):
    event_id: str = Field(default_factory=lambda: f"evt-{uuid4()}")
    case_id: str
    timestamp: datetime
    timestamp_source: str
    source_type: str
    source_name: str
    host: str | None = None
    user: str | None = None
    event_code: str | None = None
    category: str | None = None
    action: str | None = None
    message: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value


class Observable(StrictModel):
    observable_id: str = Field(default_factory=lambda: f"obs-{uuid4()}")
    case_id: str
    type: Literal["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"]
    value: str
    normalized_value: str
    internal: bool | None = None
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class SourceCitation(StrictModel):
    citation_id: str = Field(default_factory=lambda: f"src-{uuid4()}")
    url: str
    title: str | None = None
    publisher: str | None = None
    retrieved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    quote_or_highlight: str | None = None


class Claim(StrictModel):
    claim_id: str = Field(default_factory=lambda: f"clm-{uuid4()}")
    case_id: str
    kind: ClaimKind
    text: str
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    citation_ids: list[str] = Field(default_factory=list)
    status: Literal["open", "supported", "rejected", "resolved"] = "open"


class AttackMapping(StrictModel):
    mapping_id: str = Field(default_factory=lambda: f"atk-{uuid4()}")
    case_id: str
    technique_id: str
    technique_name: str
    attack_version: str
    basis: str
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class DetectionArtifact(StrictModel):
    detection_id: str = Field(default_factory=lambda: f"det-{uuid4()}")
    case_id: str
    kind: Literal["sigma", "wazuh", "kql"]
    name: str
    body: str
    status: Literal["draft", "validated", "tested", "rejected"] = "draft"
    positive_tests: int = 0
    positive_passed: int = 0
    benign_tests: int = 0
    benign_passed: int = 0
    false_positive_notes: list[str] = Field(default_factory=list)
    attack_technique_ids: list[str] = Field(default_factory=list)


class CaseRecord(StrictModel):
    schema_version: str = "0.1.0"
    case_id: str = Field(default_factory=lambda: f"case-{uuid4()}")
    title: str
    status: Literal["open", "closed", "archived"] = "open"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    artifacts: list[EvidenceArtifact] = Field(default_factory=list)
    events: list[EventRecord] = Field(default_factory=list)
    observables: list[Observable] = Field(default_factory=list)
    citations: list[SourceCitation] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    attack_mappings: list[AttackMapping] = Field(default_factory=list)
    detections: list[DetectionArtifact] = Field(default_factory=list)
