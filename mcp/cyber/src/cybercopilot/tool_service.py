from __future__ import annotations
from cybercopilot.correlation import correlate_process_activity
import hashlib
from pathlib import Path
from cybercopilot.sigma_tools import test_sigma_rule, validate_sigma_rule
from cybercopilot.attack_store import AttackStore
from cybercopilot.sigma_tools import test_sigma_rule, validate_sigma_rule
from cybercopilot.case_store import CaseStore
from cybercopilot.sigma_tools import test_sigma_rule, validate_sigma_rule
from cybercopilot.attack_store import AttackStore
from cybercopilot.sigma_tools import test_sigma_rule, validate_sigma_rule
from cybercopilot.evidence.ingest import EvidenceTooLargeError, ingest_evidence, resolve_evidence_path
from cybercopilot.sigma_tools import test_sigma_rule, validate_sigma_rule
from cybercopilot.attack_store import AttackStore
from cybercopilot.sigma_tools import test_sigma_rule, validate_sigma_rule
from cybercopilot.iocs import extract_iocs
from cybercopilot.sigma_tools import test_sigma_rule, validate_sigma_rule
from cybercopilot.attack_store import AttackStore
from cybercopilot.sigma_tools import test_sigma_rule, validate_sigma_rule
from cybercopilot.parsers.sysmon import parse_sysmon_xml
from cybercopilot.sigma_tools import test_sigma_rule, validate_sigma_rule
from cybercopilot.attack_store import AttackStore
from cybercopilot.sigma_tools import test_sigma_rule, validate_sigma_rule
from cybercopilot.schemas import CaseRecord, EvidenceArtifact
from cybercopilot.sigma_tools import test_sigma_rule, validate_sigma_rule
from cybercopilot.attack_store import AttackStore
from cybercopilot.sigma_tools import test_sigma_rule, validate_sigma_rule
from cybercopilot.timeline import build_timeline
MAX_PARSE_BYTES = 8 * 1024 * 1024
MAX_EVENT_IDS_PER_TOOL_CALL = 100
MAX_TIMELINE_EVENTS = 1000
class CyberToolError(RuntimeError): pass
class CyberToolInputError(CyberToolError): pass
class ArtifactIntegrityError(CyberToolError): pass
class CyberToolService:
    def correlate_activity(
        self,
        *,
        case_id: str,
        event_ids: list[str],
    ) -> dict:
        if not event_ids:
            raise CyberToolInputError(
                "event_ids must not be empty"
            )

        if len(event_ids) > MAX_EVENT_IDS_PER_TOOL_CALL:
            raise CyberToolInputError(
                "too many event IDs in one tool call"
            )

        events = []

        for event_id in event_ids:
            event = self.store.get_event(event_id)

            if event is None:
                raise CyberToolInputError(
                    f"event not found: {event_id}"
                )

            if event.case_id != case_id:
                raise CyberToolInputError(
                    "event does not belong to requested case"
                )

            events.append(event)

        result = correlate_process_activity(events)

        return {
            "trust": "derived_from_untrusted_evidence",
            "case_id": case_id,
            "input_event_ids": event_ids,
            **result,
        }

    def __init__(self, *, project_root: str | Path, db_path: str | Path) -> None:
        self.project_root = Path(project_root).resolve(strict=True)
        self.store = CaseStore(db_path); self.store.initialize()
    def create_case(self, *, title: str, case_id: str | None = None) -> dict:
        if not title.strip(): raise CyberToolInputError("case title must not be empty")
        kwargs={"title": title.strip()}
        if case_id is not None: kwargs["case_id"] = case_id
        case = CaseRecord(**kwargs); self.store.create_case(case)
        return {"case_id": case.case_id, "title": case.title, "status": case.status}
    def ingest_evidence(self, *, case_id: str, path: str) -> dict:
        artifact = ingest_evidence(case_id=case_id, project_root=self.project_root, requested_path=path)
        self.store.put_artifact(artifact)
        return {"trust": "untrusted_metadata", "artifact": artifact.model_dump(mode="json")}
    def _load_verified_artifact(self, *, case_id: str, artifact_id: str) -> tuple[EvidenceArtifact, bytes]:
        artifact = self.store.get_artifact(artifact_id)
        if artifact is None: raise CyberToolInputError(f"artifact not found: {artifact_id}")
        if artifact.case_id != case_id: raise CyberToolInputError("artifact does not belong to requested case")
        path, _ = resolve_evidence_path(project_root=self.project_root, requested_path=artifact.path)
        if path.stat().st_size > MAX_PARSE_BYTES: raise EvidenceTooLargeError("artifact exceeds parser size limit")
        with path.open("rb") as handle: data = handle.read(MAX_PARSE_BYTES + 1)
        if len(data) > MAX_PARSE_BYTES: raise EvidenceTooLargeError("artifact exceeds parser size limit")
        current_hash = hashlib.sha256(data).hexdigest()
        if current_hash != artifact.sha256: raise ArtifactIntegrityError("artifact SHA-256 no longer matches the ingested evidence")
        return artifact, data
    def parse_events(self, *, case_id: str, artifact_id: str, format: str = "sysmon_xml") -> dict:
        artifact, data = self._load_verified_artifact(case_id=case_id, artifact_id=artifact_id)
        if format != "sysmon_xml": raise CyberToolInputError(f"unsupported event format: {format}")
        events = parse_sysmon_xml(data, case_id=case_id, source_name=artifact.path, artifact_id=artifact.artifact_id, artifact_sha256=artifact.sha256)
        self.store.put_events(events)
        return {"trust": "untrusted_evidence", "case_id": case_id, "artifact_id": artifact_id, "format": format, "parsed_count": len(events), "event_ids": [e.event_id for e in events[:100]], "event_ids_truncated": len(events) > 100}
    def query_events(self, *, case_id: str, host: str | None = None, user: str | None = None, event_code: str | None = None, category: str | None = None, action: str | None = None, limit: int = 200) -> dict:
        events = self.store.query_events(case_id=case_id, host=host, user=user, event_code=event_code, category=category, action=action, limit=limit)
        return {"trust": "untrusted_evidence", "count": len(events), "events": [event.model_dump(mode="json") for event in events]}
    def extract_iocs(self, *, case_id: str, event_ids: list[str], include_private_ips: bool = True) -> dict:
        if not event_ids: raise CyberToolInputError("event_ids must not be empty")
        if len(event_ids) > MAX_EVENT_IDS_PER_TOOL_CALL: raise CyberToolInputError("too many event IDs in one tool call")
        observables={}
        for event_id in event_ids:
            event = self.store.get_event(event_id)
            if event is None: raise CyberToolInputError(f"event not found: {event_id}")
            if event.case_id != case_id: raise CyberToolInputError("event does not belong to requested case")
            if not event.evidence_refs: raise CyberToolInputError(f"event has no provenance: {event_id}")
            payload={"message": event.message, "fields": event.fields}
            for evidence_ref in event.evidence_refs:
                for observable in extract_iocs(case_id=case_id, payload=payload, evidence_ref=evidence_ref, include_private_ips=include_private_ips): observables[observable.observable_id]=observable
        ordered=sorted(observables.values(), key=lambda item:(item.type,item.normalized_value,item.observable_id))
        for observable in ordered: self.store.put_observable(observable)
        return {"trust":"derived_from_untrusted_evidence","count":len(ordered),"observables":[item.model_dump(mode="json") for item in ordered]}
    def attack_lookup(
        self,
        *,
        query: str,
        limit: int = 10,
    ) -> dict:
        """
        Look up official metadata from the pinned local ATT&CK
        Enterprise index.

        This tool returns reference metadata only and does not
        infer that a technique occurred in the investigated case.
        """

        index_path = (
            self.project_root
            / "data"
            / "reference"
            / "attack"
            / "v19.2"
            / "enterprise-attack-index.json"
        )

        store = AttackStore(index_path)

        result = store.lookup(
            query,
            limit=limit,
        )

        return {
            "trust": "trusted_reference_data",
            **result,
        }
    def sigma_validate(
        self,
        *,
        rule_yaml: str,
    ) -> dict:
        """Validate one Sigma rule deterministically with pinned pySigma."""
        return validate_sigma_rule(rule_yaml)

    def sigma_test(
        self,
        *,
        case_id: str,
        rule_yaml: str,
        event_ids: list[str],
        expected_match_event_ids: list[str] | None = None,
    ) -> dict:
        """
        Test one Sigma rule against specific already-normalized case events.

        The local matcher is deliberately bounded. Unsupported valid Sigma
        features are reported as unsupported rather than approximated.
        """
        if not event_ids:
            raise CyberToolInputError("event_ids must not be empty")

        if len(event_ids) > MAX_EVENT_IDS_PER_TOOL_CALL:
            raise CyberToolInputError("too many event IDs in one tool call")

        if expected_match_event_ids is not None:
            unknown_expected = (
                set(expected_match_event_ids) - set(event_ids)
            )
            if unknown_expected:
                raise CyberToolInputError(
                    "expected_match_event_ids must be a subset of event_ids"
                )

        events = []
        for event_id in event_ids:
            event = self.store.get_event(event_id)
            if event is None:
                raise CyberToolInputError(
                    f"event not found: {event_id}"
                )
            if event.case_id != case_id:
                raise CyberToolInputError(
                    "event does not belong to requested case"
                )
            events.append(event.model_dump(mode="json"))

        result = test_sigma_rule(
            rule_yaml,
            events=events,
            expected_match_event_ids=expected_match_event_ids,
        )

        return {
            "trust": "derived_from_untrusted_evidence",
            "case_id": case_id,
            **result,
        }
    def build_timeline(self, *, case_id: str, host: str | None = None, event_code: str | None = None, category: str | None = None, limit: int = 500) -> dict:
        if limit < 1 or limit > MAX_TIMELINE_EVENTS: raise CyberToolInputError("timeline limit must be between 1 and 1000")
        events=self.store.query_events(case_id=case_id,host=host,event_code=event_code,category=category,limit=limit)
        timeline=build_timeline(events)
        return {"trust":"untrusted_evidence","count":len(timeline),"timeline":timeline}



