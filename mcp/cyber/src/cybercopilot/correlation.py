from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from cybercopilot.schemas import EventRecord


PID_FALLBACK_WINDOW = timedelta(hours=6)
_ACTIVITY_EVENT_CODES = {"3", "11", "22"}


def _event_data(event: EventRecord) -> dict[str, Any]:
    value = event.fields.get("event_data", {})
    return value if isinstance(value, dict) else {}


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _host_key(event: EventRecord) -> str:
    return (event.host or "").casefold()


def _process_identity(event: EventRecord) -> dict[str, str | None]:
    data = _event_data(event)
    return {
        "process_guid": _clean(data.get("ProcessGuid")),
        "pid": _clean(data.get("ProcessId")),
        "image": _clean(data.get("Image")),
        "command_line": _clean(data.get("CommandLine")),
    }


def _parent_identity(event: EventRecord) -> dict[str, str | None]:
    data = _event_data(event)
    return {
        "process_guid": _clean(data.get("ParentProcessGuid")),
        "pid": _clean(data.get("ParentProcessId")),
        "image": _clean(data.get("ParentImage")),
    }


def _activity_details(event: EventRecord) -> dict[str, str]:
    data = _event_data(event)
    keys_by_code = {
        "3": ("DestinationIp", "DestinationPort", "Protocol", "Image"),
        "11": ("TargetFilename", "Image"),
        "22": ("QueryName", "Image"),
    }

    details: dict[str, str] = {}
    for key in keys_by_code.get(event.event_code or "", ()):
        value = _clean(data.get(key))
        if value is not None:
            details[key] = value
    return details


def _most_recent_prior_process(
    *,
    candidates: list[EventRecord],
    target: EventRecord,
) -> EventRecord | None:
    valid = [
        event
        for event in candidates
        if event.timestamp <= target.timestamp
        and target.timestamp - event.timestamp <= PID_FALLBACK_WINDOW
    ]
    if not valid:
        return None
    return max(valid, key=lambda event: (event.timestamp, event.event_id))


def correlate_process_activity(events: list[EventRecord]) -> dict[str, Any]:
    """
    Build deterministic process/activity relationships from normalized Sysmon events.

    Correlation rules:
    1. Same-host ProcessGuid matches are preferred.
    2. If ProcessGuid is unavailable, ProcessId may be used only against the
       most recent prior process creation on the same host within a bounded
       time window.
    3. Parent metadata present in a process-create event is preserved even when
       the parent's own process-create event is missing.
    4. No maliciousness, causation, or compromise judgment is produced here.
    """
    ordered = sorted(events, key=lambda event: (event.timestamp, event.event_id))
    process_events = [event for event in ordered if event.event_code == "1"]

    by_guid: dict[tuple[str, str], list[EventRecord]] = defaultdict(list)
    by_pid: dict[tuple[str, str], list[EventRecord]] = defaultdict(list)

    for event in process_events:
        identity = _process_identity(event)
        host = _host_key(event)

        if identity["process_guid"]:
            by_guid[(host, identity["process_guid"].casefold())].append(event)

        if identity["pid"]:
            by_pid[(host, identity["pid"])].append(event)

    def resolve_process(
        target: EventRecord,
        *,
        process_guid: str | None,
        pid: str | None,
    ) -> tuple[EventRecord, str] | None:
        host = _host_key(target)

        if process_guid:
            candidates = by_guid.get((host, process_guid.casefold()), [])
            if candidates:
                prior = [item for item in candidates if item.timestamp <= target.timestamp]
                if prior:
                    chosen = max(prior, key=lambda item: (item.timestamp, item.event_id))
                    return chosen, "process_guid"

        if pid:
            chosen = _most_recent_prior_process(
                candidates=by_pid.get((host, pid), []),
                target=target,
            )
            if chosen is not None:
                return chosen, "pid_temporal_fallback"

        return None

    nodes: dict[str, dict[str, Any]] = {}
    pid_fallback_relations = 0

    for event in process_events:
        identity = _process_identity(event)
        parent_identity = _parent_identity(event)

        parent: dict[str, Any] | None = None

        resolved_parent = resolve_process(
            event,
            process_guid=parent_identity["process_guid"],
            pid=parent_identity["pid"],
        )

        if resolved_parent is not None:
            parent_event, basis = resolved_parent

            # Never turn the process into its own parent because of malformed
            # or incomplete telemetry.
            if parent_event.event_id != event.event_id:
                parent_process = _process_identity(parent_event)
                parent = {
                    "process_event_id": parent_event.event_id,
                    "process_guid": parent_process["process_guid"],
                    "pid": parent_process["pid"],
                    "image": parent_process["image"] or parent_identity["image"],
                    "basis": basis,
                }
                if basis == "pid_temporal_fallback":
                    pid_fallback_relations += 1

        if parent is None and any(parent_identity.values()):
            parent = {
                "process_event_id": None,
                "process_guid": parent_identity["process_guid"],
                "pid": parent_identity["pid"],
                "image": parent_identity["image"],
                "basis": "child_event_metadata_only",
            }

        nodes[event.event_id] = {
            "process_event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "host": event.host,
            "process_guid": identity["process_guid"],
            "pid": identity["pid"],
            "image": identity["image"],
            "command_line": identity["command_line"],
            "parent": parent,
            "activities": [],
            "evidence_refs": [
                ref.model_dump(mode="json")
                for ref in event.evidence_refs
            ],
        }

    unassociated_event_ids: list[str] = []
    associated_activity_count = 0

    for event in ordered:
        if event.event_code not in _ACTIVITY_EVENT_CODES:
            continue

        identity = _process_identity(event)
        resolved = resolve_process(
            event,
            process_guid=identity["process_guid"],
            pid=identity["pid"],
        )

        if resolved is None:
            unassociated_event_ids.append(event.event_id)
            continue

        process_event, basis = resolved
        node = nodes.get(process_event.event_id)

        if node is None:
            unassociated_event_ids.append(event.event_id)
            continue

        if basis == "pid_temporal_fallback":
            pid_fallback_relations += 1

        node["activities"].append({
            "event_id": event.event_id,
            "event_code": event.event_code,
            "action": event.action,
            "timestamp": event.timestamp.isoformat(),
            "basis": basis,
            "details": _activity_details(event),
            "evidence_refs": [
                ref.model_dump(mode="json")
                for ref in event.evidence_refs
            ],
        })
        associated_activity_count += 1

    for node in nodes.values():
        node["activities"].sort(
            key=lambda item: (item["timestamp"], item["event_id"])
        )

    warnings: list[str] = []
    if pid_fallback_relations:
        warnings.append(
            "Some relationships use bounded PID/time correlation because "
            "ProcessGuid was unavailable. PID correlation is weaker because "
            "Windows can reuse process IDs."
        )

    return {
        "process_count": len(nodes),
        "associated_activity_count": associated_activity_count,
        "unassociated_event_ids": sorted(unassociated_event_ids),
        "processes": sorted(
            nodes.values(),
            key=lambda item: (item["timestamp"], item["process_event_id"]),
        ),
        "warnings": warnings,
    }
