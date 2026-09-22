"""Compact, model-facing renderings of deterministic cyber tool results.

The tool service and case store deliberately retain their complete structured
payloads.  This module is used only at the MCP text boundary, where a client
would otherwise replay those complete payloads to a model on every tool turn.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any


_REF_LABELS: ContextVar[dict[str, str]] = ContextVar(
    "model_context_ref_labels",
    default={},
)


def compact_tool_result(payload: dict[str, Any]) -> str:
    """Return a concise, loss-aware view of one runtime result for an LLM.

    ``payload`` is never modified.  The caller retains the full result and
    case-backed raw evidence; only the text sent through MCP is compacted.
    """
    lines = [_header(payload)]
    if not payload.get("ok"):
        lines.extend(_error_lines(payload))
        return "\n".join(lines)

    data = payload.get("data")
    if not isinstance(data, dict):
        lines.append("DATA " + _value(data))
        return "\n".join(lines)

    tool = _text(payload.get("tool"))
    ref_labels, provenance = _provenance_catalog(data)
    token = _REF_LABELS.set(ref_labels)
    renderers = {
        "query_events": _query_events,
        "build_timeline": _timeline,
        "correlate_activity": _correlation,
        "extract_iocs": _iocs,
        "attack_lookup": _attack_lookup,
        "parse_events": _parse_events,
        "ingest_evidence": _ingest_evidence,
        "create_case": _create_case,
        "sigma_validate": _generic_data,
        "sigma_test": _generic_data,
    }
    try:
        lines.extend(renderers.get(tool, _generic_data)(data))
        lines.extend(provenance)
        return "\n".join(line for line in lines if line)
    finally:
        _REF_LABELS.reset(token)


def _header(payload: dict[str, Any]) -> str:
    status = "ok" if payload.get("ok") else "error"
    parts = ["TOOL", _text(payload.get("tool"), "unknown"), status]
    call_id = _text(payload.get("call_id"))
    if call_id:
        parts.append(f"call={call_id}")
    return " ".join(parts)


def _error_lines(payload: dict[str, Any]) -> list[str]:
    parts = ["ERROR"]
    for key in ("code", "error_type", "message"):
        value = _text(payload.get(key))
        if value:
            parts.append(f"{key}={_compact_text(value, 500)}")
    errors = payload.get("errors")
    if isinstance(errors, list):
        for error in errors:
            if isinstance(error, dict):
                location = ".".join(str(item) for item in error.get("loc", []))
                message = _text(error.get("msg"))
                parts.append(f"validation[{location or '?'}]={message}")
    return [" ".join(parts)]


def _query_events(data: dict[str, Any]) -> list[str]:
    events = _dicts(data.get("events"))
    lines = [f"EVENTS count={_count(data, events)}"]
    seen: set[str] = set()
    for event in sorted(events, key=_event_order):
        event_id = _text(event.get("event_id"))
        key = event_id or repr(event)
        if key in seen:
            continue
        seen.add(key)
        lines.append(_event_line(event))
    return lines


def _timeline(data: dict[str, Any]) -> list[str]:
    timeline = _dicts(data.get("timeline"))
    lines = [f"TIMELINE count={_count(data, timeline)}"]
    seen: set[str] = set()
    for item in timeline:
        event_id = _text(item.get("event_id"))
        if event_id and event_id in seen:
            continue
        seen.add(event_id)
        lines.append(_event_line(item))
    return lines


def _event_line(event: dict[str, Any]) -> str:
    fields = event.get("fields")
    event_data = fields.get("event_data", {}) if isinstance(fields, dict) else {}
    system = fields.get("system", {}) if isinstance(fields, dict) else {}
    if not isinstance(event_data, dict):
        event_data = {}
    if not isinstance(system, dict):
        system = {}

    parts = ["EVENT"]
    _add(parts, "id", event.get("event_id"))
    _add(parts, "record", system.get("record_id"))
    _add(parts, "time", event.get("timestamp_utc", event.get("timestamp")))
    _add(parts, "host", event.get("host"))
    _add(parts, "code", event.get("event_code"))
    _add(parts, "action", event.get("action"))
    _add(parts, "user", event.get("user"))
    for source, label in (
        ("Image", "image"),
        ("ProcessId", "pid"),
        ("ProcessGuid", "guid"),
        ("ParentImage", "parent_image"),
        ("ParentProcessId", "parent_pid"),
        ("ParentProcessGuid", "parent_guid"),
        ("CommandLine", "cmd"),
        ("QueryName", "query"),
        ("DestinationIp", "dst_ip"),
        ("DestinationPort", "dst_port"),
        ("Protocol", "protocol"),
        ("TargetFilename", "target"),
    ):
        _add(parts, label, event_data.get(source), limit=360)
    _add(parts, "message", event.get("message"), limit=360)
    _add_refs(parts, event.get("evidence_refs"))
    return " ".join(parts)


def _correlation(data: dict[str, Any]) -> list[str]:
    processes = _dicts(data.get("processes"))
    lines = [
        "CORRELATION"
        f" processes={_count(data, processes, 'process_count')}"
        f" associated={_text(data.get('associated_activity_count'), '0')}"
    ]
    seen_activities: set[str] = set()
    for process in sorted(processes, key=lambda item: (_text(item.get("timestamp")), _text(item.get("process_event_id")))):
        parts = ["PROCESS"]
        _add(parts, "event", process.get("process_event_id"))
        _add(parts, "time", process.get("timestamp"))
        _add(parts, "host", process.get("host"))
        _add(parts, "guid", process.get("process_guid"))
        _add(parts, "pid", process.get("pid"))
        _add(parts, "image", process.get("image"))
        _add(parts, "cmd", process.get("command_line"), limit=360)
        parent = process.get("parent")
        if isinstance(parent, dict):
            _add(parts, "parent_event", parent.get("process_event_id"))
            _add(parts, "parent_guid", parent.get("process_guid"))
            _add(parts, "parent_pid", parent.get("pid"))
            _add(parts, "parent_image", parent.get("image"))
            _add(parts, "parent_basis", parent.get("basis"))
        _add_refs(parts, process.get("evidence_refs"))
        lines.append(" ".join(parts))
        for activity in _dicts(process.get("activities")):
            event_id = _text(activity.get("event_id"))
            if event_id and event_id in seen_activities:
                continue
            seen_activities.add(event_id)
            activity_parts = ["ACTIVITY"]
            _add(activity_parts, "event", event_id)
            _add(activity_parts, "process_event", process.get("process_event_id"))
            _add(activity_parts, "time", activity.get("timestamp"))
            _add(activity_parts, "code", activity.get("event_code"))
            _add(activity_parts, "action", activity.get("action"))
            _add(activity_parts, "basis", activity.get("basis"))
            details = activity.get("details")
            if isinstance(details, dict):
                for key in ("QueryName", "DestinationIp", "DestinationPort", "Protocol", "TargetFilename", "Image"):
                    _add(activity_parts, key, details.get(key), limit=360)
            _add_refs(activity_parts, activity.get("evidence_refs"))
            lines.append(" ".join(activity_parts))
    unassociated = _strings(data.get("unassociated_event_ids"))
    if unassociated:
        lines.append("UNASSOCIATED " + ",".join(sorted(set(unassociated))))
    for warning in _strings(data.get("warnings")):
        lines.append("WARNING " + _compact_text(warning, 500))
    return lines


def _iocs(data: dict[str, Any]) -> list[str]:
    observables = _dicts(data.get("observables"))
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for observable in observables:
        kind = _text(observable.get("type"), "unknown")
        value = _text(observable.get("normalized_value"), _text(observable.get("value")))
        grouped.setdefault((kind, value), []).append(observable)
    # The displayed count must equal the distinct observables below, not the
    # raw record count (which may include the same observable with new refs).
    lines = [f"IOCS count={len(grouped)}"]
    for (kind, value), entries in sorted(grouped.items()):
        parts = ["IOC", f"type={kind}", f"value={_value(value)}"]
        internal_values = {entry.get("internal") for entry in entries if isinstance(entry.get("internal"), bool)}
        if len(internal_values) == 1:
            parts.append(f"internal={str(internal_values.pop()).lower()}")
        refs = [ref for entry in entries for ref in _dicts(entry.get("evidence_refs"))]
        _add_refs(parts, refs)
        lines.append(" ".join(parts))
    return lines


def _attack_lookup(data: dict[str, Any]) -> list[str]:
    results = _dicts(data.get("results"))
    lines = [
        "ATTACK_REFERENCE"
        f" source={_value(data.get('source'))}"
        f" version={_value(data.get('attack_version'))}"
        f" count={_count(data, results)}"
    ]
    for result in results:
        parts = ["TECHNIQUE"]
        for key in ("attack_id", "name", "tactics", "platforms", "url"):
            value = result.get(key)
            if isinstance(value, list):
                value = ",".join(_strings(value))
            _add(parts, key, value, limit=500)
        lines.append(" ".join(parts))
    notice = _text(data.get("interpretation_notice"))
    if notice:
        lines.append("NOTICE " + _compact_text(notice, 300))
    return lines


def _parse_events(data: dict[str, Any]) -> list[str]:
    parts = ["PARSED"]
    for key in ("case_id", "artifact_id", "format", "parsed_count"):
        _add(parts, key, data.get(key))
    event_ids = _strings(data.get("event_ids"))
    if event_ids:
        parts.append("event_ids=" + ",".join(event_ids))
    if data.get("event_ids_truncated"):
        parts.append("event_ids_truncated=true")
    return [" ".join(parts)]


def _ingest_evidence(data: dict[str, Any]) -> list[str]:
    artifact = data.get("artifact")
    if not isinstance(artifact, dict):
        return _generic_data(data)
    parts = ["ARTIFACT"]
    for key in ("artifact_id", "case_id", "kind", "path", "sha256", "size_bytes", "parser", "parser_version"):
        _add(parts, key, artifact.get(key))
    return [" ".join(parts)]


def _create_case(data: dict[str, Any]) -> list[str]:
    parts = ["CASE"]
    for key in ("case_id", "title", "status"):
        _add(parts, key, data.get(key))
    return [" ".join(parts)]


def _generic_data(data: dict[str, Any]) -> list[str]:
    # Non-evidence tools are already bounded; retain scalar status fields only.
    parts = ["RESULT"]
    for key, value in sorted(data.items()):
        if isinstance(value, (str, int, float, bool)) or value is None:
            _add(parts, key, value, limit=500)
    return [" ".join(parts)]


def _add(parts: list[str], key: str, value: Any, *, limit: int = 160) -> None:
    text = _text(value)
    if text:
        parts.append(f"{key}={_value(_compact_text(text, limit))}")


def _add_refs(parts: list[str], value: Any) -> None:
    refs = _dicts(value)
    if not refs:
        return
    rendered = sorted({_ref(ref) for ref in refs})
    parts.append("refs=" + ";".join(rendered))


def _ref(ref: dict[str, Any]) -> str:
    key = _ref_key(ref)
    label = _REF_LABELS.get().get(key)
    if label:
        event_id = _text(ref.get("event_id"))
        return f"{label}:{event_id}" if event_id else label
    parts = [f"artifact:{_text(ref.get('artifact_id'), '?')}"]
    _append_ref(parts, "event", ref.get("event_id"))
    _append_ref(parts, "locator", ref.get("locator"))
    _append_ref(parts, "sha256", ref.get("sha256"))
    return "|".join(parts)


def _provenance_catalog(data: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for ref in _walk_evidence_refs(data):
        groups.setdefault(
            (_text(ref.get("artifact_id"), "?"), _text(ref.get("sha256"))),
            [],
        ).append(ref)
    ordered_groups = sorted(groups.items(), key=lambda item: item[0])
    labels: dict[str, str] = {}
    for index, (_, refs) in enumerate(ordered_groups, start=1):
        for ref in refs:
            labels[_ref_key(ref)] = f"R{index}"
    lines: list[str] = []
    for index, ((artifact_id, sha256), refs) in enumerate(ordered_groups, start=1):
        parts = ["PROVENANCE", f"R{index}"]
        _add(parts, "artifact", artifact_id)
        _add(parts, "sha256", sha256, limit=128)
        locations = sorted(
            {
                f"{_text(ref.get('event_id'), '?')}@{_value(_compact_text(_text(ref.get('locator'), '?'), 240))}"
                for ref in refs
            }
        )
        if locations:
            parts.append("event_locators=" + ";".join(locations))
        lines.append(" ".join(parts))
    return labels, lines


def _walk_evidence_refs(value: Any) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    if isinstance(value, dict):
        candidate = value.get("evidence_refs")
        if isinstance(candidate, list):
            refs.extend(_dicts(candidate))
        for item in value.values():
            refs.extend(_walk_evidence_refs(item))
    elif isinstance(value, list):
        for item in value:
            refs.extend(_walk_evidence_refs(item))
    return refs


def _ref_key(ref: dict[str, Any]) -> str:
    return "\x1f".join(
        _text(ref.get(key))
        for key in ("artifact_id", "event_id", "locator", "sha256")
    )


def _append_ref(parts: list[str], key: str, value: Any) -> None:
    text = _text(value)
    if text:
        parts.append(f"{key}:{_value(text)}")


def _event_order(event: dict[str, Any]) -> tuple[str, str]:
    return (
        _text(event.get("timestamp_utc", event.get("timestamp"))),
        _text(event.get("event_id")),
    )


def _count(data: dict[str, Any], values: list[dict[str, Any]], key: str = "count") -> str:
    value = data.get(key)
    return _text(value, str(len(values)))


def _dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _strings(value: Any) -> list[str]:
    return [_text(item) for item in value if _text(item)] if isinstance(value, list) else []


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _compact_text(value: str, limit: int) -> str:
    text = " ".join(value.split())
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def _value(value: Any) -> str:
    text = _text(value, "-")
    return '"' + text.replace('"', "'") + '"' if any(char.isspace() for char in text) else text
