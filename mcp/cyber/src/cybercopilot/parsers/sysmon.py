from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import xml.etree.ElementTree as ET

from cybercopilot.schemas import EvidenceRef, EventRecord

_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS = {"e": _EVENT_NS}
_EVENT_MAP: dict[str, tuple[str, str]] = {
    "1": ("process", "process_create"),
    "3": ("network", "network_connect"),
    "11": ("file", "file_create"),
    "22": ("dns", "dns_query"),
}

class SysmonParseError(ValueError):
    """Raised when required Sysmon event fields are missing or malformed."""

def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SysmonParseError(f"invalid SystemTime: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SysmonParseError("SystemTime must include a timezone")
    return parsed

def _event_data(event: ET.Element) -> dict[str, str]:
    data: dict[str, str] = {}
    for node in event.findall("e:EventData/e:Data", _NS):
        name = node.attrib.get("Name")
        if not name:
            continue
        data[name] = node.text or ""
    return data

def _required_text(event: ET.Element, path: str, label: str) -> str:
    value = event.findtext(path, namespaces=_NS)
    if value is None or not value.strip():
        raise SysmonParseError(f"missing required Sysmon field: {label}")
    return value.strip()

def _stable_event_id(*, case_id: str, source_key: str, record_id: str | None, event_code: str, system_time: str) -> str:
    material = "\x1f".join([case_id, source_key, record_id or "", event_code, system_time]).encode("utf-8", errors="strict")
    digest = sha256(material).hexdigest()
    return f"evt-{digest[:24]}"

def parse_sysmon_event(event: ET.Element, *, case_id: str, source_name: str, artifact_id: str | None = None, artifact_sha256: str | None = None) -> EventRecord:
    provider = event.find("e:System/e:Provider", _NS)
    provider_name = provider.attrib.get("Name") if provider is not None else None
    if provider_name != "Microsoft-Windows-Sysmon":
        raise SysmonParseError(f"unexpected provider: {provider_name!r}")
    event_code = _required_text(event, "e:System/e:EventID", "EventID")
    time_node = event.find("e:System/e:TimeCreated", _NS)
    system_time = time_node.attrib.get("SystemTime") if time_node is not None else None
    if not system_time:
        raise SysmonParseError("missing required Sysmon field: TimeCreated/@SystemTime")
    timestamp = _parse_timestamp(system_time)
    host = event.findtext("e:System/e:Computer", namespaces=_NS)
    record_id = event.findtext("e:System/e:EventRecordID", namespaces=_NS)
    channel = event.findtext("e:System/e:Channel", namespaces=_NS)
    data = _event_data(event)
    category, action = _EVENT_MAP.get(event_code, ("sysmon", "event"))
    source_key = artifact_sha256 if artifact_sha256 else source_name
    event_id = _stable_event_id(case_id=case_id, source_key=source_key, record_id=record_id, event_code=event_code, system_time=system_time)
    locator_parts = [f"Sysmon Event ID {event_code}"]
    if record_id:
        locator_parts.append(f"Record {record_id}")
    evidence_ref = EvidenceRef(artifact_id=artifact_id or source_name, event_id=event_id, locator=" / ".join(locator_parts), sha256=artifact_sha256)
    fields = {"system": {"provider": provider_name, "channel": channel, "record_id": record_id, "system_time_raw": system_time}, "event_data": data}
    return EventRecord(event_id=event_id, case_id=case_id, timestamp=timestamp, timestamp_source="System/TimeCreated/@SystemTime", source_type="sysmon", source_name=source_name, host=host.strip() if host else None, user=data.get("User") or None, event_code=event_code, category=category, action=action, fields=fields, evidence_refs=[evidence_ref])

def parse_sysmon_xml(xml_text: str | bytes, *, case_id: str, source_name: str, artifact_id: str | None = None, artifact_sha256: str | None = None) -> list[EventRecord]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise SysmonParseError(f"invalid XML: {exc}") from exc
    if root.tag == f"{{{_EVENT_NS}}}Event":
        events = [root]
    else:
        events = root.findall(".//e:Event", _NS)
    if not events:
        raise SysmonParseError("no Windows Event XML <Event> elements found")
    return [parse_sysmon_event(event, case_id=case_id, source_name=source_name, artifact_id=artifact_id, artifact_sha256=artifact_sha256) for event in events]
