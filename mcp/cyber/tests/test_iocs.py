from cybercopilot.iocs import extract_iocs
from cybercopilot.schemas import EvidenceRef


def test_extract_iocs_deduplicates_and_normalizes():
    payload = {
        "msg": "Connect to https://Example.COM/a and 8.8.8.8; hash " + "A" * 64,
        "again": "example.com"
    }
    items = extract_iocs(case_id="case-1", payload=payload)
    values = {(x.type, x.normalized_value) for x in items}
    assert ("url", "https://example.com/a") in values
    assert ("domain", "example.com") in values
    assert ("ipv4", "8.8.8.8") in values
    assert ("sha256", "a" * 64) in values


def test_private_ip_can_be_excluded():
    items = extract_iocs(case_id="case-1", payload="10.0.0.5 8.8.8.8", include_private_ips=False)
    values = {x.normalized_value for x in items}
    assert "10.0.0.5" not in values
    assert "8.8.8.8" in values


def test_observable_id_is_deterministic():
    ref = EvidenceRef(artifact_id="art-1", event_id="evt-1", locator="Sysmon Event ID 1 / Record 10", sha256="a" * 64)
    first = extract_iocs(case_id="case-1", payload="Connect to 8.8.8.8", evidence_ref=ref)
    second = extract_iocs(case_id="case-1", payload="Connect to 8.8.8.8", evidence_ref=ref)
    assert first[0].observable_id == second[0].observable_id
