from cybercopilot import mcp_stdio


def test_mcp_result_sends_compact_text_without_mutating_raw_payload():
    payload = {
        "ok": True,
        "tool": "query_events",
        "call_id": "call-1",
        "data": {
            "count": 1,
            "events": [{
                "event_id": "evt-1",
                "timestamp": "2026-09-18T13:50:00+00:00",
                "host": "LAB-WS05",
                "event_code": "1",
                "fields": {"event_data": {"ProcessId": "7000"}},
                "evidence_refs": [],
            }],
        },
    }

    result = mcp_stdio._tool_result(payload)
    text = result["content"][0]["text"]

    assert text.startswith("TOOL query_events ok")
    assert "EVENT id=evt-1" in text
    assert payload["data"]["events"][0]["fields"]["event_data"]["ProcessId"] == "7000"
