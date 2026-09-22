from cybercopilot.mcp_adapter import CyberMCPAdapter
from cybercopilot.policy import ToolPolicy


class FakeService:
    def __init__(self):
        self.calls = []

    def create_case(self, **kwargs):
        self.calls.append(("create_case", kwargs))
        return {"case_id": "case-1"}

    def ingest_evidence(self, **kwargs):
        self.calls.append(("ingest_evidence", kwargs))
        return {"artifact": {"artifact_id": "art-1"}}

    def parse_events(self, **kwargs):
        self.calls.append(("parse_events", kwargs))
        return {"parsed_count": 1}

    def query_events(self, **kwargs):
        self.calls.append(("query_events", kwargs))
        return {"count": 0, "events": []}

    def correlate_activity(self, **kwargs):
        self.calls.append(("correlate_activity", kwargs))
        return {
            "case_id": kwargs["case_id"],
            "process_count": 0,
            "processes": [],
        }

    def extract_iocs(self, **kwargs):
        self.calls.append(("extract_iocs", kwargs))
        return {"count": 0, "observables": []}

    def attack_lookup(self, **kwargs):
        self.calls.append(("attack_lookup", kwargs))
        return {"query": kwargs["query"], "results": []}

    def sigma_validate(self, **kwargs):
        self.calls.append(("sigma_validate", kwargs))
        return {"valid": True, "errors": []}

    def sigma_test(self, **kwargs):
        self.calls.append(("sigma_test", kwargs))
        return {
            "valid": True,
            "test_supported": True,
            "matched_event_ids": [],
        }

    def build_timeline(self, **kwargs):
        self.calls.append(("build_timeline", kwargs))
        return {"count": 0, "timeline": []}


def test_tool_discovery_is_strict():
    adapter = CyberMCPAdapter(service=FakeService())
    tools = adapter.list_tools()
    names = {tool["name"] for tool in tools}

    assert names == {
        "create_case",
        "ingest_evidence",
        "parse_events",
        "query_events",
        "correlate_activity",
        "extract_iocs",
        "build_timeline",
        "sigma_test",
        "sigma_validate",
        "attack_lookup",
    }

    for tool in tools:
        assert tool["inputSchema"]["additionalProperties"] is False


def test_invalid_arguments_never_reach_service():
    service = FakeService()
    adapter = CyberMCPAdapter(service=service)

    result = adapter.call_tool(
        turn_id="turn-1",
        name="query_events",
        arguments={
            "case_id": "case-1",
            "shell_command": "whoami",
        },
    )

    assert result["ok"] is False
    assert result["code"] == "invalid_arguments"
    assert service.calls == []


def test_valid_call_reaches_expected_handler():
    service = FakeService()
    adapter = CyberMCPAdapter(service=service)

    result = adapter.call_tool(
        turn_id="turn-1",
        name="query_events",
        arguments={
            "case_id": "case-1",
            "event_code": "1",
            "limit": 25,
        },
    )

    assert result["ok"] is True
    assert service.calls == [
        (
            "query_events",
            {
                "case_id": "case-1",
                "event_code": "1",
                "limit": 25,
            },
        )
    ]


def test_duplicate_gateway_call_is_blocked():
    service = FakeService()
    adapter = CyberMCPAdapter(service=service)

    args = {
        "case_id": "case-1",
        "limit": 10,
    }

    first = adapter.call_tool(
        turn_id="turn-1",
        name="query_events",
        arguments=args,
    )

    second = adapter.call_tool(
        turn_id="turn-1",
        name="query_events",
        arguments=args,
    )

    assert first["ok"] is True
    assert second["code"] == "duplicate_call"
    assert len(service.calls) == 1


def test_turn_reset_allows_same_call_again():
    service = FakeService()

    adapter = CyberMCPAdapter(
        service=service,
        policy=ToolPolicy(
            max_tool_calls_per_turn=12,
            max_identical_calls_per_turn=2,
        ),
    )

    args = {
        "case_id": "case-1",
        "limit": 10,
    }

    adapter.begin_turn("turn-1")

    first = adapter.call_tool(
        turn_id="turn-1",
        name="query_events",
        arguments=args,
    )

    adapter.end_turn("turn-1")
    adapter.begin_turn("turn-1")

    second = adapter.call_tool(
        turn_id="turn-1",
        name="query_events",
        arguments=args,
    )

    assert first["ok"] is True
    assert second["ok"] is True
    assert len(service.calls) == 2


