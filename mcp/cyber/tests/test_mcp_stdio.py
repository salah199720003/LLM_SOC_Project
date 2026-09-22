from cybercopilot import mcp_stdio


def test_initialize_and_list_tools():
    initialized = mcp_stdio.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18"
            },
        }
    )

    assert (
        initialized["result"]["protocolVersion"]
        == "2025-06-18"
    )

    listed = mcp_stdio.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
        }
    )

    names = {
        tool["name"]
        for tool in listed["result"]["tools"]
    }

    assert "query_events" in names
    assert "ingest_evidence" in names


def test_initialized_notification_has_no_response():
    assert (
        mcp_stdio.handle_message(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            }
        )
        is None
    )
