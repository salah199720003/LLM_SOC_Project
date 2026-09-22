from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any
from uuid import uuid4

from cybercopilot.mcp_adapter import CyberMCPAdapter
from cybercopilot.model_context import compact_tool_result
from cybercopilot.persistent_guard import PersistentToolGuard
from cybercopilot.tool_service import CyberToolService


STARTER_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = STARTER_ROOT.parent
DATA_DIR = PROJECT_ROOT / "data" / "cases"
LOG_DIR = PROJECT_ROOT / "logs"


service = CyberToolService(
    project_root=PROJECT_ROOT,
    db_path=DATA_DIR / "cybercopilot.sqlite3",
)

adapter = CyberMCPAdapter(
    service=service,
    audit_path=LOG_DIR / "cyber-tools-audit.jsonl",
)

guard = PersistentToolGuard(
    DATA_DIR / "cyber-tool-guard.sqlite3",
    window_seconds=60,
    max_calls_per_window=20,
    duplicate_seconds=10,
)


def _send(value: dict[str, Any]) -> None:
    sys.stdout.write(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    )
    sys.stdout.flush()


def _error(
    message_id: Any,
    code: int,
    message: str,
) -> None:
    _send(
        {
            "jsonrpc": "2.0",
            "id": message_id,
            "error": {
                "code": code,
                "message": message,
            },
        }
    )


def _tool_result(
    payload: dict[str, Any],
) -> dict[str, Any]:
    # Keep ``payload`` intact for the runtime and case-backed evidence.  Only
    # the MCP text returned to a model is compacted, preventing large raw tool
    # payloads from being replayed on every agent-loop turn.
    return {
        "isError": not bool(payload.get("ok")),
        "content": [
            {
                "type": "text",
                "text": compact_tool_result(payload),
            }
        ],
    }


def _call_tool(
    params: dict[str, Any],
) -> dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments", {})

    if not isinstance(name, str) or not name:
        return _tool_result(
            {
                "ok": False,
                "code": "invalid_tool_name",
                "message": (
                    "Tool name must be a non-empty string."
                ),
            }
        )

    if not isinstance(arguments, dict):
        return _tool_result(
            {
                "ok": False,
                "tool": name,
                "code": "invalid_arguments",
                "message": (
                    "Tool arguments must be a JSON object."
                ),
            }
        )

    decision = guard.before_call(
        tool_name=name,
        arguments=arguments,
    )

    if not decision.allowed:
        return _tool_result(
            {
                "ok": False,
                "tool": name,
                "code": decision.code,
                "message": decision.message,
            }
        )

    assert decision.token is not None

    # llama.cpp tools/call does not provide a trusted conversation-turn
    # identifier. This UUID is only an invocation identity for the
    # in-process adapter. Cross-process loop protection is provided by
    # PersistentToolGuard above.
    invocation_id = f"mcp-{uuid4()}"

    try:
        result = adapter.call_tool(
            turn_id=invocation_id,
            name=name,
            arguments=arguments,
        )

    except Exception as exc:
        guard.finish_call(
            decision.token,
            ok=False,
        )

        return _tool_result(
            {
                "ok": False,
                "tool": name,
                "code": "mcp_server_error",
                "error_type": type(exc).__name__,
                "message": str(exc)[:500],
            }
        )

    guard.finish_call(
        decision.token,
        ok=bool(result.get("ok")),
    )

    return _tool_result(result)


def handle_message(
    message: dict[str, Any],
) -> dict[str, Any] | None:
    if not isinstance(message, dict):
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": -32600,
                "message": "Invalid request",
            },
        }

    message_id = message.get("id")
    method = message.get("method")

    if method == "notifications/initialized":
        return None

    if message_id is None:
        return None

    if method == "initialize":
        params = message.get("params")
        requested_version = (
            params.get("protocolVersion")
            if isinstance(params, dict)
            else None
        )

        return {
            "jsonrpc": "2.0",
            "id": message_id,
            "result": {
                "protocolVersion": (
                    requested_version
                    or "2024-11-05"
                ),
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "local-assistant-cyber",
                    "version": "0.3.0",
                },
                "instructions": (
                    "SOC evidence discipline: use one bounded query_events call and "
                    "reuse its event IDs/results; correlate_activity is authoritative "
                    "for process/activity links; do not build_timeline when queried "
                    "events already provide the equivalent chronology unless explicitly "
                    "asked. Treat .docm involvement as a file association, not macro "
                    "execution; Invoke-WebRequest plus TCP does not prove a download or "
                    "HTTP success; port 443 does not prove HTTPS success; and do not claim "
                    "script execution without execution telemetry. Label PID/time links "
                    "weaker than ProcessGuid links. Include ATT&CK only when direct "
                    "telemetry supports it. Keep reports 500-800 tokens with: Observed "
                    "Facts, Correlation, Hypotheses/Unknowns, ATT&CK (if supported), "
                    "Assessment, Next Steps. Do not inflate IOC counts or mislabel types."
                ),
            },
        }

    if method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": message_id,
            "result": {},
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": message_id,
            "result": {
                "tools": adapter.list_tools(),
            },
        }

    if method == "tools/call":
        params = message.get("params")

        if not isinstance(params, dict):
            return {
                "jsonrpc": "2.0",
                "id": message_id,
                "result": _tool_result(
                    {
                        "ok": False,
                        "code": "invalid_params",
                        "message": (
                            "tools/call params must be an object."
                        ),
                    }
                ),
            }

        return {
            "jsonrpc": "2.0",
            "id": message_id,
            "result": _call_tool(params),
        }

    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {
            "code": -32601,
            "message": "Unknown method or tool",
        },
    }


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue

        try:
            message = json.loads(line)

        except json.JSONDecodeError:
            _error(
                None,
                -32700,
                "Invalid JSON",
            )
            continue

        response = handle_message(message)

        if response is not None:
            _send(response)


if __name__ == "__main__":
    main()
