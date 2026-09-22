import json

import pytest

from cybercopilot.policy import ToolPolicy
from cybercopilot.tool_runtime import (
    ApprovalRequiredError,
    ToolBudgetExceededError,
    ToolLoopError,
    ToolRuntime,
)


def test_duplicate_call_is_blocked_without_reexecution():
    calls = []

    def handler(*, value):
        calls.append(value)
        return {"value": value}

    runtime = ToolRuntime(
        allowed_tools={"demo"},
    )

    first = runtime.invoke(
        turn_id="turn-1",
        tool_name="demo",
        arguments={"value": 7},
        handler=handler,
    )

    second = runtime.invoke(
        turn_id="turn-1",
        tool_name="demo",
        arguments={"value": 7},
        handler=handler,
    )

    assert first["ok"] is True
    assert second["ok"] is False
    assert second["code"] == "duplicate_call"
    assert calls == [7]


def test_identical_loop_hits_hard_stop():
    runtime = ToolRuntime(
        allowed_tools={"demo"},
    )

    runtime.invoke(
        turn_id="turn-1",
        tool_name="demo",
        arguments={"value": 1},
        handler=lambda **_: {},
    )

    runtime.invoke(
        turn_id="turn-1",
        tool_name="demo",
        arguments={"value": 1},
        handler=lambda **_: {},
    )

    with pytest.raises(ToolLoopError):
        runtime.invoke(
            turn_id="turn-1",
            tool_name="demo",
            arguments={"value": 1},
            handler=lambda **_: {},
        )


def test_total_turn_budget_is_enforced():
    policy = ToolPolicy(
        max_tool_calls_per_turn=2,
        max_identical_calls_per_turn=2,
    )

    runtime = ToolRuntime(
        allowed_tools={"demo"},
        policy=policy,
    )

    for value in (1, 2):
        result = runtime.invoke(
            turn_id="turn-1",
            tool_name="demo",
            arguments={"value": value},
            handler=lambda **kwargs: kwargs,
        )

        assert result["ok"] is True

    with pytest.raises(ToolBudgetExceededError):
        runtime.invoke(
            turn_id="turn-1",
            tool_name="demo",
            arguments={"value": 3},
            handler=lambda **kwargs: kwargs,
        )


def test_approval_is_out_of_band():
    runtime = ToolRuntime(
        allowed_tools={"dangerous_demo"},
    )

    with pytest.raises(ApprovalRequiredError):
        runtime.invoke(
            turn_id="turn-1",
            tool_name="dangerous_demo",
            arguments={},
            handler=lambda: {},
            requires_approval=True,
            approved=False,
        )


def test_audit_log_hashes_args_without_logging_content(
    tmp_path,
):
    audit = tmp_path / "audit.jsonl"

    runtime = ToolRuntime(
        allowed_tools={"demo"},
        audit_path=audit,
    )

    result = runtime.invoke(
        turn_id="turn-1",
        tool_name="demo",
        arguments={"secret": "NEVER-LOG-THIS"},
        handler=lambda **_: {"ok": True},
    )

    assert result["ok"] is True

    text = audit.read_text(
        encoding="utf-8"
    )

    assert "NEVER-LOG-THIS" not in text

    record = json.loads(
        text.splitlines()[0]
    )

    assert record["tool"] == "demo"
    assert record["status"] == "ok"
    assert len(record["args_sha256"]) == 64
