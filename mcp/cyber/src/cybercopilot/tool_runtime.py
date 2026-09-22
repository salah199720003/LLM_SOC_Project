from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import threading
import time
from typing import Any, Callable
from uuid import uuid4

from cybercopilot.policy import DEFAULT_POLICY, ToolPolicy


class ToolRuntimeError(RuntimeError):
    """Base error for deterministic tool runtime controls."""


class UnknownToolError(ToolRuntimeError):
    """Raised when a tool name is not on the explicit allowlist."""


class ToolBudgetExceededError(ToolRuntimeError):
    """Raised when a turn exceeds its maximum tool-call budget."""


class ToolLoopError(ToolRuntimeError):
    """Raised when the same tool call repeats too many times."""


class ApprovalRequiredError(ToolRuntimeError):
    """Raised when a sensitive tool lacks explicit approval."""


@dataclass
class _TurnState:
    total_calls: int = 0
    identical_counts: dict[str, int] = field(default_factory=dict)
    executed_call_hashes: set[str] = field(default_factory=set)


def _canonical_args(arguments: dict[str, Any]) -> str:
    return json.dumps(
        arguments,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _call_hash(tool_name: str, arguments: dict[str, Any]) -> str:
    material = (
        tool_name
        + "\x1f"
        + _canonical_args(arguments)
    ).encode("utf-8")

    return hashlib.sha256(material).hexdigest()


class ToolRuntime:
    """
    Per-turn safety wrapper for deterministic tools.

    The gateway, not the LLM, must supply ``turn_id``.
    Tool arguments never control the turn identity or approval state.
    """

    def __init__(
        self,
        *,
        allowed_tools: set[str],
        policy: ToolPolicy = DEFAULT_POLICY,
        audit_path: str | Path | None = None,
    ) -> None:
        self.allowed_tools = frozenset(allowed_tools)
        self.policy = policy
        self.audit_path = (
            Path(audit_path)
            if audit_path is not None
            else None
        )
        self._turns: dict[str, _TurnState] = {}
        self._lock = threading.RLock()

    def begin_turn(self, turn_id: str) -> None:
        if not turn_id.strip():
            raise ValueError("turn_id must not be empty")

        with self._lock:
            self._turns[turn_id] = _TurnState()

    def end_turn(self, turn_id: str) -> None:
        with self._lock:
            self._turns.pop(turn_id, None)

    def _state(self, turn_id: str) -> _TurnState:
        if not turn_id.strip():
            raise ValueError("turn_id must not be empty")

        with self._lock:
            return self._turns.setdefault(
                turn_id,
                _TurnState(),
            )

    def _audit(
        self,
        *,
        turn_id: str,
        call_id: str,
        tool_name: str,
        args_hash: str,
        status: str,
        duration_ms: float,
        error_type: str | None = None,
    ) -> None:
        if self.audit_path is None:
            return

        record = {
            "timestamp_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "turn_id": turn_id,
            "call_id": call_id,
            "tool": tool_name,
            "args_sha256": args_hash,
            "status": status,
            "duration_ms": round(duration_ms, 3),
            "error_type": error_type,
        }

        self.audit_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        line = json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        with self._lock:
            with self.audit_path.open(
                "a",
                encoding="utf-8",
            ) as handle:
                handle.write(line + "\n")

    def invoke(
        self,
        *,
        turn_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        handler: Callable[..., Any],
        requires_approval: bool = False,
        approved: bool = False,
    ) -> dict[str, Any]:
        if tool_name not in self.allowed_tools:
            raise UnknownToolError(
                f"tool is not allowed: {tool_name}"
            )

        if requires_approval and not approved:
            raise ApprovalRequiredError(
                f"explicit approval required for: {tool_name}"
            )

        call_id = f"call-{uuid4()}"
        args_hash = _call_hash(
            tool_name,
            arguments,
        )
        identity = f"{tool_name}:{args_hash}"

        state = self._state(turn_id)

        with self._lock:
            if (
                state.total_calls
                >= self.policy.max_tool_calls_per_turn
            ):
                raise ToolBudgetExceededError(
                    "maximum tool calls for this turn exceeded"
                )

            state.total_calls += 1

            identical_count = (
                state.identical_counts.get(
                    identity,
                    0,
                )
                + 1
            )

            state.identical_counts[
                identity
            ] = identical_count

            if (
                identical_count
                > self.policy.max_identical_calls_per_turn
            ):
                raise ToolLoopError(
                    "identical tool call repeated too many times"
                )

            if identity in state.executed_call_hashes:
                self._audit(
                    turn_id=turn_id,
                    call_id=call_id,
                    tool_name=tool_name,
                    args_hash=args_hash,
                    status="duplicate_blocked",
                    duration_ms=0.0,
                )

                return {
                    "ok": False,
                    "tool": tool_name,
                    "call_id": call_id,
                    "code": "duplicate_call",
                    "message": (
                        "This identical tool call already ran "
                        "during the current turn. Reuse its "
                        "previous result or change the query."
                    ),
                }

            state.executed_call_hashes.add(
                identity
            )

        started = time.monotonic()

        try:
            result = handler(**arguments)

        except Exception as exc:
            duration_ms = (
                time.monotonic() - started
            ) * 1000

            self._audit(
                turn_id=turn_id,
                call_id=call_id,
                tool_name=tool_name,
                args_hash=args_hash,
                status="error",
                duration_ms=duration_ms,
                error_type=type(exc).__name__,
            )

            return {
                "ok": False,
                "tool": tool_name,
                "call_id": call_id,
                "code": "tool_error",
                "error_type": type(exc).__name__,
                "message": str(exc)[:500],
            }

        duration_ms = (
            time.monotonic() - started
        ) * 1000

        self._audit(
            turn_id=turn_id,
            call_id=call_id,
            tool_name=tool_name,
            args_hash=args_hash,
            status="ok",
            duration_ms=duration_ms,
        )

        return {
            "ok": True,
            "tool": tool_name,
            "call_id": call_id,
            "data": result,
        }
