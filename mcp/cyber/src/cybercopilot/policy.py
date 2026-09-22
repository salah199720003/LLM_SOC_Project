from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolPolicy:
    read_only_default: bool = True
    max_tool_calls_per_turn: int = 12
    max_identical_calls_per_turn: int = 2
    default_timeout_seconds: int = 30
    require_approval_for_write: bool = True
    require_approval_for_process_execution: bool = True
    allow_network_by_default: bool = False


DEFAULT_POLICY = ToolPolicy()
