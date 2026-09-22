from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
import time
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    token: str | None = None
    code: str | None = None
    message: str | None = None


class PersistentToolGuard:
    """
    Process-independent anti-loop guard for llama.cpp MCP.

    llama.cpp may respawn stdio MCP servers between calls, so this
    guard stores short-lived call state in SQLite instead of memory.
    It is deliberately a rolling-window safeguard, not a claim of
    exact conversational turn identity.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        window_seconds: int = 60,
        max_calls_per_window: int = 20,
        duplicate_seconds: int = 10,
    ) -> None:
        if window_seconds < 1:
            raise ValueError("window_seconds must be positive")
        if max_calls_per_window < 1:
            raise ValueError("max_calls_per_window must be positive")
        if duplicate_seconds < 1:
            raise ValueError("duplicate_seconds must be positive")

        self.db_path = Path(db_path)
        self.window_seconds = window_seconds
        self.max_calls_per_window = max_calls_per_window
        self.duplicate_seconds = duplicate_seconds
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.db_path, timeout=5.0)
        db.execute("PRAGMA busy_timeout = 5000")
        return db

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS tool_calls (
                    token TEXT PRIMARY KEY,
                    scope TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    args_sha256 TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    status TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tool_calls_scope_time
                ON tool_calls(scope, started_at);

                CREATE INDEX IF NOT EXISTS idx_tool_calls_duplicate
                ON tool_calls(scope, tool_name, args_sha256, started_at);
                """
            )

    @staticmethod
    def _args_hash(tool_name: str, arguments: dict[str, Any]) -> str:
        encoded = json.dumps(
            {"tool": tool_name, "arguments": arguments},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _scope(arguments: dict[str, Any]) -> str:
        case_id = arguments.get("case_id")
        if isinstance(case_id, str) and case_id.strip():
            return f"case:{case_id.strip()}"
        return "global"

    def before_call(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        now: float | None = None,
    ) -> GuardDecision:
        current = time.time() if now is None else float(now)
        window_start = current - self.window_seconds
        duplicate_start = current - self.duplicate_seconds
        scope = self._scope(arguments)
        args_hash = self._args_hash(tool_name, arguments)

        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")

            db.execute(
                "DELETE FROM tool_calls WHERE started_at < ?",
                (window_start,),
            )

            total = db.execute(
                """
                SELECT COUNT(*)
                FROM tool_calls
                WHERE scope = ?
                  AND started_at >= ?
                """,
                (scope, window_start),
            ).fetchone()[0]

            if total >= self.max_calls_per_window:
                db.commit()
                return GuardDecision(
                    allowed=False,
                    code="rate_limited",
                    message=(
                        "Cyber tool call rate exceeded the safety window. "
                        "Stop the tool loop and summarize existing evidence."
                    ),
                )

            duplicate = db.execute(
                """
                SELECT 1
                FROM tool_calls
                WHERE scope = ?
                  AND tool_name = ?
                  AND args_sha256 = ?
                  AND started_at >= ?
                  AND status = 'ok'
                LIMIT 1
                """,
                (
                    scope,
                    tool_name,
                    args_hash,
                    duplicate_start,
                ),
            ).fetchone()

            if duplicate is not None:
                db.commit()
                return GuardDecision(
                    allowed=False,
                    code="duplicate_call",
                    message=(
                        "The same successful cyber tool call was made recently. "
                        "Reuse the previous result or change the query."
                    ),
                )

            token = f"guard-{uuid4()}"

            db.execute(
                """
                INSERT INTO tool_calls (
                    token,
                    scope,
                    tool_name,
                    args_sha256,
                    started_at,
                    status
                )
                VALUES (?, ?, ?, ?, ?, 'started')
                """,
                (
                    token,
                    scope,
                    tool_name,
                    args_hash,
                    current,
                ),
            )

            db.commit()
            return GuardDecision(
                allowed=True,
                token=token,
            )

        except Exception:
            db.rollback()
            raise

        finally:
            db.close()

    def finish_call(
        self,
        token: str,
        *,
        ok: bool,
    ) -> None:
        with self._connect() as db:
            db.execute(
                """
                UPDATE tool_calls
                SET status = ?
                WHERE token = ?
                """,
                (
                    "ok" if ok else "error",
                    token,
                ),
            )
