from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cybercopilot.schemas import EventRecord


MAX_QUERY_RESULTS = 1000
DEFAULT_QUERY_RESULTS = 200


def _require_aware(
    value: datetime | None,
    name: str,
) -> None:
    if value is None:
        return

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(
            f"{name} must be timezone-aware"
        )


def _nested_field(
    event: EventRecord,
    path: str,
) -> Any:
    current: Any = event.fields

    for component in path.split("."):
        if not isinstance(current, dict):
            return None

        if component not in current:
            return None

        current = current[component]

    return current


def query_events(
    events: list[EventRecord],
    *,
    case_id: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    hosts: set[str] | None = None,
    users: set[str] | None = None,
    event_codes: set[str] | None = None,
    categories: set[str] | None = None,
    actions: set[str] | None = None,
    field_equals: dict[str, Any] | None = None,
    limit: int = DEFAULT_QUERY_RESULTS,
) -> list[EventRecord]:
    """
    Deterministically filter normalized events.

    No SQL, regex, Python expressions, or model-generated
    executable query language is accepted.
    """

    if limit < 1 or limit > MAX_QUERY_RESULTS:
        raise ValueError(
            f"limit must be between 1 "
            f"and {MAX_QUERY_RESULTS}"
        )

    _require_aware(start, "start")
    _require_aware(end, "end")

    if (
        start is not None
        and end is not None
        and start > end
    ):
        raise ValueError(
            "start must be earlier than or equal to end"
        )

    matches: list[EventRecord] = []

    for event in events:
        if (
            case_id is not None
            and event.case_id != case_id
        ):
            continue

        timestamp = event.timestamp

        if start is not None and timestamp < start:
            continue

        if end is not None and timestamp > end:
            continue

        if hosts is not None and event.host not in hosts:
            continue

        if users is not None and event.user not in users:
            continue

        if (
            event_codes is not None
            and event.event_code not in event_codes
        ):
            continue

        if (
            categories is not None
            and event.category not in categories
        ):
            continue

        if (
            actions is not None
            and event.action not in actions
        ):
            continue

        if field_equals:
            failed = False

            for path, expected in field_equals.items():
                actual = _nested_field(
                    event,
                    path,
                )

                if actual != expected:
                    failed = True
                    break

            if failed:
                continue

        matches.append(event)

    matches.sort(
        key=lambda event: (
            event.timestamp.astimezone(timezone.utc),
            event.event_id,
        )
    )

    return matches[:limit]