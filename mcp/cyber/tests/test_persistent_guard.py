from cybercopilot.persistent_guard import PersistentToolGuard


def test_guard_survives_new_instances(tmp_path):
    db = tmp_path / "guard.sqlite3"

    first = PersistentToolGuard(
        db,
        duplicate_seconds=10,
    )

    decision = first.before_call(
        tool_name="query_events",
        arguments={
            "case_id": "case-1",
            "limit": 10,
        },
        now=100.0,
    )

    assert decision.allowed is True

    first.finish_call(
        decision.token,
        ok=True,
    )

    second = PersistentToolGuard(
        db,
        duplicate_seconds=10,
    )

    duplicate = second.before_call(
        tool_name="query_events",
        arguments={
            "case_id": "case-1",
            "limit": 10,
        },
        now=105.0,
    )

    assert duplicate.allowed is False
    assert duplicate.code == "duplicate_call"


def test_failed_call_can_be_retried(tmp_path):
    guard = PersistentToolGuard(
        tmp_path / "guard.sqlite3"
    )

    first = guard.before_call(
        tool_name="parse_events",
        arguments={
            "case_id": "case-1",
            "artifact_id": "art-1",
        },
        now=100.0,
    )

    guard.finish_call(
        first.token,
        ok=False,
    )

    retry = guard.before_call(
        tool_name="parse_events",
        arguments={
            "case_id": "case-1",
            "artifact_id": "art-1",
        },
        now=101.0,
    )

    assert retry.allowed is True


def test_guard_rate_limit_is_scoped_by_case(
    tmp_path,
):
    guard = PersistentToolGuard(
        tmp_path / "guard.sqlite3",
        max_calls_per_window=2,
        window_seconds=60,
    )

    for index in range(2):
        decision = guard.before_call(
            tool_name="query_events",
            arguments={
                "case_id": "case-1",
                "limit": index + 1,
            },
            now=100.0 + index,
        )

        assert decision.allowed is True

        guard.finish_call(
            decision.token,
            ok=True,
        )

    blocked = guard.before_call(
        tool_name="build_timeline",
        arguments={
            "case_id": "case-1",
            "limit": 10,
        },
        now=103.0,
    )

    assert blocked.allowed is False
    assert blocked.code == "rate_limited"

    other_case = guard.before_call(
        tool_name="build_timeline",
        arguments={
            "case_id": "case-2",
            "limit": 10,
        },
        now=103.0,
    )

    assert other_case.allowed is True
