import pytest

from cybercopilot.sigma_tools import (
    test_sigma_rule,
    validate_sigma_rule,
)


RULE = r"""
title: PowerShell Web Request
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: 'Invoke-WebRequest'
    condition: selection
level: medium
"""


def make_event(event_id: str, image: str, command_line: str) -> dict:
    return {
        "event_id": event_id,
        "fields": {
            "event_data": {
                "Image": image,
                "CommandLine": command_line,
            }
        },
    }


def test_validate_sigma_rule():
    result = validate_sigma_rule(RULE)
    assert result["valid"] is True
    assert result["title"] == "PowerShell Web Request"


def test_sigma_fixture_matching():
    events = [
        make_event(
            "evt-positive",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoProfile -Command Invoke-WebRequest https://example.com/a",
        ),
        make_event(
            "evt-benign",
            r"C:\Windows\System32\notepad.exe",
            "notepad.exe notes.txt",
        ),
    ]

    result = test_sigma_rule(
        RULE,
        events=events,
        expected_match_event_ids=["evt-positive"],
    )

    assert result["test_supported"] is True
    assert result["matched_event_ids"] == ["evt-positive"]
    assert result["expectation"]["passed"] is True


def test_unsupported_modifier_fails_closed():
    rule = RULE.replace(
        "CommandLine|contains:",
        "CommandLine|re:",
    )
    event = make_event(
        "evt-1",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe Invoke-WebRequest",
    )

    result = test_sigma_rule(rule, events=[event])
    assert result["valid"] is True
    assert result["test_supported"] is False
    assert "unsupported Sigma modifier" in result["errors"][0]


def test_duplicate_yaml_keys_are_rejected():
    rule = r"""
title: Duplicate Key Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'Invoke-WebRequest'
        CommandLine|contains: 'https://example.com/payload.ps1'
    condition: selection
"""
    result = validate_sigma_rule(rule)
    assert result["valid"] is False
    assert any(
        "duplicate YAML key" in error
        for error in result["errors"]
    )
