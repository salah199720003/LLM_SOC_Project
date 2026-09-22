from datetime import datetime

import pytest
from pydantic import ValidationError

from cybercopilot.schemas import EventRecord


def test_event_rejects_naive_timestamp():
    with pytest.raises(ValidationError):
        EventRecord(
            case_id="case-1",
            timestamp=datetime(2026, 1, 1, 12, 0),
            timestamp_source="event.system_time",
            source_type="sysmon",
            source_name="fixture",
        )
