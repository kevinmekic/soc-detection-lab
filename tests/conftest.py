"""Hand-authored events and small file helpers, independent of the generator."""

import json
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture
def event():
    def make(uid, seconds, event_id=4625, **changes):
        timestamp = datetime(2026, 4, 8, 12, tzinfo=timezone.utc) + timedelta(seconds=seconds)
        return {
            "schema_version": "1.0", "event_uid": uid,
            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
            "event_id": event_id, "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security", "destination_host": "LAB-UNIT-SERVER",
            "target_user": "unit-user", "target_domain": "LAB-UNIT",
            "source_ip": "192.0.2.70", "logon_type": 3,
            "status": "0xC000006D" if event_id == 4625 else None,
            "sub_status": "0xC000006A" if event_id == 4625 else None,
            "data_origin": "synthetic", **changes,
        }
    return make


@pytest.fixture
def write_events(tmp_path):
    def write(events, name="events.jsonl"):
        path = tmp_path / name
        path.write_text("".join(json.dumps(item) + "\n" for item in events), encoding="utf-8")
        return path
    return write
