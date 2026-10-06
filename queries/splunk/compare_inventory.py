"""Check actual imported rows and original indexed _time against a transport file."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys


TEXT_FIELDS = ("timestamp", "target_domain", "target_user", "source_ip", "destination_host", "data_origin")
INT_FIELDS = ("event_id", "logon_type", "timestamp_epoch_us")


def integer(value):
    if type(value) is int:
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    raise ValueError(f"expected integer or decimal integer string: {value!r}")


def compare(normalized, imported):
    if not isinstance(imported, list):
        raise ValueError("inventory export must be a JSON array of result objects")
    expected = {}
    for event in normalized:
        uid = event["event_uid"]
        if uid in expected:
            raise ValueError(f"duplicate transport UID: {uid}")
        expected[uid] = event
    actual = {}
    for event in imported:
        uid = event["event_uid"]
        if uid in actual:
            raise ValueError(f"duplicate imported UID: {uid}")
        actual[uid] = event
    missing, extra = sorted(set(expected) - set(actual)), sorted(set(actual) - set(expected))
    if missing or extra:
        raise ValueError(f"import inventory mismatch: missing={missing}, unexpected={extra}")
    for uid, event in expected.items():
        row = actual[uid]
        for name in TEXT_FIELDS:
            if row.get(name) != event[name]:
                raise ValueError(f"{uid}: {name} differs")
        for name in INT_FIELDS:
            if integer(row.get(name)) != event[name]:
                raise ValueError(f"{uid}: {name} differs")
        for name in ("record_id", "timestamp_raw"):
            if name in event:
                value = integer(row.get(name)) if name == "record_id" else row.get(name)
                if value != event[name]:
                    raise ValueError(f"{uid}: {name} differs")
            elif row.get(name) not in (None, ""):
                raise ValueError(f"{uid}: unexpected {name}")
        stamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
        stamp_us = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
        if stamp_us != event["timestamp_epoch_us"]:
            raise ValueError(f"{uid}: timestamp and transport epoch differ")
        for name in ("indexed_time_us", "parsed_time_us"):
            if integer(row.get(name)) != stamp_us:
                raise ValueError(f"{uid}: {name} differs from timestamp; check index-time parsing")
    return len(expected)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--normalized", type=Path, required=True)
    parser.add_argument("--splunk-results", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        rows = [json.loads(line) for line in args.normalized.read_text(encoding="utf-8").splitlines()]
        exported = json.loads(args.splunk_results.read_text(encoding="utf-8"))
        count = compare(rows, exported)
    except (OSError, ValueError, TypeError, KeyError, OverflowError) as exc:
        print(f"Inventory comparison failed: {exc}", file=sys.stderr)
        return 1
    print(f"Matched {count} imported events including indexed _time, parsed timestamp, keys and native metadata.")
    print("This checks supplied exports; it does not establish an executed Splunk search.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
