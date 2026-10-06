"""Compare a future Splunk JSON-array export with Python reference results.

This checks exported evidence. It does not run or validate a Splunk search.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys


KEY_FIELDS = ("target_domain", "target_user", "source_ip", "destination_host", "logon_type")


def epoch_us(value):
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.utcoffset() is None:
        raise ValueError("Python evidence timestamp has no timezone")
    delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def integer(value):
    # Splunk may export numerical fields as strings. Reject fractional values,
    # booleans and scientific notation instead of losing microsecond precision.
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f"expected an integer or decimal integer string: {value!r}")
    if isinstance(value, str) and not value.lstrip("-").isdigit():
        raise ValueError(f"invalid decimal integer: {value!r}")
    return int(value)


def multivalue(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def metadata(record_id, timestamp_raw):
    if record_id is not None:
        record_id = integer(record_id)
        if record_id <= 0:
            raise ValueError("evidence record_id must be positive")
    if timestamp_raw is not None and not isinstance(timestamp_raw, str):
        raise ValueError("evidence timestamp_raw must be a string")
    return {"record_id": record_id, "timestamp_raw": timestamp_raw}


def failure_evidence(value):
    """Decode paired evidence without splitting UIDs or raw timestamps."""
    decoded = {}
    for item in multivalue(value):
        item = json.loads(item) if isinstance(item, str) else item
        if not isinstance(item, dict):
            raise ValueError("failure_evidence must contain JSON objects or object strings")
        uid = item["event_uid"]
        if not isinstance(uid, str) or uid in decoded:
            raise ValueError("invalid or duplicated UID in paired failure evidence")
        decoded[uid] = {
            "time_us": integer(item["timestamp_epoch_us"]),
            **metadata(item.get("record_id"), item.get("timestamp_raw")),
        }
    return decoded


def compare(reference, exported):
    if not isinstance(exported, list):
        raise ValueError("Splunk export must be a JSON array of result objects")
    rule = reference["rule"]
    params = rule["parameters"]
    expected = {}
    for alert in reference["alerts"]:
        uid = alert["success"]["event_uid"]
        if uid in expected:
            raise ValueError(f"duplicate reference success UID: {uid}")
        expected[uid] = {
            "alert_id": alert["alert_id"],
            "key": alert["key"],
            "success_time_us": epoch_us(alert["success"]["timestamp"]),
            "success_metadata": metadata(alert["success"].get("record_id"),
                                         alert["success"].get("timestamp_raw")),
            "failure_count": alert["failure_count"],
            "failures": {item["event_uid"]: {
                "time_us": epoch_us(item["timestamp"]),
                **metadata(item.get("record_id"), item.get("timestamp_raw")),
            } for item in alert["failures"]},
        }
    actual = {}
    for row in exported:
        if row.get("result_status") != "alert":
            raise ValueError("Splunk reported an invalid batch or unexpected result status")
        if row["rule_id"] != rule["id"] or row["rule_version"] != rule["version"]:
            raise ValueError("rule ID/version mismatch")
        if integer(row["threshold"]) != params["threshold"] or integer(row["window_seconds"]) != params["window_seconds"]:
            raise ValueError("threshold/window mismatch")
        if sorted(integer(x) for x in str(row["logon_types"]).split(",")) != params["logon_types"]:
            raise ValueError("logon-type configuration mismatch")
        uid = row["success_uid"]
        if uid in actual:
            raise ValueError(f"duplicate Splunk success UID: {uid}")
        failure_uids = multivalue(row.get("failure_uids"))
        failure_times = [integer(x) for x in multivalue(row.get("failure_times_us"))]
        count = integer(row["failure_count"])
        if len(failure_uids) != count or len(failure_times) != count or len(set(failure_uids)) != count:
            raise ValueError(f"incomplete or duplicated failure evidence for {uid}")
        pairs = dict(zip(failure_uids, failure_times))
        if row.get("failure_evidence") is not None:
            failures = failure_evidence(row["failure_evidence"])
            if {item_uid: item["time_us"] for item_uid, item in failures.items()} != pairs:
                raise ValueError(f"paired failure evidence disagrees with UID/time arrays for {uid}")
        else:
            # Old synthetic exports have no optional native metadata. Retaining
            # them is safe: a native reference will differ and fail comparison.
            failures = {item_uid: {"time_us": time, **metadata(None, None)}
                        for item_uid, time in pairs.items()}
        key = {name: row[name] for name in KEY_FIELDS}
        key["logon_type"] = integer(key["logon_type"])
        actual[uid] = {
            "alert_id": row["alert_id"], "key": key,
            "success_time_us": integer(row["success_time_us"]),
            "success_metadata": metadata(row.get("success_record_id"),
                                         row.get("success_timestamp_raw")),
            "failure_count": count,
            "failures": failures,
        }
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    differing = sorted(uid for uid in set(expected) & set(actual) if expected[uid] != actual[uid])
    if missing or unexpected or differing:
        raise ValueError(f"comparison mismatch: missing={missing}, unexpected={unexpected}, differing={differing}")
    return len(expected)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-results", type=Path, required=True)
    parser.add_argument("--splunk-results", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        reference = json.loads(args.python_results.read_text(encoding="utf-8"))
        exported = json.loads(args.splunk_results.read_text(encoding="utf-8"))
        count = compare(reference, exported)
    except (OSError, ValueError, TypeError, KeyError, OverflowError) as exc:
        print(f"Comparison failed: {exc}", file=sys.stderr)
        return 1
    print(f"Matched {count} alerts including rule parameters, IDs, keys, timestamped evidence and supplied native metadata.")
    print("This compares supplied exports; it does not establish that Splunk was executed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
