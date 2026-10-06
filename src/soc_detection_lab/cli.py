"""Offline CLI. Exit 0: completed; 2: input/usage error; 3: expectation mismatch."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from .engine import (Config, InputError, MAX_BYTES, MAX_EVENTS, analyze_loaded,
                     candidate_alert_id, canonical, event_content, load_file, parse_time)
from .reporting import markdown, write_json, write_text


def parser():
    cli = argparse.ArgumentParser(description="Analyze normalized lab logons offline; no automatic response actions.")
    commands = cli.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate", help="write a deterministic synthetic demo")
    generate.add_argument("--output", type=Path, required=True)
    generate.add_argument("--seed", type=int, default=42)
    inspect_xml = commands.add_parser("inspect-windows-xml", help="read native XML fields and report compatibility; no normalization")
    inspect_xml.add_argument("--input", type=Path, required=True)
    inspect_xml.add_argument("--max-bytes", type=int, default=MAX_BYTES)
    inspect_xml.add_argument("--max-events", type=int, default=MAX_EVENTS)
    adapt_xml = commands.add_parser("adapt-windows-xml", help="convert eligible Windows XML with raw times and record IDs")
    adapt_xml.add_argument("--input", type=Path, required=True)
    adapt_xml.add_argument("--output", type=Path, required=True)
    adapt_xml.add_argument("--data-origin", choices=("synthetic", "lab-captured"), required=True)
    adapt_xml.add_argument("--max-bytes", type=int, default=MAX_BYTES)
    adapt_xml.add_argument("--max-events", type=int, default=MAX_EVENTS)
    for command in ("validate", "analyze", "evaluate"):
        sub = commands.add_parser(command)
        sub.add_argument("--input", type=Path, required=True)
        sub.add_argument("--skip-invalid", action="store_true", help="report and skip structurally invalid records; UID conflicts still abort")
        sub.add_argument("--max-bytes", type=int, default=MAX_BYTES)
        sub.add_argument("--max-events", type=int, default=MAX_EVENTS)
        if command != "validate":
            sub.add_argument("--threshold", type=int, default=5)
            sub.add_argument("--window-seconds", type=int, default=300)
            sub.add_argument("--logon-types", type=int, nargs="+", default=[3, 10])
        if command == "analyze":
            sub.add_argument("--output", type=Path, required=True)
        if command == "evaluate":
            sub.add_argument("--expected", type=Path, required=True)
    return cli


def evaluate(result, expected_path):
    try:
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InputError(f"cannot read expectations: {exc}") from exc
    if not isinstance(expected, dict) or not isinstance(expected.get("expected_alerts"), list):
        raise InputError("expectations require an expected_alerts array")
    by_uid = {alert["success"]["event_uid"]: alert for alert in result["alerts"]}
    mismatches = []
    seen = set()
    for item in expected["expected_alerts"]:
        if (not isinstance(item, dict) or not isinstance(item.get("success_uid"), str)
                or not isinstance(item.get("failure_uids"), list)
                or not all(isinstance(uid, str) for uid in item["failure_uids"])
                or not isinstance(item.get("key"), dict)):
            raise InputError("each expectation requires success_uid, failure_uids and key")
        uid = item["success_uid"]
        if uid in seen or len(set(item["failure_uids"])) != len(item["failure_uids"]):
            raise InputError("expectations contain duplicate identities")
        seen.add(uid)
        actual = by_uid.get(uid)
        if actual is None:
            mismatches.append({"success_uid": uid, "reason": "expected alert missing"})
            continue
        if sorted(item["failure_uids"]) != sorted(f["event_uid"] for f in actual["failures"]):
            mismatches.append({"success_uid": uid, "reason": "failure evidence differs"})
        if item["key"] != actual["key"]:
            mismatches.append({"success_uid": uid, "reason": "correlation key differs"})
        if "success_timestamp" in item and item["success_timestamp"] != actual["success"]["timestamp"]:
            mismatches.append({"success_uid": uid, "reason": "success time differs"})
        if "failure_timestamps" in item:
            actual_times = {f["event_uid"]: f["timestamp"] for f in actual["failures"]}
            if item["failure_timestamps"] != actual_times:
                mismatches.append({"success_uid": uid, "reason": "failure times differ"})
    for uid in sorted(set(by_uid) - seen):
        mismatches.append({"success_uid": uid, "reason": "unexpected alert"})
    return {"matched": not mismatches, "expected_alert_count": len(seen),
            "actual_alert_count": len(by_uid), "mismatches": mismatches,
            "scope": "technical rule correctness on this finite dataset, not attack detection performance",
            "input": result["input"], "counts": result["counts"], "issues": result["issues"]}


def export_splunk(events, config):
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    for event in events:
        projected = event_content(event)
        delta = parse_time(event["timestamp"]) - epoch
        projected["timestamp_epoch_us"] = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
        projected["candidate_alert_id"] = None
        if event["event_id"] == 4624:
            projected["candidate_alert_id"] = candidate_alert_id(event, config)
        yield projected


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "generate":
            from .generate import generate
            output = generate(args.output, args.seed)
            print(json.dumps(output, indent=2))
            return 0
        if args.command == "inspect-windows-xml":
            from .windows_xml import inspect_windows_xml
            inspected = inspect_windows_xml(args.input, max_bytes=args.max_bytes, max_events=args.max_events)
            print(json.dumps(inspected, indent=2))
            return 0
        if args.command == "adapt-windows-xml":
            from .windows_adapter import adapt_windows_xml
            paths = {name: args.output / name for name in ("events.jsonl", "adapter-result.json")}
            if args.input.resolve() in {path.resolve() for path in paths.values()}:
                raise InputError("output would overwrite the input file; choose another output directory")
            adapted = adapt_windows_xml(args.input, data_origin=args.data_origin,
                                       max_bytes=args.max_bytes, max_events=args.max_events)
            write_text(paths["events.jsonl"], "".join(canonical(event) + "\n" for event in adapted["events"]))
            write_json(paths["adapter-result.json"], adapted)
            print(json.dumps({"counts": adapted["counts"],
                              "artifacts": {name: str(path) for name, path in paths.items()}}, indent=2))
            return 0
        config = Config(args.threshold, args.window_seconds, tuple(args.logon_types)) if args.command != "validate" else None
        loaded = load_file(args.input, skip_invalid=args.skip_invalid,
                           max_bytes=args.max_bytes, max_events=args.max_events)
        if args.command == "validate":
            print(json.dumps(loaded.summary(), indent=2))
            return 0
        result = analyze_loaded(loaded, config)
        if args.command == "evaluate":
            evaluation = evaluate(result, args.expected)
            print(json.dumps(evaluation, indent=2))
            return 0 if evaluation["matched"] else 3
        paths = {name: args.output / name for name in ("results.json", "report.md", "normalized.jsonl", "splunk-import.jsonl")}
        if args.input.resolve() in {path.resolve() for path in paths.values()}:
            raise InputError("output would overwrite the input file; choose another output directory")
        write_json(paths["results.json"], result)
        write_text(paths["report.md"], markdown(result))
        write_text(paths["normalized.jsonl"], "".join(canonical(event_content(event)) + "\n" for event in loaded.events))
        write_text(paths["splunk-import.jsonl"], "".join(canonical(event) + "\n" for event in export_splunk(loaded.events, config)))
        print(json.dumps({"alert_count": len(result["alerts"]), "counts": result["counts"],
                          "artifacts": {name: str(path) for name, path in paths.items()}}, indent=2))
        return 0
    except (InputError, ValueError, OSError) as exc:
        detail = {"error": str(exc)}
        if isinstance(exc, InputError) and exc.result:
            detail.update(exc.result)
        print(json.dumps(detail, indent=2), file=sys.stderr)
        return 2
