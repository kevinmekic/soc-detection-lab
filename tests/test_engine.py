import copy
import json
from datetime import datetime
from pathlib import Path

import pytest

from soc_detection_lab.engine import Config, InputError, analyze_file, load_file


def ids(alert):
    return [item["event_uid"] for item in alert["failures"]]


def moment(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def sequence(event, failures=5):
    return [event(f"f{i}", i * 20) for i in range(failures)] + [event("s", 150, 4624)]


def test_five_failures_include_exact_evidence_times_key_and_provenance(event, write_events):
    source = write_events(sequence(event))
    result = analyze_file(source)
    assert len(result["alerts"]) == 1
    alert = result["alerts"][0]
    assert alert["success"]["event_uid"] == "s"
    assert ids(alert) == ["f0", "f1", "f2", "f3", "f4"]
    assert alert["failure_count"] == 5
    assert alert["key"] == {"target_domain": "lab-unit", "target_user": "unit-user",
                            "source_ip": "192.0.2.70", "destination_host": "lab-unit-server",
                            "logon_type": 3}
    assert [moment(item["timestamp"]) for item in alert["failures"]] == [
        moment(event("unused", i * 20)["timestamp"]) for i in range(5)]
    assert moment(alert["pattern_start"]) == moment(event("unused", 0)["timestamp"])
    assert moment(alert["pattern_end"]) == moment(event("unused", 150)["timestamp"])
    assert alert["success"]["provenance"]["line"] == 6
    assert Path(alert["success"]["provenance"]["input_file"]) == source
    assert [item["provenance"]["line"] for item in alert["failures"]] == [1, 2, 3, 4, 5]
    assert alert["priority"] == "medium"
    assert alert["rationale"] and alert["open_questions"]
    assert result["input"]["sha256"] and result["input"]["data_origins"] == ["synthetic"]


@pytest.mark.parametrize("mode", ["four", "no-success", "success-before"])
def test_negative_sequences(mode, event, write_events):
    if mode == "four":
        events = sequence(event, 4)
    elif mode == "no-success":
        events = sequence(event)[:-1]
    else:
        events = [event("s", -1, 4624)] + sequence(event)[:-1]
    assert analyze_file(write_events(events))["alerts"] == []


def test_window_includes_lower_excludes_equal_and_after_success(event, write_events):
    events = [event("lower", 0), event("outside", -0.000001),
              event("a", 10), event("b", 50), event("c", 200), event("d", 299),
              event("equal", 300), event("after", 300.000001), event("s", 300, 4624)]
    alert = analyze_file(write_events(events))["alerts"][0]
    assert ids(alert) == ["lower", "a", "b", "c", "d"]
    assert alert["failure_count"] == 5


@pytest.mark.parametrize("extra_time", [-0.000001, 300, 300.000001])
def test_outside_equal_after_cannot_supply_fifth_failure(extra_time, event, write_events):
    events = [event(f"f{i}", i * 20 + 1) for i in range(4)]
    events += [event("outside", extra_time), event("s", 300, 4624)]
    assert analyze_file(write_events(events))["alerts"] == []


@pytest.mark.parametrize("field,value", [
    ("target_user", "another-user"), ("target_domain", "OTHER"),
    ("source_ip", "192.0.2.71"), ("destination_host", "LAB-OTHER"), ("logon_type", 10),
])
def test_every_key_component_is_separate(field, value, event, write_events):
    events = sequence(event, 4)
    events.append(event("different", 90, **{field: value}))
    assert analyze_file(write_events(events))["alerts"] == []


def test_supported_logon_types_correlate_separately(event, write_events):
    events = sequence(event)
    events += [event(f"remote-f{i}", i * 20, logon_type=10) for i in range(5)]
    events += [event("remote-s", 150, 4624, logon_type=10)]
    alerts = analyze_file(write_events(events))["alerts"]
    assert {item["key"]["logon_type"] for item in alerts} == {3, 10}
    assert {item["success"]["event_uid"] for item in alerts} == {"s", "remote-s"}


def test_previous_success_does_not_reset_and_qualifying_successes_have_distinct_ids(event, write_events):
    events = sequence(event) + [event("early-success", 25, 4624), event("s2", 151, 4624)]
    alerts = analyze_file(write_events(events))["alerts"]
    assert [item["success"]["event_uid"] for item in alerts] == ["s", "s2"]
    assert [ids(item) for item in alerts] == [["f0", "f1", "f2", "f3", "f4"]] * 2
    assert len({item["alert_id"] for item in alerts}) == 2


def test_input_order_and_provenance_do_not_change_ids(event, write_events):
    events = sequence(event)
    first = analyze_file(write_events(events, "first.jsonl"))
    second = analyze_file(write_events(list(reversed(events)), "second.jsonl"))
    assert first["alerts"][0]["alert_id"] == second["alerts"][0]["alert_id"]
    assert ids(first["alerts"][0]) == ids(second["alerts"][0])
    assert first["alerts"][0]["success"]["provenance"]["line"] != second["alerts"][0]["success"]["provenance"]["line"]


def test_id_changes_when_effective_configuration_changes(event, write_events):
    path = write_events(sequence(event))
    default = analyze_file(path)["alerts"][0]["alert_id"]
    threshold = analyze_file(path, Config(threshold=4))["alerts"][0]["alert_id"]
    window = analyze_file(path, Config(window_seconds=301))["alerts"][0]["alert_id"]
    types = analyze_file(path, Config(logon_types=(3,)))["alerts"][0]["alert_id"]
    assert len({default, threshold, window, types}) == 4


def test_duplicate_events_cannot_supply_threshold(event, write_events):
    events = sequence(event, 4)
    events += [copy.deepcopy(events[0])] * 4
    result = analyze_file(write_events(events))
    assert result["alerts"] == []
    assert result["counts"]["duplicates"] == 4
    assert result["counts"]["processed"] == 5


def test_equivalent_normalized_duplicates_and_timezone(event, write_events):
    events = sequence(event)
    duplicate = dict(events[0], target_domain="lab-unit", target_user="UNIT-USER",
                     destination_host="lab-unit-server", source_ip="::ffff:192.0.2.70",
                     timestamp="2026-04-08T14:00:00+02:00")
    events.append(duplicate)
    result = analyze_file(write_events(events))
    assert result["counts"]["duplicates"] == 1
    assert ids(result["alerts"][0]) == ["f0", "f1", "f2", "f3", "f4"]


def test_ipv6_addresses_canonicalize(event, write_events):
    events = [event(f"f{i}", i * 20, source_ip="2001:0DB8:0000:0000:0000:0000:0000:0001") for i in range(5)]
    events.append(event("s", 150, 4624, source_ip="2001:db8::1"))
    assert analyze_file(write_events(events))["alerts"][0]["key"]["source_ip"] == "2001:db8::1"


@pytest.mark.parametrize("skip_invalid", [False, True])
def test_conflicting_uid_is_always_fatal(skip_invalid, event, write_events):
    path = write_events([event("same", 0), event("same", 1)])
    with pytest.raises(InputError):
        analyze_file(path, skip_invalid=skip_invalid)


@pytest.mark.parametrize("field,value", [
    ("source_ip", None), ("source_ip", ""), ("source_ip", "-"), ("source_ip", "invalid-address"),
    ("target_user", None), ("target_domain", "-"), ("destination_host", ""),
])
def test_quality_exclusions_remain_visible(field, value, event, write_events):
    events = sequence(event, 4) + [event("quality", 90, **{field: value})]
    result = analyze_file(write_events(events))
    assert result["alerts"] == []
    assert result["counts"]["excluded"] == 1
    assert result["counts"]["errors"] == 0
    assert result["issues"] and result["excluded_events"]
    assert "quality" in json.dumps(result["excluded_events"])


def test_missing_critical_field_is_quality_exclusion(event, write_events):
    item = event("missing-source", 0)
    del item["source_ip"]
    result = analyze_file(write_events([item]))
    assert result["counts"]["excluded"] == 1
    assert result["counts"]["errors"] == 0


@pytest.mark.parametrize("field,value", [
    ("event_id", 1), ("logon_type", 2), ("provider", "Microsoft-Windows-Sysmon"), ("channel", "System"),
])
def test_unsupported_event_source_is_excluded(field, value, event, write_events):
    result = analyze_file(write_events([event("excluded", 0, **{field: value})]))
    assert result["counts"]["excluded"] == 1
    assert result["alerts"] == []


@pytest.mark.parametrize("field,value", [
    ("timestamp", "2026-04-08T12:00:00"), ("timestamp", "not-a-date"),
    ("event_id", "4625"), ("event_id", True), ("logon_type", "3"),
    ("schema_version", "99"), ("data_origin", "production"),
])
def test_structural_errors_fail_default_but_skip_explicitly(field, value, event, write_events):
    path = write_events([event("broken", 0, **{field: value})] + sequence(event))
    with pytest.raises(InputError):
        analyze_file(path)
    result = analyze_file(path, skip_invalid=True)
    assert result["counts"]["errors"] == 1
    assert result["issues"]
    assert len(result["alerts"]) == 1


@pytest.mark.parametrize("kwargs", [{"threshold": 0}, {"threshold": -1},
                                    {"window_seconds": -1}, {"logon_types": ()}])
def test_invalid_configuration_rejected(kwargs):
    with pytest.raises((ValueError, InputError)):
        Config(**kwargs)


def test_configurable_limits_reject_instead_of_truncating(event, write_events):
    path = write_events(sequence(event))
    for kwargs in ({"max_bytes": 10}, {"max_events": 3}):
        with pytest.raises(InputError):
            analyze_file(path, **kwargs)
        with pytest.raises(InputError):
            analyze_file(path, skip_invalid=True, **kwargs)


def test_manual_independent_evaluation_exact_matches():
    base = Path(__file__).resolve().parents[1] / "data" / "evaluation"
    result = analyze_file(base / "events.jsonl")
    expected = json.loads((base / "expected.json").read_text())["expected_alerts"]
    actual = [{"success_uid": item["success"]["event_uid"], "failure_uids": ids(item),
               "key": item["key"]} for item in result["alerts"]]
    assert actual == expected
    assert result["counts"]["duplicates"] == 1


def test_empty_file_has_explicit_zero_counts(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("")
    result = analyze_file(path)
    assert result["alerts"] == []
    assert all(result["counts"][key] == 0 for key in ["input_lines", "processed", "duplicates", "excluded", "errors"])


def test_loader_retains_provenance(event, write_events):
    path = write_events([event("one", 0)])
    loaded = load_file(path)
    assert loaded.events[0]["provenance"] == {"input_file": str(path), "line": 1}
