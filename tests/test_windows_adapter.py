"""Adapter and record-order tests use hand-authored synthetic events only."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from soc_detection_lab.engine import Config, InputError, analyze_file, load_file, normalize
from soc_detection_lab.windows_adapter import adapt_windows_xml


PROJECT = Path(__file__).resolve().parents[1]
FIXTURE = PROJECT / "data/fixtures/windows-adapter-synthetic.xml"


def cli(*args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PROJECT / "src")
    return subprocess.run([sys.executable, "-m", "soc_detection_lab", *map(str, args)],
                          cwd=PROJECT, env=env, capture_output=True, text=True, check=False)


def changed_fixture(tmp_path, before, after):
    content = FIXTURE.read_text(encoding="utf-8")
    assert before in content
    path = tmp_path / "synthetic.xml"
    path.write_text(content.replace(before, after, 1), encoding="utf-8")
    return path


def test_adapter_maps_native_fields_and_truncates_instead_of_rounding():
    result = adapt_windows_xml(FIXTURE, data_origin="synthetic")
    assert result["counts"] == {
        "input_events": 8, "emitted": 3, "excluded": 5, "outside_rule_scope": 3,
        "truncated_timestamps": 1, "precision_loss_events": 1,
    }
    failure, success, remote = result["events"]
    assert failure["timestamp"] == "2026-04-08T12:00:00.999999Z"
    assert failure["timestamp_raw"] == "2026-04-08T12:00:00.9999999Z"
    assert failure["record_id"] == 100 and type(failure["record_id"]) is int
    assert failure["schema_version"] == "1.0"
    assert failure["event_id"] == 4625
    assert failure["provider"] == "Microsoft-Windows-Security-Auditing"
    assert failure["channel"] == "Security"
    assert failure["destination_host"] == "lab-synth-adapter"
    assert failure["target_domain"] == "lab-synth-adapter"
    assert failure["target_user"] == "adapter-user"
    assert failure["source_ip"] == "192.0.2.80"
    assert failure["logon_type"] == 3
    assert failure["status"] == "0xc000006d"
    assert failure["sub_status"] == "0xc000006a"
    assert all(item["data_origin"] == "synthetic" for item in result["events"])
    assert success["event_id"] == 4624 and success["record_id"] == 101
    assert success["timestamp_raw"] == "2026-04-08T12:00:02.123456Z"
    assert remote["logon_type"] == 10
    assert all(normalize(item)[1] == [] for item in result["events"])


def test_adapter_excludes_every_outside_scope_event_with_its_actual_reason():
    result = adapt_windows_xml(FIXTURE, data_origin="synthetic")
    excluded = {item["record_id"]: item for item in result["excluded_events"]}
    assert set(excluded) == {103, 104, 105, 106, 107}
    assert [item["xml_event_index"] for item in result["excluded_events"]] == [4, 5, 6, 7, 8]
    reasons = {key: " ".join(value["reasons"]) for key, value in excluded.items()}
    assert "logon_type" in reasons[103] and "source_ip" in reasons[103]
    assert "event_id" in reasons[104]
    assert "provider" in reasons[105]
    assert "target_domain" in reasons[106]
    assert "source_ip" in reasons[107]
    assert all(item["reasons"] for item in excluded.values())
    assert {item["record_id"] for item in result["events"]}.isdisjoint(excluded)


def test_uid_is_manual_hash_of_raw_computer_channel_and_canonical_record_id(tmp_path):
    expected = "windows-xml:" + hashlib.sha256(
        b"LAB-SYNTH-ADAPTER|Security|100").hexdigest()
    first = adapt_windows_xml(FIXTURE, data_origin="synthetic")["events"][0]
    copy = tmp_path / "renamed-synthetic.xml"
    copy.write_bytes(FIXTURE.read_bytes())
    moved = adapt_windows_xml(copy, data_origin="lab-captured")["events"][0]
    leading_zero = changed_fixture(tmp_path, "<EventRecordID>100</EventRecordID>",
                                  "<EventRecordID>00100</EventRecordID>")
    canonical = adapt_windows_xml(leading_zero, data_origin="synthetic")["events"][0]
    assert first["event_uid"] == moved["event_uid"] == canonical["event_uid"] == expected
    changed = changed_fixture(tmp_path, "<EventRecordID>100</EventRecordID>",
                              "<EventRecordID>200</EventRecordID>")
    assert adapt_windows_xml(changed, data_origin="synthetic")["events"][0]["event_uid"] != expected


@pytest.mark.parametrize("value", ["", "-", "not-an-ip"])
def test_adapter_never_substitutes_a_missing_or_invalid_source(tmp_path, value):
    path = changed_fixture(tmp_path, '<Data Name="IpAddress">192.0.2.80</Data>',
                           f'<Data Name="IpAddress">{value}</Data>')
    result = adapt_windows_xml(path, data_origin="synthetic")
    assert result["counts"]["emitted"] == 2
    assert result["counts"]["excluded"] == 6
    excluded = next(item for item in result["excluded_events"] if item["record_id"] == 100)
    assert any("source_ip" in reason for reason in excluded["reasons"])
    assert not any(item["record_id"] == 100 for item in result["events"])


def test_adapter_validates_input_bounds_without_modifying_synthetic_source(tmp_path):
    before = FIXTURE.read_bytes()
    with pytest.raises(InputError, match="max_events"):
        adapt_windows_xml(FIXTURE, data_origin="synthetic", max_events=7)
    with pytest.raises(InputError, match="max_bytes"):
        adapt_windows_xml(FIXTURE, data_origin="synthetic", max_bytes=len(before) - 1)
    assert FIXTURE.read_bytes() == before


def test_record_id_breaks_microsecond_ties_independently_of_jsonl_order(event, write_events):
    shared_time = "2026-04-08T12:00:00.123456Z"
    events = [event("z-first", 0, record_id=10, timestamp=shared_time),
              event("a-second", 0, record_id=11, timestamp=shared_time),
              event("success", 0, 4624, record_id=12, timestamp=shared_time),
              event("higher-id", 0, record_id=13, timestamp=shared_time),
              event("legacy-no-id", 0, timestamp=shared_time)]
    first_source = write_events(events, "ordered.jsonl")
    reversed_source = write_events(list(reversed(events)), "reversed.jsonl")
    first = analyze_file(first_source, Config(threshold=2))
    second = analyze_file(reversed_source, Config(threshold=2))
    assert len(first["alerts"]) == len(second["alerts"]) == 1
    assert [item["event_uid"] for item in first["alerts"][0]["failures"]] == ["z-first", "a-second"]
    assert first["alerts"][0]["failure_count"] == 2
    assert first["alerts"][0]["alert_id"] == second["alerts"][0]["alert_id"]
    assert [item["event_uid"] for item in second["alerts"][0]["failures"]] == ["z-first", "a-second"]
    assert [item["record_id"] for item in load_file(reversed_source).events
            if "record_id" in item] == [10, 11, 12, 13]


def test_lower_time_boundary_remains_inclusive_and_higher_tie_cannot_supply_threshold(event, write_events):
    events = [event("lower-bound", 0, record_id=900),
              event("middle-1", 20, record_id=901),
              event("middle-2", 40, record_id=902),
              event("middle-3", 60, record_id=903),
              event("higher-tie", 300, record_id=906),
              event("success", 300, 4624, record_id=905)]
    assert analyze_file(write_events(events, "four.jsonl"))["alerts"] == []
    events.append(event("lower-tie", 300, record_id=904))
    alert = analyze_file(write_events(list(reversed(events)), "five.jsonl"))["alerts"][0]
    assert [item["event_uid"] for item in alert["failures"]] == [
        "lower-bound", "middle-1", "middle-2", "middle-3", "lower-tie"]
    assert alert["failure_count"] == 5


def test_legacy_success_without_record_id_keeps_equal_timestamp_excluded(event, write_events):
    events = [event("native-failure", 0, record_id=10), event("legacy-success", 0, 4624)]
    assert analyze_file(write_events(events), Config(threshold=1))["alerts"] == []


@pytest.mark.parametrize("value", [True, 0, -1, 1.5, "1", None])
def test_optional_record_id_requires_positive_integer_when_present(event, value):
    with pytest.raises(ValueError, match="record_id"):
        normalize(event("one", 0, record_id=value))


def test_optional_fields_preserve_original_precision_but_do_not_appear_in_legacy_event(event):
    raw = event("native", 0, timestamp="2026-04-08T12:00:00.999999Z",
                timestamp_raw="2026-04-08T12:00:00.9999999Z", record_id=10)
    normalized, quality = normalize(raw)
    assert quality == []
    assert normalized["timestamp_raw"] == raw["timestamp_raw"]
    assert normalized["record_id"] == 10
    legacy, _ = normalize(event("legacy", 0))
    assert "timestamp_raw" not in legacy and "record_id" not in legacy


def test_original_time_must_agree_with_its_truncated_normalized_time(event):
    with pytest.raises(ValueError, match="timestamp_raw.*match timestamp"):
        normalize(event("native", 0, timestamp="2026-04-08T12:00:01.000000Z",
                        timestamp_raw="2026-04-08T12:00:00.9999999Z", record_id=10))


def test_invalid_native_time_is_excluded_with_a_reason(tmp_path):
    path = changed_fixture(tmp_path, "2026-04-08T12:00:00.9999999Z", "not-a-timestamp")
    result = adapt_windows_xml(path, data_origin="synthetic")
    assert result["counts"]["emitted"] == 2
    excluded = next(item for item in result["excluded_events"] if item["record_id"] == 100)
    assert any("timestamp_raw" in reason for reason in excluded["reasons"])


def test_cli_adapter_writes_jsonl_and_exclusion_result(tmp_path):
    output = tmp_path / "adapted"
    before = FIXTURE.read_bytes()
    command = cli("adapt-windows-xml", "--input", FIXTURE, "--output", output,
                  "--data-origin", "synthetic")
    assert command.returncode == 0, command.stderr + command.stdout
    rows = [json.loads(line) for line in (output / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    result = json.loads((output / "adapter-result.json").read_text(encoding="utf-8"))
    assert len(rows) == 3
    assert rows == adapt_windows_xml(FIXTURE, data_origin="synthetic")["events"]
    assert result["counts"]["input_events"] == 8
    assert result["counts"]["excluded"] == len(result["excluded_events"]) == 5
    assert rows[0]["timestamp"] == "2026-04-08T12:00:00.999999Z"
    assert FIXTURE.read_bytes() == before
    command = cli("validate", "--input", output / "events.jsonl")
    assert command.returncode == 0, command.stderr + command.stdout
    assert json.loads(command.stdout)["counts"]["processed"] == 3
    report = tmp_path / "analysis"
    command = cli("analyze", "--input", output / "events.jsonl", "--output", report,
                  "--threshold", "1")
    assert command.returncode == 0, command.stderr + command.stdout
    markdown = (report / "report.md").read_text(encoding="utf-8")
    assert "Record ID" in markdown and "Original SystemTime" in markdown
    assert "2026-04-08T12:00:00.9999999Z" in markdown
    assert "lower record IDs" in markdown


def test_cli_adapter_requires_explicit_origin(tmp_path):
    command = cli("adapt-windows-xml", "--input", FIXTURE, "--output", tmp_path / "adapted")
    assert command.returncode == 2
    assert "data-origin" in command.stderr
    assert not (tmp_path / "adapted").exists()
