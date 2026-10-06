"""Additional checks of safe bounded handling and the future SIEM handoff."""

import json

import pytest

from soc_detection_lab.cli import export_splunk
from soc_detection_lab.engine import Config, InputError, analyze_file, load_file


def test_export_preserves_integer_microseconds_and_candidate_ids(event, write_events):
    events = [event(f"f{i}", i) for i in range(5)]
    events += [event("early", -1, 4624), event("matched", 10.000001, 4624)]
    path = write_events(events)
    result = analyze_file(path)
    projected = list(export_splunk(load_file(path).events, Config()))
    by_uid = {item["event_uid"]: item for item in projected}
    assert by_uid["matched"]["candidate_alert_id"] == result["alerts"][0]["alert_id"]
    assert by_uid["early"]["candidate_alert_id"]  # No label: even non-qualifying successes have IDs.
    assert by_uid["f0"]["candidate_alert_id"] is None
    assert by_uid["matched"]["timestamp_epoch_us"] % 1_000_000 == 1
    assert by_uid["matched"]["timestamp_epoch_us"] - by_uid["f0"]["timestamp_epoch_us"] == 10_000_001


def test_duplicate_json_keys_never_silently_choose_one(event, tmp_path):
    path = tmp_path / "duplicate-keys.jsonl"
    record = json.dumps(event("one", 0))
    path.write_text(record[:-1] + ', "event_id": 4624}\n')
    with pytest.raises(InputError) as error:
        analyze_file(path)
    assert "duplicate JSON field" in error.value.result["issues"][0]["reason"]


@pytest.mark.parametrize("timestamp", ["2026-04-08T12:00:00.0000001Z", "2026-04-08T12:00:00+24:00"])
def test_invalid_timestamp_precision_or_offset_is_rejected(timestamp, event, write_events):
    with pytest.raises(InputError):
        analyze_file(write_events([event("bad", 0, timestamp=timestamp)]))


def test_utf8_and_blank_records_are_counted_as_errors(tmp_path):
    path = tmp_path / "bad-encoding.jsonl"
    path.write_bytes(b"\xff\n\n")
    result = analyze_file(path, skip_invalid=True)
    assert result["counts"] == {"input_lines": 2, "processed": 0, "duplicates": 0, "excluded": 0, "errors": 2}
    assert [issue["provenance"]["line"] for issue in result["issues"]] == [1, 2]


def test_configuration_exclusions_preserve_counts_and_evidence(event, write_events):
    result = analyze_file(write_events([event("remote", 0, logon_type=10)]), Config(logon_types=(3,)))
    assert result["counts"] == {"input_lines": 1, "processed": 0, "duplicates": 0, "excluded": 1, "errors": 0}
    assert result["excluded_events"][0]["event"]["event_uid"] == "remote"


def test_repeated_success_output_is_bounded(event, write_events, monkeypatch):
    monkeypatch.setattr("soc_detection_lab.engine.MAX_EVIDENCE_REFERENCES", 10)
    events = [event(f"f{i}", i) for i in range(5)]
    events += [event("s1", 10, 4624), event("s2", 11, 4624)]
    with pytest.raises(InputError, match="total evidence references"):
        analyze_file(write_events(events))


def test_unknown_fields_cannot_inject_scenario_labels(event, write_events):
    with pytest.raises(InputError) as error:
        analyze_file(write_events([event("one", 0, expected_alert=True)]))
    assert "unknown schema fields" in error.value.result["issues"][0]["reason"]


@pytest.mark.parametrize("invalid_first", [False, True])
def test_skip_mode_cannot_select_valid_version_of_disputed_uid(invalid_first, event, write_events):
    records = [event("same", 0), event("same", 0, timestamp="not-a-date")]
    if invalid_first:
        records.reverse()
    with pytest.raises(InputError, match="conflicting event identities") as error:
        analyze_file(write_events(records), skip_invalid=True)
    assert any(issue["kind"] == "uid_conflict" for issue in error.value.result["issues"])


def test_invalid_unicode_is_rejected_before_report_writing(event, write_events):
    with pytest.raises(InputError) as error:
        analyze_file(write_events([event("bad", 0, target_user="bad\ud800")]))
    assert "invalid Unicode surrogate" in error.value.result["issues"][0]["reason"]
