"""Export-comparison checks; these fixtures are not executed Splunk output."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location("compare_results", Path(__file__).with_name("compare_results.py"))
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


def example():
    key = {"target_domain": "lab", "target_user": "sample01", "source_ip": "192.0.2.1",
           "destination_host": "lab-target", "logon_type": 3}
    reference = {"rule": {"id": "test-rule", "version": "1.0", "parameters": {
        "threshold": 1, "window_seconds": 300, "logon_types": [3, 10]}}, "alerts": [{
            "alert_id": "example-digest", "key": key, "failure_count": 1,
            "success": {"event_uid": "s1", "timestamp": "1970-01-01T00:05:00.000001Z"},
            "failures": [{"event_uid": "f1", "timestamp": "1970-01-01T00:00:00.000001Z"}]}]}
    exported = [{"result_status": "alert", "rule_id": "test-rule", "rule_version": "1.0",
                 "threshold": "1", "window_seconds": "300", "logon_types": "3,10",
                 "alert_id": "example-digest", "success_uid": "s1", "success_time_us": "300000001",
                 **key, "failure_count": "1", "failure_uids": "f1", "failure_times_us": "1"}]
    return reference, exported


def test_matches_manual_microsecond_evidence_and_scalar_export():
    reference, exported = example()
    assert comparison.compare(reference, exported) == 1


def test_matches_array_export():
    reference, exported = example()
    exported[0]["failure_uids"] = ["f1"]
    exported[0]["failure_times_us"] = ["1"]
    assert comparison.compare(reference, exported) == 1


@pytest.mark.parametrize("field,value", [
    ("alert_id", "wrong"), ("failure_uids", "wrong"), ("failure_times_us", "2"),
    ("success_time_us", "300000002"), ("target_domain", "other"),
    ("threshold", "2"), ("logon_types", "10"), ("result_status", "invalid-batch"),
    ("failure_count", "2"),
])
def test_rejects_mismatched_identity_evidence_config_or_error(field, value):
    reference, exported = example()
    exported[0][field] = value
    with pytest.raises(ValueError):
        comparison.compare(reference, exported)


def test_rejects_missing_unexpected_and_duplicate_alerts():
    reference, exported = example()
    for rows in ([], exported + deepcopy(exported)):
        with pytest.raises(ValueError):
            comparison.compare(reference, rows)
    exported[0]["success_uid"] = "unexpected"
    with pytest.raises(ValueError):
        comparison.compare(reference, exported)


def test_rejects_precision_loss_and_wrong_container():
    reference, exported = example()
    exported[0]["success_time_us"] = 300000001.0
    with pytest.raises(ValueError):
        comparison.compare(reference, exported)
    with pytest.raises(ValueError):
        comparison.compare(reference, {"results": []})


def test_cli_success_and_failure(tmp_path, capsys):
    reference, exported = example()
    py_file, splunk_file = tmp_path / "python.json", tmp_path / "supplied-example.json"
    py_file.write_text(json.dumps(reference), encoding="utf-8")
    splunk_file.write_text(json.dumps(exported), encoding="utf-8")
    args = ["--python-results", str(py_file), "--splunk-results", str(splunk_file)]
    assert comparison.main(args) == 0
    assert "does not establish that Splunk was executed" in capsys.readouterr().out
    exported[0]["failure_times_us"] = "2"
    splunk_file.write_text(json.dumps(exported), encoding="utf-8")
    assert comparison.main(args) == 1
    assert "comparison mismatch" in capsys.readouterr().err


def native_example():
    reference, exported = example()
    alert, row = reference["alerts"][0], exported[0]
    alert["success"].update(event_uid="windows-xml:s:104", record_id=104,
                            timestamp_raw="1970-01-01T00:05:00.0000018Z")
    alert["failures"][0].update(event_uid="windows-xml:f:101", record_id=101,
                               timestamp_raw="1970-01-01T00:00:00.0000012Z")
    alert["failures"].append({"event_uid": 'windows-xml:f:"103',
                             "timestamp": "1970-01-01T00:05:00.000001Z",
                             "record_id": 103,
                             "timestamp_raw": "1970-01-01T00:05:00.0000017Z"})
    alert["failure_count"] = 2
    row.update(success_uid="windows-xml:s:104", success_record_id="104",
               success_timestamp_raw="1970-01-01T00:05:00.0000018Z", failure_count="2",
               failure_uids=["windows-xml:f:101", 'windows-xml:f:"103'],
               failure_times_us=["1", "300000001"], failure_evidence=[
                   json.dumps({"event_uid": "windows-xml:f:101", "timestamp_epoch_us": "1",
                               "record_id": "101", "timestamp_raw": "1970-01-01T00:00:00.0000012Z"}),
                   json.dumps({"event_uid": 'windows-xml:f:"103', "timestamp_epoch_us": "300000001",
                               "record_id": "103", "timestamp_raw": "1970-01-01T00:05:00.0000017Z"})])
    return reference, exported


def test_matches_native_metadata_with_colons_quotes_and_reordered_paired_evidence():
    reference, exported = native_example()
    exported[0]["failure_evidence"].reverse()
    assert comparison.compare(reference, exported) == 1


@pytest.mark.parametrize("field", ["success_record_id", "success_timestamp_raw", "failure_evidence"])
def test_rejects_missing_native_evidence(field):
    reference, exported = native_example()
    del exported[0][field]
    with pytest.raises(ValueError, match="comparison mismatch"):
        comparison.compare(reference, exported)


@pytest.mark.parametrize("field,value", [
    ("record_id", "102"), ("timestamp_raw", "1970-01-01T00:00:00.0000013Z"),
    ("record_id", None), ("timestamp_epoch_us", "2"),
])
def test_rejects_changed_or_missing_metadata_in_paired_failure(field, value):
    reference, exported = native_example()
    evidence = json.loads(exported[0]["failure_evidence"][0])
    evidence[field] = value
    exported[0]["failure_evidence"][0] = json.dumps(evidence)
    with pytest.raises(ValueError):
        comparison.compare(reference, exported)


def test_rejects_metadata_swapped_between_failure_uids():
    reference, exported = native_example()
    evidence = [json.loads(item) for item in exported[0]["failure_evidence"]]
    evidence[0]["record_id"], evidence[1]["record_id"] = evidence[1]["record_id"], evidence[0]["record_id"]
    exported[0]["failure_evidence"] = [json.dumps(item) for item in evidence]
    with pytest.raises(ValueError, match="comparison mismatch"):
        comparison.compare(reference, exported)


def test_matches_mixed_native_and_legacy_failures_without_shifting_metadata():
    reference, exported = native_example()
    legacy = {"event_uid": "legacy:f3", "timestamp": "1970-01-01T00:04:00.000000Z"}
    reference["alerts"][0]["failures"].append(legacy)
    reference["alerts"][0]["failure_count"] = 3
    row = exported[0]
    row["failure_count"] = "3"
    row["failure_uids"].append("legacy:f3")
    row["failure_times_us"].append("240000000")
    row["failure_evidence"].append(json.dumps({"event_uid": "legacy:f3",
        "timestamp_epoch_us": "240000000", "record_id": None, "timestamp_raw": None}))
    assert comparison.compare(reference, exported) == 1


def test_rejects_duplicate_paired_evidence_even_when_uid_time_arrays_are_complete():
    reference, exported = native_example()
    exported[0]["failure_evidence"][1] = exported[0]["failure_evidence"][0]
    with pytest.raises(ValueError, match="duplicated UID"):
        comparison.compare(reference, exported)
