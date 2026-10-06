"""Inspection tests use constructed documented structure, never lab captures."""

import hashlib
from pathlib import Path

import pytest

from soc_detection_lab.engine import InputError
from soc_detection_lab.windows_xml import inspect_windows_xml

FIXTURE = Path(__file__).resolve().parents[1] / "data/documentation-examples/security-structure.xml"


def changed_fixture(tmp_path, before, after):
    content = FIXTURE.read_text(encoding="utf-8")
    assert before in content
    path = tmp_path / "synthetic.xml"
    path.write_text(content.replace(before, after, 1), encoding="utf-8")
    return path


def test_inspects_selected_fields_without_creating_normalized_data():
    result = inspect_windows_xml(FIXTURE)
    assert result["input"] == {
        "path": str(FIXTURE), "sha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
        "origin": "unverified-export",
    }
    assert result["counts"] == {
        "input_events": 2, "events_with_issues": 0, "missing_correlation": 0,
        "outside_rule_scope": 0, "incompatible_timestamps": 0,
    }
    failure, success = result["events"]
    assert failure["xml_event_index"] == 1
    assert success["xml_event_index"] == 2
    assert failure["system"] == {
        "Provider": "Microsoft-Windows-Security-Auditing", "EventID": "4625", "Version": "0",
        "Channel": "Security", "Computer": "LAB-DOC-SERVER", "EventRecordID": "10",
        "SystemTime": "2026-04-08T12:00:00.123456000Z",
    }
    assert failure["event_data"] == {
        "TargetUserName": "doc-user", "TargetDomainName": "LAB-DOC-SERVER",
        "IpAddress": "192.0.2.70", "LogonType": "3", "Status": "0xc000006d", "SubStatus": "0xc000006a",
    }
    assert success["system"]["EventID"] == "4624"
    assert success["event_data"]["Status"] is None
    assert success["event_data"]["SubStatus"] is None
    assert "SubjectUserName" not in failure["event_data"]
    assert "event_uid" not in failure
    assert "data_origin" not in failure


@pytest.mark.parametrize("raw", [
    "2015-11-12T00:24:35.079785200Z",  # Microsoft's original 4624 example.
    "2015-09-08T22:54:54.962511700Z",  # Microsoft's original 4625 example.
])
def test_reports_documented_native_precision_without_truncating(tmp_path, raw):
    path = changed_fixture(tmp_path, "2026-04-08T12:00:00.123456000Z", raw)
    event = inspect_windows_xml(path)["events"][0]
    assert event["system"]["SystemTime"] == raw
    assert event["timestamp"]["representable_microseconds"] is False
    assert "submicrosecond" in event["timestamp"]["reason"]
    assert any("cannot be imported exactly" in issue for issue in event["issues"])


@pytest.mark.parametrize("raw, representable", [
    ("2026-04-08T12:00:00Z", True),
    ("2026-04-08T14:00:00.123456000+02:00", True),
    ("2026-04-08T12:00:00.000000100Z", False),
    ("2026-04-08T12:00:00", False),
    ("2026-02-30T12:00:00.123456000Z", False),
    ("2026-04-08T12:00:00+24:00", False),
])
def test_checks_timestamp_representation_and_validity(tmp_path, raw, representable):
    path = changed_fixture(tmp_path, "2026-04-08T12:00:00.123456000Z", raw)
    event = inspect_windows_xml(path)["events"][0]
    assert event["system"]["SystemTime"] == raw
    assert event["timestamp"]["representable_microseconds"] is representable


@pytest.mark.parametrize("replacement", [
    '<Data Name="IpAddress">-</Data>', '<Data Name="IpAddress" />', "",
])
def test_missing_source_is_visible_and_never_invented(tmp_path, replacement):
    path = changed_fixture(tmp_path, '<Data Name="IpAddress">192.0.2.70</Data>', replacement)
    result = inspect_windows_xml(path)
    event = result["events"][0]
    assert event["event_data"]["IpAddress"] in ("-", None)
    assert event["missing_correlation_fields"] == ["source_ip"]
    assert event["source_ip_valid"] is None
    assert result["counts"]["missing_correlation"] == 1


def test_invalid_source_and_missing_identity_are_inspection_issues(tmp_path):
    path = changed_fixture(tmp_path, "192.0.2.70", "not-an-ip")
    path.write_text(path.read_text().replace("<EventRecordID>10</EventRecordID>", ""), encoding="utf-8")
    event = inspect_windows_xml(path)["events"][0]
    assert event["source_ip_valid"] is False
    assert event["system"]["EventRecordID"] is None
    assert any("EventRecordID is missing" in issue for issue in event["issues"])


@pytest.mark.parametrize("before,field", [
    ("<Computer>LAB-DOC-SERVER</Computer>", "destination_host"),
    ('<Data Name="TargetUserName">doc-user</Data>', "target_user"),
    ('<Data Name="TargetDomainName">LAB-DOC-SERVER</Data>', "target_domain"),
    ('<Data Name="LogonType">3</Data>', "logon_type"),
])
def test_each_missing_correlation_value_is_identified(tmp_path, before, field):
    path = changed_fixture(tmp_path, before, "")
    event = inspect_windows_xml(path)["events"][0]
    assert event["missing_correlation_fields"] == [field]


@pytest.mark.parametrize("before,after", [
    ('<Data Name="LogonType">3</Data>', '<Data Name="LogonType">2</Data>'),
    ("<EventID>4625</EventID>", "<EventID>4634</EventID>"),
    ("Microsoft-Windows-Security-Auditing", "Other-Provider"),
    ("<Channel>Security</Channel>", "<Channel>System</Channel>"),
])
def test_out_of_scope_records_are_reported_without_normalization(tmp_path, before, after):
    path = changed_fixture(tmp_path, before, after)
    result = inspect_windows_xml(path)
    assert result["events"][0]["rule_scope_compatible"] is False
    assert result["counts"]["outside_rule_scope"] == 1


@pytest.mark.parametrize("xml,reason", [
    ("<Events>", "cannot inspect"),
    ("<Event />", "Events container"),
    ('<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event" />', "Events container"),
    ("<Events><Event><System /><EventData /></Event></Events>", "namespace"),
    ('<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event" /></Events>', "System and EventData"),
    ("<Events>not-events</Events>", "only Event elements"),
    ('<!DOCTYPE Events [<!ENTITY data "x">]><Events />', "DTD and entity"),
    ('<?xml version="1.0" encoding="UTF-16"?><Events />', "requires UTF-8"),
])
def test_rejects_invalid_or_unsupported_export_structures(tmp_path, xml, reason):
    path = tmp_path / "invalid.xml"
    path.write_text(xml, encoding="utf-8")
    with pytest.raises(InputError, match=reason):
        inspect_windows_xml(path)


@pytest.mark.parametrize("before,after,reason", [
    ("<EventID>4625</EventID>", "<EventID>4625</EventID><EventID>4624</EventID>", "multiple EventID"),
    ('<Data Name="IpAddress">192.0.2.70</Data>',
     '<Data Name="IpAddress">192.0.2.70</Data><Data Name="IpAddress">192.0.2.71</Data>', "duplicate EventData name"),
    ('<Data Name="IpAddress">192.0.2.70</Data>', '<Data>192.0.2.70</Data>', "Name attribute"),
])
def test_rejects_ambiguous_fields_with_event_ordinal(tmp_path, before, after, reason):
    path = changed_fixture(tmp_path, before, after)
    with pytest.raises(InputError, match="XML event 1: .*" + reason):
        inspect_windows_xml(path)


def test_enforces_input_bounds_and_reads_utf8_bom_without_writing(tmp_path):
    path = tmp_path / "with-bom.xml"
    content = b"\xef\xbb\xbf" + FIXTURE.read_bytes()
    path.write_bytes(content)
    before = tuple(tmp_path.iterdir())
    result = inspect_windows_xml(path, max_bytes=len(content), max_events=2)
    assert result["input"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert tuple(tmp_path.iterdir()) == before
    assert path.read_bytes() == content
    with pytest.raises(InputError, match="max_bytes"):
        inspect_windows_xml(path, max_bytes=len(content) - 1)
    with pytest.raises(InputError, match="max_events"):
        inspect_windows_xml(path, max_events=1)


@pytest.mark.parametrize("name,value", [("max_bytes", 0), ("max_events", -1), ("max_events", True)])
def test_rejects_invalid_limits(name, value):
    with pytest.raises(InputError, match="positive integer"):
        inspect_windows_xml(FIXTURE, **{name: value})


def test_empty_container_is_an_inspection_of_zero_events(tmp_path):
    path = tmp_path / "empty.xml"
    path.write_text("<Events />", encoding="utf-8")
    result = inspect_windows_xml(path)
    assert result["events"] == []
    assert result["counts"]["input_events"] == 0
