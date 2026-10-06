import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


PROJECT = Path(__file__).resolve().parents[1]


def cli(*args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PROJECT / "src")
    return subprocess.run([sys.executable, "-m", "soc_detection_lab", *map(str, args)],
                          cwd=PROJECT, env=env, capture_output=True, text=True, check=False)


def test_complete_cli_generate_validate_analyze_evaluate(tmp_path):
    generated = tmp_path / "generated"
    report = tmp_path / "report"
    command = cli("generate", "--output", generated, "--seed", 42)
    assert command.returncode == 0, command.stderr
    assert json.loads(command.stdout)["events_written"] == 24
    source = generated / "events.jsonl"
    command = cli("validate", "--input", source)
    assert command.returncode == 0, command.stderr
    summary = json.loads(command.stdout)
    assert summary["counts"] == {"input_lines": 24, "processed": 23, "duplicates": 1,
                                  "excluded": 0, "errors": 0}
    command = cli("analyze", "--input", source, "--output", report)
    assert command.returncode == 0, command.stderr
    json.loads(command.stdout)
    result = json.loads((report / "results.json").read_text())
    assert len(result["alerts"]) == 3
    assert result["rule"]["id"] == "repeated-failed-logons-then-success"
    assert result["rule"]["version"] == "1.0"
    assert result["rule"]["parameters"] == {"threshold": 5, "window_seconds": 300, "logon_types": [3, 10]}
    assert result["input"]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    markdown = (report / "report.md").read_text()
    for item in result["alerts"]:
        assert item["alert_id"] in markdown
        assert item["success"]["event_uid"] in markdown
        for failure in item["failures"]:
            assert failure["event_uid"] in markdown
    exported = [json.loads(line) for line in (report / "normalized.jsonl").read_text().splitlines()]
    assert len(exported) == 23
    assert len({row["event_uid"] for row in exported}) == 23
    command = cli("evaluate", "--input", source, "--expected", generated / "expected.json")
    assert command.returncode == 0, command.stderr + command.stdout
    command = cli("evaluate", "--input", PROJECT / "data/evaluation/events.jsonl",
                  "--expected", PROJECT / "data/evaluation/expected.json")
    assert command.returncode == 0, command.stderr + command.stdout


def test_generation_repeats_bytes_and_keeps_labels_separate(tmp_path):
    outputs = [tmp_path / name for name in ("one", "two", "other")]
    for path, seed in zip(outputs, [42, 42, 43]):
        result = cli("generate", "--output", path, "--seed", seed)
        assert result.returncode == 0, result.stderr
    for filename in ["events.jsonl", "expected.json", "context.json"]:
        assert (outputs[0] / filename).read_bytes() == (outputs[1] / filename).read_bytes()
    assert (outputs[0] / "events.jsonl").read_bytes() != (outputs[2] / "events.jsonl").read_bytes()
    event_fields = {"schema_version", "event_uid", "timestamp", "event_id", "provider", "channel",
                    "destination_host", "target_user", "target_domain", "source_ip", "logon_type",
                    "status", "sub_status", "data_origin"}
    for row in (outputs[0] / "events.jsonl").read_text().splitlines():
        assert set(json.loads(row)) == event_fields
    context = json.loads((outputs[0] / "context.json").read_text())
    assert {item["analyst_assessment"] for item in context["cases"]} == {"suspicious", "legitimate", "unresolved"}


def test_analysis_does_not_read_context_or_expectations(tmp_path):
    generated = tmp_path / "generated"
    assert cli("generate", "--output", generated).returncode == 0
    first = tmp_path / "one"
    second = tmp_path / "two"
    assert cli("analyze", "--input", generated / "events.jsonl", "--output", first).returncode == 0
    (generated / "expected.json").write_text("not JSON")
    (generated / "context.json").write_text("not JSON")
    assert cli("analyze", "--input", generated / "events.jsonl", "--output", second).returncode == 0
    assert (first / "results.json").read_bytes() == (second / "results.json").read_bytes()


def test_evaluation_mismatch_has_distinct_exit_code(tmp_path):
    expected = tmp_path / "wrong.json"
    expected.write_text(json.dumps({"expected_alerts": []}))
    result = cli("evaluate", "--input", PROJECT / "data/evaluation/events.jsonl", "--expected", expected)
    assert result.returncode == 3
    json.loads(result.stdout)


@pytest.mark.parametrize("content", ["{not-json}\n", "[]\n", "null\n", "\n"])
def test_malformed_lines_require_explicit_skip(content, tmp_path):
    source = tmp_path / "bad.jsonl"
    source.write_text(content)
    result = cli("validate", "--input", source)
    assert result.returncode == 2
    assert "1" in result.stderr + result.stdout
    assert "Traceback" not in result.stderr
    result = cli("validate", "--input", source, "--skip-invalid")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["counts"]["errors"] == 1


def test_conflicting_identity_cannot_be_skipped(event, write_events):
    path = write_events([event("same", 0), event("same", 1)])
    result = cli("validate", "--input", path, "--skip-invalid")
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("options", [
    ["--threshold", "0"], ["--threshold", "-1"], ["--threshold", "one"],
    ["--window-seconds", "-1"], ["--max-bytes", "0"], ["--max-events", "0"],
    ["--logon-types", "2"],
])
def test_cli_invalid_parameters_have_actionable_errors(options, tmp_path):
    result = cli("analyze", "--input", PROJECT / "data/fixtures/events.jsonl",
                 "--output", tmp_path / "report", *options)
    assert result.returncode == 2
    assert result.stderr.strip() or result.stdout.strip()
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("options", [["--max-events", "2"], ["--max-bytes", "2"]])
def test_cli_limits_reject_even_with_skip(options):
    result = cli("validate", "--input", PROJECT / "data/fixtures/events.jsonl", "--skip-invalid", *options)
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


def test_missing_input_clean_error(tmp_path):
    result = cli("validate", "--input", tmp_path / "missing.jsonl")
    assert result.returncode == 2
    assert "Traceback" not in result.stderr


def test_markdown_escapes_untrusted_log_values(event, write_events, tmp_path):
    malicious = "a|<script>alert(1)</script>"
    events = [event(f"f{i}", i * 20, target_user=malicious) for i in range(5)]
    events.append(event("s", 150, 4624, target_user=malicious))
    source = write_events(events)
    report = tmp_path / "report"
    result = cli("analyze", "--input", source, "--output", report)
    assert result.returncode == 0, result.stderr
    assert len(json.loads((report / "results.json").read_text())["alerts"]) == 1
    markdown = (report / "report.md").read_text()
    assert "<script>" not in markdown
    assert "a|" not in markdown
    assert "\nextra" not in markdown
    assert "&lt;script&gt;" in markdown


def test_control_character_in_field_is_visible_validation_error(event, write_events):
    source = write_events([event("one", 0, target_user="user\nextra")])
    result = cli("validate", "--input", source)
    assert result.returncode == 2
    assert "control characters" in result.stderr


def test_inspect_windows_xml_reports_raw_fields_without_writing(tmp_path):
    source = PROJECT / "data/documentation-examples/security-structure.xml"
    before = source.read_bytes()
    result = cli("inspect-windows-xml", "--input", source)
    assert result.returncode == 0, result.stderr
    inspected = json.loads(result.stdout)
    assert inspected["input"]["origin"] == "unverified-export"
    assert inspected["counts"]["input_events"] == 2
    assert inspected["events"][0]["event_data"]["LogonType"] == "3"
    assert "event_uid" not in inspected["events"][0]
    assert source.read_bytes() == before


def test_inspect_windows_xml_invalid_input_and_limits_fail_cleanly(tmp_path):
    source = tmp_path / "invalid.xml"
    source.write_text("<Events><broken></Events>")
    result = cli("inspect-windows-xml", "--input", source)
    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    source = PROJECT / "data/documentation-examples/security-structure.xml"
    result = cli("inspect-windows-xml", "--input", source, "--max-events", 1)
    assert result.returncode == 2
    assert "max_events" in result.stderr
