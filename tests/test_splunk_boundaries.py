"""Fixed synthetic expectations for the later, genuine Splunk comparison."""

import json
from pathlib import Path

from soc_detection_lab.cli import evaluate, export_splunk
from soc_detection_lab.engine import Config, analyze_file, load_file
from soc_detection_lab.windows_adapter import adapt_windows_xml


DATA = Path(__file__).resolve().parents[1] / "data/splunk-boundaries"


def test_synthetic_boundary_pipeline_has_exact_predeclared_evidence(tmp_path):
    adapted = adapt_windows_xml(DATA / "events.xml", data_origin="synthetic")
    assert adapted["counts"]["input_events"] == adapted["counts"]["emitted"] == 14
    assert adapted["counts"]["excluded"] == 0
    path = tmp_path / "normalized.jsonl"
    path.write_text("".join(json.dumps(e) + "\n" for e in adapted["events"]))
    result = analyze_file(path)
    assert evaluate(result, DATA / "expected.json")["matched"] is True
    by_success = {a["success"]["record_id"]: a for a in result["alerts"]}
    assert set(by_success) == {1006, 2006}
    assert [f["record_id"] for f in by_success[1006]["failures"]] == [1001,1002,1003,1004,1005]
    assert [f["record_id"] for f in by_success[2006]["failures"]] == [2001,2002,2003,2004,2005]
    transport = list(export_splunk(load_file(path).events, Config()))
    assert len(transport) == 14
    assert all(e["data_origin"] == "synthetic" and "timestamp_raw" in e and "record_id" in e for e in transport)
    tie = [e for e in transport if e["target_user"] == "tie-user"]
    assert len({e["timestamp_epoch_us"] for e in tie}) == 1
    assert all(e["timestamp"].endswith(".999999Z") for e in tie)
