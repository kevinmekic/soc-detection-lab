"""Artificial inventory exports check failures; they are not real Splunk evidence."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path

import pytest


path = Path(__file__).resolve().parents[1] / "queries/splunk/compare_inventory.py"
spec = importlib.util.spec_from_file_location("compare_inventory", path)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def example():
    event = {"event_uid": "synthetic:one", "timestamp": "1970-01-01T00:00:00.999999Z",
             "timestamp_epoch_us": 999999, "timestamp_raw": "1970-01-01T00:00:00.9999999Z",
             "record_id": 123, "event_id": 4625, "target_domain": "lab", "target_user": "sample",
             "source_ip": "192.0.2.90", "destination_host": "lab-target", "logon_type": 3,
             "data_origin": "synthetic"}
    exported = deepcopy(event)
    for name in inventory.INT_FIELDS + ("record_id",):
        exported[name] = str(exported[name])
    exported.update(indexed_time_us="999999", parsed_time_us="999999")
    return [event], [exported]


def test_inventory_matches_time_and_all_native_fields():
    assert inventory.compare(*example()) == 1


@pytest.mark.parametrize("field,value", [("indexed_time_us", "1000000"), ("parsed_time_us", "999998"),
    ("timestamp", "1970-01-01T00:00:01.000000Z"), ("record_id", "124"),
    ("timestamp_raw", "1970-01-01T00:00:00.9999998Z"), ("source_ip", "192.0.2.91"),
    ("logon_type", "10"), ("data_origin", "lab-captured")])
def test_inventory_rejects_time_loss_metadata_loss_or_wrong_mapping(field, value):
    events, rows = example()
    rows[0][field] = value
    with pytest.raises(ValueError):
        inventory.compare(events, rows)


def test_inventory_rejects_incomplete_duplicate_and_unexpected_rows():
    events, rows = example()
    for supplied in ([], rows + rows, [{**rows[0], "event_uid": "extra"}]):
        with pytest.raises(ValueError):
            inventory.compare(events, supplied)


def test_inventory_cli_checks_export_and_reports_failure(tmp_path, capsys):
    events, rows = example()
    transport, exported = tmp_path / "transport.jsonl", tmp_path / "artificial-inventory.json"
    transport.write_text(json.dumps(events[0]) + "\n")
    exported.write_text(json.dumps(rows))
    args = ["--normalized", str(transport), "--splunk-results", str(exported)]
    assert inventory.main(args) == 0
    assert "does not establish" in capsys.readouterr().out
    rows[0]["indexed_time_us"] = "1000000"
    exported.write_text(json.dumps(rows))
    assert inventory.main(args) == 1
    assert "index-time parsing" in capsys.readouterr().err
