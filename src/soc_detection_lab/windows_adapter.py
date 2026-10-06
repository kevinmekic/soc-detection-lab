"""Adapt selected native Windows XML to the lab schema under its truncation policy."""

import hashlib
import re

from .engine import InputError, MAX_BYTES, MAX_EVENTS, PROVIDER, event_sort_key, normalize, truncate_windows_time
from .windows_xml import _integer, inspect_windows_xml


def adapt_windows_xml(path, *, data_origin="lab-captured", max_bytes=MAX_BYTES, max_events=MAX_EVENTS):
    """Return eligible events and explicit exclusions without inventing missing fields."""
    if data_origin not in ("synthetic", "lab-captured"):
        raise InputError("data_origin must be synthetic or lab-captured")
    inspected = inspect_windows_xml(path, max_bytes=max_bytes, max_events=max_events)
    emitted = []
    excluded = []
    provenance = []
    shortened = 0
    precision_loss = 0
    outside_scope = 0
    for item in inspected["events"]:
        system, payload = item["system"], item["event_data"]
        event_id = _integer(system["EventID"])
        logon_type = _integer(payload["LogonType"])
        record_id = _integer(system["EventRecordID"])
        reasons = []
        if system["Provider"] != PROVIDER:
            reasons.append("outside_scope: unsupported provider")
        if system["Channel"] != "Security":
            reasons.append("outside_scope: unsupported channel")
        if event_id not in (4624, 4625):
            reasons.append("outside_scope: event_id is not 4624 or 4625")
        if logon_type not in (3, 10):
            reasons.append("outside_scope: logon_type is not 3 or 10")
        if reasons:
            outside_scope += 1
        reasons.extend("missing critical correlation field: " + name for name in item["missing_correlation_fields"])
        if item["source_ip_valid"] is False:
            reasons.append("source_ip is invalid")
        if record_id is None or record_id <= 0:
            reasons.append("record_id is missing or invalid")
        if reasons:
            excluded.append({"xml_event_index": item["xml_event_index"], "record_id": record_id,
                             "event_id": event_id, "logon_type": logon_type, "reasons": reasons})
            continue
        try:
            timestamp_raw = system["SystemTime"]
            timestamp = truncate_windows_time(timestamp_raw)
            identity = f"{system['Computer']}|{system['Channel']}|{record_id}"
            uid = "windows-xml:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
            event, quality = normalize({
                "schema_version": "1.0", "event_uid": uid,
                "timestamp": timestamp, "timestamp_raw": timestamp_raw, "record_id": record_id,
                "event_id": event_id, "provider": system["Provider"], "channel": system["Channel"],
                "destination_host": system["Computer"], "target_user": payload["TargetUserName"],
                "target_domain": payload["TargetDomainName"], "source_ip": payload["IpAddress"],
                "logon_type": logon_type, "status": payload["Status"], "sub_status": payload["SubStatus"],
                "data_origin": data_origin,
            })
        except ValueError as exc:
            excluded.append({"xml_event_index": item["xml_event_index"], "record_id": record_id,
                             "event_id": event_id, "logon_type": logon_type,
                             "reasons": ["invalid normalized record: " + str(exc)]})
            continue
        if quality:
            excluded.append({"xml_event_index": item["xml_event_index"], "record_id": record_id,
                             "event_id": event_id, "logon_type": logon_type, "reasons": quality})
            continue
        fraction = re.search(r"\.(\d+)", timestamp_raw)
        digits = fraction.group(1) if fraction else ""
        shortened += len(digits) > 6
        precision_loss += any(digit != "0" for digit in digits[6:])
        emitted.append(event)
        provenance.append({"event_uid": uid, "record_id": record_id,
                           "xml_event_index": item["xml_event_index"]})
    emitted.sort(key=event_sort_key)
    return {
        "input": {"path": inspected["input"]["path"], "sha256": inspected["input"]["sha256"],
                  "data_origin": data_origin},
        "format": "windows-events-xml", "schema_version": "1.0",
        "counts": {"input_events": inspected["counts"]["input_events"], "emitted": len(emitted),
                   "excluded": len(excluded), "outside_rule_scope": outside_scope,
                   "truncated_timestamps": shortened, "precision_loss_events": precision_loss},
        "events": emitted, "excluded_events": excluded, "event_provenance": provenance,
        "precision_policy": "string truncation to six fractional digits; timestamp_raw retained; no rounding",
        "uid_policy": "windows-xml: + sha256(raw Computer|Channel|integer EventRecordID); record ID reuse can collide",
        "limits": inspected["limits"],
        "scope": "origin is declared by the caller; conversion does not authenticate the capture",
    }
