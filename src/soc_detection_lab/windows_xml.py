"""Read-only inspection of a bounded Windows Event XML export.

This module does not normalize events, assert capture provenance or generate UIDs.
"""

import hashlib
import ipaddress
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from .engine import InputError, MAX_BYTES, MAX_EVENTS, PROVIDER, parse_time

EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = "{" + EVENT_NAMESPACE + "}"
DATA_FIELDS = ("TargetUserName", "TargetDomainName", "IpAddress", "LogonType", "Status", "SubStatus")


def _one(parent, name):
    children = parent.findall(NS + name)
    if len(children) > 1:
        raise ValueError(f"multiple {name} elements make the export ambiguous")
    return children[0] if children else None


def _text(parent, name):
    element = _one(parent, name)
    return element.text if element is not None else None


def _usable(value):
    return value is not None and value.strip() not in ("", "-")


def _integer(value):
    if value is None or not re.fullmatch(r"[0-9]+", value.strip()):
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _timestamp_check(raw):
    if not isinstance(raw, str):
        return {"representable_microseconds": False, "reason": "SystemTime is missing"}
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})", raw
    )
    if not match:
        return {"representable_microseconds": False,
                "reason": "SystemTime requires seconds and an explicit ISO 8601 timezone"}
    fraction = match.group(2) or ""
    if any(digit != "0" for digit in fraction[6:]):
        return {"representable_microseconds": False,
                "reason": "nonzero submicrosecond digits cannot be represented exactly by schema 1.0"}
    exact = match.group(1) + ("." + fraction[:6] if fraction else "") + match.group(3)
    try:
        parse_time(exact)
    except ValueError as exc:
        return {"representable_microseconds": False, "reason": str(exc)}
    return {"representable_microseconds": True,
            "reason": "exactly representable; any fractional digits after the sixth are zero"}


def _inspect_event(element, index):
    if element.tag != NS + "Event":
        raise ValueError("each Events child must be Event in the documented Windows event namespace")
    system_node = _one(element, "System")
    data_node = _one(element, "EventData")
    if system_node is None or data_node is None:
        raise ValueError("each Event requires System and EventData elements")
    provider = _one(system_node, "Provider")
    created = _one(system_node, "TimeCreated")
    system = {
        "Provider": provider.get("Name") if provider is not None else None,
        "EventID": _text(system_node, "EventID"),
        "Version": _text(system_node, "Version"),
        "Channel": _text(system_node, "Channel"),
        "Computer": _text(system_node, "Computer"),
        "EventRecordID": _text(system_node, "EventRecordID"),
        "SystemTime": created.get("SystemTime") if created is not None else None,
    }
    named = {}
    for data in data_node:
        if data.tag != NS + "Data":
            raise ValueError("EventData children must be named Data elements for this export contract")
        name = data.get("Name")
        if not name:
            raise ValueError("EventData/Data requires a Name attribute for this export contract")
        if name in named:
            raise ValueError(f"duplicate EventData name: {name}")
        named[name] = data.text
    payload = {name: named.get(name) for name in DATA_FIELDS}
    missing = [field for field, value in (
        ("destination_host", system["Computer"]),
        ("target_user", payload["TargetUserName"]),
        ("target_domain", payload["TargetDomainName"]),
        ("source_ip", payload["IpAddress"]),
        ("logon_type", payload["LogonType"]),
    ) if not _usable(value)]
    issues = []
    if missing:
        issues.append("missing critical correlation fields: " + ", ".join(missing))
    source_supported = system["Provider"] == PROVIDER and system["Channel"] == "Security"
    if not source_supported:
        issues.append("unsupported provider or channel")
    event_id = _integer(system["EventID"])
    if event_id not in (4624, 4625):
        issues.append("EventID is missing, invalid or outside this rule")
    logon_type = _integer(payload["LogonType"])
    if logon_type not in (3, 10):
        issues.append("LogonType is missing, invalid or outside this rule")
    if _integer(system["EventRecordID"]) is None:
        issues.append("EventRecordID is missing or invalid; an adapter cannot assign the planned identity")
    source_ip_valid = None
    if _usable(payload["IpAddress"]):
        try:
            if "%" in payload["IpAddress"]:
                raise ValueError("scoped addresses are outside schema 1.0")
            ipaddress.ip_address(payload["IpAddress"].strip())
            source_ip_valid = True
        except ValueError:
            source_ip_valid = False
            issues.append("IpAddress is invalid for schema 1.0")
    timestamp = _timestamp_check(system["SystemTime"])
    if not timestamp["representable_microseconds"]:
        issues.append("SystemTime cannot be imported exactly: " + timestamp["reason"])
    return {
        "xml_event_index": index, "system": system, "event_data": payload,
        "missing_correlation_fields": missing, "source_ip_valid": source_ip_valid,
        "rule_scope_compatible": source_supported and event_id in (4624, 4625) and logon_type in (3, 10),
        "timestamp": timestamp, "issues": issues,
    }


def inspect_windows_xml(path, *, max_bytes=MAX_BYTES, max_events=MAX_EVENTS):
    """Inspect raw selected fields without writing files or asserting authenticity.

    A completed inspection can contain quality, scope and precision issues. Input
    bounds and unsupported/ambiguous XML structures raise InputError.
    """
    for name, value in (("max_bytes", max_bytes), ("max_events", max_events)):
        if type(value) is not int or value <= 0:
            raise InputError(f"{name} must be a positive integer")
    path = Path(path)
    try:
        with path.open("rb") as handle:
            content = handle.read(max_bytes + 1)
    except (OSError, OverflowError) as exc:
        raise InputError(f"cannot read input {path}: {exc}") from exc
    if len(content) > max_bytes:
        raise InputError(f"input exceeds max_bytes={max_bytes}")
    try:
        xml = content.decode("utf-8-sig")
        declaration = re.match(r"\s*<\?xml\s+[^?]*\?>", xml)
        if declaration:
            encoding = re.search(r"encoding\s*=\s*['\"]([^'\"]+)['\"]", declaration.group(), re.I)
            if encoding and encoding.group(1).casefold() not in ("utf-8", "utf8"):
                raise ValueError("the selected export contract requires UTF-8")
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", xml, re.I):
            raise ValueError("DTD and entity declarations are outside the export contract")
        root = ET.fromstring(xml)
        if root.tag != "Events":
            raise ValueError("expected one unnamespaced Events container")
        if root.text and root.text.strip():
            raise ValueError("Events may contain only Event elements and whitespace")
        if len(root) > max_events:
            raise InputError(f"input exceeds max_events={max_events}")
        events = []
        for index, element in enumerate(root, start=1):
            try:
                if element.tail and element.tail.strip():
                    raise ValueError("Events may contain only Event elements and whitespace")
                events.append(_inspect_event(element, index))
            except ValueError as exc:
                raise ValueError(f"XML event {index}: {exc}") from exc
    except (ValueError, ET.ParseError, RecursionError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError(f"cannot inspect Windows Event XML: {exc}") from exc
    return {
        "input": {"path": str(path), "sha256": hashlib.sha256(content).hexdigest(),
                  "origin": "unverified-export"},
        "format": "windows-events-xml",
        "counts": {
            "input_events": len(events),
            "events_with_issues": sum(bool(event["issues"]) for event in events),
            "missing_correlation": sum(bool(event["missing_correlation_fields"]) for event in events),
            "outside_rule_scope": sum(not event["rule_scope_compatible"] for event in events),
            "incompatible_timestamps": sum(not event["timestamp"]["representable_microseconds"] for event in events),
        },
        "events": events,
        "limits": {"max_bytes": max_bytes, "max_events": max_events},
        "scope": "read-only field inspection; no normalization, event UID or lab-capture authenticity claim",
    }
