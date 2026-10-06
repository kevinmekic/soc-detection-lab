"""Validation and a deterministic batch reference rule; no scenario labels are read."""

from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re

RULE_ID = "repeated-failed-logons-then-success"
RULE_VERSION = "1.0"
PROVIDER = "Microsoft-Windows-Security-Auditing"
FIELDS = (
    "schema_version", "event_uid", "timestamp", "event_id", "provider", "channel",
    "destination_host", "target_user", "target_domain", "source_ip", "logon_type",
    "status", "sub_status", "data_origin",
)
OPTIONAL_FIELDS = ("timestamp_raw", "record_id")
KEY_FIELDS = ("target_domain", "target_user", "source_ip", "destination_host", "logon_type")
MAX_BYTES = 10_485_760
MAX_EVENTS = 100_000
MAX_EVIDENCE_REFERENCES = 100_000


class InputError(ValueError):
    """Input cannot be safely analyzed under the requested policy."""

    def __init__(self, message, result=None):
        super().__init__(message)
        self.result = result


@dataclass(frozen=True)
class Config:
    threshold: int = 5
    window_seconds: int = 300
    logon_types: tuple[int, ...] = (3, 10)

    def __post_init__(self):
        for name in ("threshold", "window_seconds"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not self.logon_types or any(type(x) is not int or x not in (3, 10) for x in self.logon_types):
            raise ValueError("logon_types must be a nonempty subset of 3 and 10")
        object.__setattr__(self, "logon_types", tuple(sorted(set(self.logon_types))))

    def parameters(self):
        return {"threshold": self.threshold, "window_seconds": self.window_seconds,
                "logon_types": list(self.logon_types)}


@dataclass
class LoadResult:
    path: str
    sha256: str
    events: list = field(default_factory=list)
    counts: dict = field(default_factory=lambda: {
        "input_lines": 0, "processed": 0, "duplicates": 0, "excluded": 0, "errors": 0,
    })
    issues: list = field(default_factory=list)
    excluded_events: list = field(default_factory=list)
    data_origins: list = field(default_factory=list)

    def summary(self):
        return {"input": {"path": self.path, "sha256": self.sha256,
                          "data_origins": self.data_origins},
                "counts": self.counts, "issues": self.issues,
                "excluded_events": self.excluded_events}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def event_content(event):
    return {**{name: event[name] for name in FIELDS},
            **{name: event[name] for name in OPTIONAL_FIELDS if name in event}}


def candidate_alert_id(success, config):
    """Identity of a possible alert, independent of whether its pattern qualifies."""
    identity = {"rule_id": RULE_ID, "rule_version": RULE_VERSION,
                "parameters": config.parameters(), "success": event_content(success)}
    return hashlib.sha256(canonical(identity).encode("utf-8")).hexdigest()


def parse_time(value):
    if not isinstance(value, str) or "T" not in value:
        raise ValueError("timestamp must be an ISO 8601 date-time with explicit timezone")
    # datetime stores microseconds; reject finer precision instead of silently truncating.
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", value):
        raise ValueError("timestamp requires seconds, explicit timezone and at most 6 fractional digits")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise ValueError("timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def format_time(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def truncate_windows_time(value):
    """String-truncate a native time to microseconds, retaining no rounded digits."""
    if not isinstance(value, str):
        raise ValueError("timestamp_raw must be an ISO 8601 string")
    match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})", value)
    if not match:
        raise ValueError("timestamp_raw requires seconds and an explicit ISO 8601 timezone")
    fraction = match.group(2) or ""
    shortened = match.group(1) + ("." + fraction[:6] if fraction else "") + match.group(3)
    return format_time(parse_time(shortened))


def event_sort_key(event):
    record_id = event.get("record_id")
    # Legacy events retain UID ordering; supplied native IDs order equal microseconds.
    return (event["timestamp"], record_id is None, record_id if record_id is not None else 0,
            event["event_uid"])


def _text(value, name, *, folded=False):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string or null")
    value = value.strip()
    if value in ("", "-"):
        return None
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"{name} contains control characters")
    if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError(f"{name} contains an invalid Unicode surrogate")
    return value.casefold() if folded else value


def normalize(raw):
    if not isinstance(raw, dict):
        raise ValueError("each JSONL line must be an object")
    unknown = set(raw) - set(FIELDS) - set(OPTIONAL_FIELDS)
    if unknown:
        raise ValueError(f"unknown schema fields: {', '.join(sorted(unknown))}")
    if raw.get("schema_version") != "1.0":
        raise ValueError("schema_version must be '1.0'")
    event = {name: raw.get(name) for name in FIELDS}
    event["event_uid"] = _text(event["event_uid"], "event_uid")
    if not event["event_uid"]:
        raise ValueError("event_uid is required")
    event["timestamp"] = format_time(parse_time(event["timestamp"]))
    if "timestamp_raw" in raw:
        if truncate_windows_time(raw["timestamp_raw"]) != event["timestamp"]:
            raise ValueError("timestamp_raw truncated to microseconds must match timestamp")
        event["timestamp_raw"] = raw["timestamp_raw"]
    if "record_id" in raw:
        if type(raw["record_id"]) is not int or raw["record_id"] <= 0:
            raise ValueError("record_id must be a positive integer")
        event["record_id"] = raw["record_id"]
    for name in ("event_id", "logon_type"):
        if type(event[name]) is not int or event[name] <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if event["data_origin"] not in ("synthetic", "lab-captured"):
        raise ValueError("data_origin must be 'synthetic' or 'lab-captured'")
    for name in ("provider", "channel", "status", "sub_status"):
        event[name] = _text(event[name], name)
    for name in ("destination_host", "target_user", "target_domain"):
        event[name] = _text(event[name], name, folded=True)
    source = _text(event["source_ip"], "source_ip")
    quality = []
    if source:
        try:
            if "%" in source:
                raise ValueError("scoped addresses are not part of this schema")
            address = ipaddress.ip_address(source)
            source = str(address.ipv4_mapped or address) if isinstance(address, ipaddress.IPv6Address) else str(address)
        except ValueError:
            quality.append("source_ip is invalid")
            # Preserve invalid content for UID conflict detection; never correlate it.
    event["source_ip"] = source
    for name in ("destination_host", "target_user", "target_domain", "source_ip"):
        if not event[name]:
            quality.append(f"missing critical correlation field: {name}")
    if event["provider"] != PROVIDER or event["channel"] != "Security":
        quality.append("unsupported provider or channel")
    if event["event_id"] not in (4624, 4625):
        quality.append("event_id is outside this rule")
    if event["logon_type"] not in (3, 10):
        quality.append("logon_type is outside this rule")
    return event, quality


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON field: {key}")
        obj[key] = value
    return obj


def _reject_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def load_file(path, *, skip_invalid=False, max_bytes=MAX_BYTES, max_events=MAX_EVENTS):
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
    result = LoadResult(str(path), hashlib.sha256(content).hexdigest())
    # Split only on LF, so Unicode separators inside strings are not record boundaries.
    lines = content.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    if len(lines) > max_events:
        raise InputError(f"input exceeds max_events={max_events}")
    seen = {}
    invalid_uids = {}
    origins = set()
    conflicts = False
    for number, line in enumerate(lines, start=1):
        result.counts["input_lines"] += 1
        provenance = {"input_file": str(path), "line": number}
        raw = None
        try:
            raw = json.loads(line.decode("utf-8"), object_pairs_hook=_unique_object,
                             parse_constant=_reject_constant)
            event, quality = normalize(raw)
        except (ValueError, OverflowError, RecursionError) as exc:
            result.counts["errors"] += 1
            result.issues.append({"kind": "invalid_record", "provenance": provenance,
                                  "reason": str(exc), "raw_line": line.decode("utf-8", errors="replace")})
            # A parseable but invalid copy of a known UID must not let the skip
            # mode arbitrarily select the valid version. Its identity is disputed.
            invalid_uid = None
            if isinstance(raw, dict):
                try:
                    invalid_uid = _text(raw.get("event_uid"), "event_uid")
                except ValueError:
                    pass
            if invalid_uid:
                first = seen[invalid_uid][1] if invalid_uid in seen else invalid_uids.get(invalid_uid)
                if first:
                    conflicts = True
                    result.issues.append({"kind": "uid_conflict", "event_uid": invalid_uid,
                                          "provenance": provenance, "first_provenance": first,
                                          "reason": "repeated event_uid includes structurally invalid content"})
                invalid_uids.setdefault(invalid_uid, provenance)
            continue
        origins.add(event["data_origin"])
        serialized = canonical(event)
        uid = event["event_uid"]
        if uid in invalid_uids:
            conflicts = True
            result.counts["errors"] += 1
            result.issues.append({"kind": "uid_conflict", "event_uid": uid,
                                  "provenance": provenance, "first_provenance": invalid_uids[uid],
                                  "reason": "event_uid was already seen with structurally invalid content", "raw": raw})
            continue
        if uid in seen:
            if seen[uid][0] == serialized:
                result.counts["duplicates"] += 1
                result.issues.append({"kind": "duplicate", "event_uid": uid,
                                      "provenance": provenance, "first_provenance": seen[uid][1],
                                      "reason": "identical normalized event ignored"})
            else:
                conflicts = True
                result.counts["errors"] += 1
                result.issues.append({"kind": "uid_conflict", "event_uid": uid,
                                      "provenance": provenance, "first_provenance": seen[uid][1],
                                      "reason": "same event_uid carries conflicting normalized content", "raw": raw})
            continue
        seen[uid] = (serialized, provenance)
        event["provenance"] = provenance
        if quality:
            result.counts["excluded"] += 1
            result.excluded_events.append({"event": event, "raw": raw, "reasons": quality})
            result.issues.append({"kind": "excluded", "event_uid": uid, "provenance": provenance,
                                  "reason": "; ".join(quality)})
        else:
            result.events.append(event)
            result.counts["processed"] += 1
    result.events.sort(key=event_sort_key)
    result.data_origins = sorted(origins)
    if conflicts or (result.counts["errors"] and not skip_invalid):
        message = "conflicting event identities; analysis aborted" if conflicts else "invalid records; use --skip-invalid to explicitly omit them"
        raise InputError(message, result.summary())
    return result


def correlation_key(event):
    return tuple(event[name] for name in KEY_FIELDS)


def evidence(event):
    return {"event_uid": event["event_uid"], "timestamp": event["timestamp"],
            "provenance": event["provenance"],
            **{name: event[name] for name in OPTIONAL_FIELDS if name in event}}


def detect(events, config):
    failures = defaultdict(list)
    times = defaultdict(list)
    for event in events:
        if event["event_id"] == 4625 and event["logon_type"] in config.logon_types:
            key = correlation_key(event)
            failures[key].append(event)
            times[key].append(parse_time(event["timestamp"]))
    alerts = []
    evidence_references = 0
    for success in events:
        if success["event_id"] != 4624 or success["logon_type"] not in config.logon_types:
            continue
        key = correlation_key(success)
        t = parse_time(success["timestamp"])
        try:
            start = t - timedelta(seconds=config.window_seconds)
        except OverflowError:
            start = datetime.min.replace(tzinfo=timezone.utc)
        left = bisect_left(times[key], start)
        right = bisect_left(times[key], t)
        matching = failures[key][left:right]
        if "record_id" in success:
            tied = failures[key][right:bisect_right(times[key], t)]
            matching += [event for event in tied if "record_id" in event
                         and event["record_id"] < success["record_id"]]
        if len(matching) < config.threshold:
            continue
        evidence_references += len(matching) + 1
        if evidence_references > MAX_EVIDENCE_REFERENCES:
            raise InputError(f"analysis exceeds {MAX_EVIDENCE_REFERENCES} total evidence references; reduce the batch size")
        rationale = f"{len(matching)} matching failures in [{format_time(start)}, {success['timestamp']}) precede this success; this pattern warrants triage but does not prove compromise."
        if "record_id" in success:
            rationale = f"{len(matching)} matching failures from {format_time(start)} precede this success at {success['timestamp']}; equal microseconds use lower record_id as the native-event tiebreaker; this pattern warrants triage but does not prove compromise."
        alerts.append({
            "alert_id": candidate_alert_id(success, config),
            "key": dict(zip(KEY_FIELDS, key)), "failure_count": len(matching),
            "failures": [evidence(event) for event in matching], "success": evidence(success),
            "pattern_start": matching[0]["timestamp"], "pattern_end": success["timestamp"],
            "priority": "medium",
            "rationale": rationale,
            "open_questions": ["Was this activity expected and authorized?", "Were stored credentials recently changed?",
                               "What do endpoint, authentication and change records show?"],
        })
    return alerts


def analyze_loaded(loaded, config):
    # Configuration exclusions remain explicit and preserve their evidence.
    included = []
    for event in loaded.events:
        if event["logon_type"] in config.logon_types:
            included.append(event)
        else:
            loaded.counts["processed"] -= 1
            loaded.counts["excluded"] += 1
            reason = "logon_type excluded by effective configuration"
            loaded.excluded_events.append({"event": event, "raw": event_content(event), "reasons": [reason]})
            loaded.issues.append({"kind": "excluded", "event_uid": event["event_uid"],
                                  "provenance": event["provenance"], "reason": reason})
    loaded.events = included
    return {"rule": {"id": RULE_ID, "version": RULE_VERSION, "parameters": config.parameters()},
            **loaded.summary(), "alerts": detect(included, config)}


def analyze_file(path, config=Config(), **kwargs):
    return analyze_loaded(load_file(path, **kwargs), config)
