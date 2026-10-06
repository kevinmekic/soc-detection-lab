"""Small deterministic synthetic examples with separately authored expectations."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _event(uid: str, clock: str, user: str, ip: str, host: str,
           logon_type: int = 3, event_id: int = 4625) -> dict:
    return {
        "schema_version": "1.0", "event_uid": uid,
        "timestamp": f"2026-01-15T{clock}Z", "event_id": event_id,
        "provider": "Microsoft-Windows-Security-Auditing", "channel": "Security",
        "destination_host": host, "target_user": user, "target_domain": "LAB",
        "source_ip": ip, "logon_type": logon_type,
        "status": "0xC000006D" if event_id == 4625 else None,
        "sub_status": "0xC000006A" if event_id == 4625 else None,
        "data_origin": "synthetic",
    }


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def generate(output: Path, seed: int = 42) -> dict:
    """Write events, manual expected matches, and explicitly synthetic context.

    Seed changes input order and the negative example's failure spacing. The
    three reportable timelines remain fixed so analyst reports stay checkable.
    No labels or scenario names are added to event records.
    """
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    events = []
    groups = [
        (1, "analyst01", "192.0.2.10", "LAB-SERVER-01", 3,
         ["09:00:00", "09:00:20", "09:00:50", "09:01:30", "09:02:30", "09:03:00"]),
        (7, "analyst02", "192.0.2.20", "LAB-SERVER-02", 3,
         ["09:10:00", "09:10:20", "09:11:00", "09:11:40", "09:12:20", "09:13:00"]),
        (13, "analyst03", "198.51.100.30", "LAB-SERVER-03", 10,
         ["09:20:00", "09:20:15", "09:20:45", "09:21:15", "09:21:45", "09:22:00"]),
    ]
    for first, user, ip, host, logon_type, clocks in groups:
        for index, clock in enumerate(clocks):
            events.append(_event(f"demo-{first + index:03d}", clock, user, ip, host,
                                 logon_type, 4624 if index == 5 else 4625))
    base = datetime(2026, 1, 15, 9, 30, tzinfo=timezone.utc)
    for index, seconds in enumerate(sorted(rng.sample(range(0, 120), 4))):
        clock = (base + timedelta(seconds=seconds)).strftime("%H:%M:%S")
        events.append(_event(f"demo-{19 + index:03d}", clock, "analyst04",
                             "192.0.2.40", "LAB-SERVER-01"))
    events.append(_event("demo-023", "09:33:00", "analyst04", "192.0.2.40",
                         "LAB-SERVER-01", event_id=4624))
    events.append(dict(events[0]))
    rng.shuffle(events)
    events_path = output / "events.jsonl"
    events_path.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
                           encoding="utf-8")

    # Manually enumerated expectations: never derived by running the detector.
    expected = {
        "description": "Manually derived rule matches; these do not label attacks.",
        "expected_alerts": [
            {"success_uid": "demo-006", "failure_uids":
             ["demo-001", "demo-002", "demo-003", "demo-004", "demo-005"],
             "key": {"target_domain": "lab", "target_user": "analyst01",
                     "source_ip": "192.0.2.10", "destination_host": "lab-server-01",
                     "logon_type": 3}},
            {"success_uid": "demo-012", "failure_uids":
             ["demo-007", "demo-008", "demo-009", "demo-010", "demo-011"],
             "key": {"target_domain": "lab", "target_user": "analyst02",
                     "source_ip": "192.0.2.20", "destination_host": "lab-server-02",
                     "logon_type": 3}},
            {"success_uid": "demo-018", "failure_uids":
             ["demo-013", "demo-014", "demo-015", "demo-016", "demo-017"],
             "key": {"target_domain": "lab", "target_user": "analyst03",
                     "source_ip": "198.51.100.30", "destination_host": "lab-server-03",
                     "logon_type": 10}},
        ],
    }
    context = {
        "data_origin": "synthetic",
        "warning": "All context below is invented for this lab; no real contact, ticket, or endpoint evidence is claimed.",
        "cases": [
            {"case_id": "SYN-001", "success_uid": "demo-006",
             "analyst_assessment": "suspicious",
             "synthetic_context": [
                 "192.0.2.10 is assigned to LAB-CLIENT-01 in the fictional inventory.",
                 "The fictional lab access matrix does not assign LAB-CLIENT-01 to analyst01.",
                 "The fictional change calendar contains no scheduled activity matching this account, target, and time."],
             "unavailable_evidence": ["Actual user confirmation", "Endpoint follow-up", "Authenticated session actions"],
             "alternative": "A legitimate user may have used another shared client with stale saved credentials."},
            {"case_id": "SYN-002", "success_uid": "demo-012",
             "analyst_assessment": "legitimate",
             "synthetic_context": [
                 "A fictional approved lab password rotation precedes the observed failures.",
                 "A scheduled network-drive reconnect uses stale saved credentials for analyst02.",
                 "In this fictional scenario the lab operator corrects the cached credentials before the success."],
             "unavailable_evidence": ["Real change ticket", "Real operator contact", "Actual endpoint capture"],
             "alternative": "Without the supplied fictional context, unauthorized credential use cannot be excluded."},
            {"case_id": "SYN-003", "success_uid": "demo-018",
             "analyst_assessment": "unresolved",
             "synthetic_context": ["No additional corroborating context was supplied for this scenario."],
             "unavailable_evidence": ["Source ownership", "Authentication intent", "Endpoint follow-up", "Session actions"],
             "alternative": "A permitted remote user may have mistyped or reused a stale password."},
        ],
    }
    _write_json(output / "expected.json", expected)
    _write_json(output / "context.json", context)
    return {"output": str(output), "seed": seed, "events_written": len(events),
            "unique_events": 23, "expected_alerts": 3, "data_origin": "synthetic"}
