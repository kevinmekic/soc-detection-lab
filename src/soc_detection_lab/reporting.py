"""Plain JSON and escaped Markdown output for a human to inspect."""

import html
import json
import os
from pathlib import Path
import tempfile


def write_text(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            temporary = handle.name
            handle.write(content)
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    write_text(path, json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n")


def escape(value):
    text = html.escape(str(value), quote=True).replace("\\", "\\\\")
    for character in "|`*_[]()#!":
        text = text.replace(character, "\\" + character)
    return text.replace("\r", " ").replace("\n", " ")


def markdown(result):
    rule = result["rule"]
    counts = result["counts"]
    lines = ["# Logon pattern analysis", "", f"Detected **{len(result['alerts'])}** rule matches. "
             "These are preliminary investigation leads, not confirmed attacks.", "",
             f"Input: {escape(result['input']['path'])}", "",
             f"SHA-256: `{result['input']['sha256']}`", "",
             f"Origin: {escape(', '.join(result['input']['data_origins']) or 'no accepted records')}", "",
             f"Rule: `{rule['id']}` version `{rule['version']}`. Parameters: `{json.dumps(rule['parameters'], sort_keys=True)}`.", "",
             "| Input lines | Processed | Duplicate | Excluded | Invalid/conflicting |",
             "| --- | --- | --- | --- | --- |",
             f"| {counts['input_lines']} | {counts['processed']} | {counts['duplicates']} | {counts['excluded']} | {counts['errors']} |", ""]
    for alert in result["alerts"]:
        lines.extend([f"## Alert {alert['alert_id']}", "", "Preliminary priority: **medium**. "
                      "A success following repeated failures warrants triage; neither account impact nor malicious intent is established.", "",
                      "Key: " + "; ".join(f"{name}={escape(value)}" for name, value in alert["key"].items()), "",
                      escape(alert["rationale"]), "", "### Observed evidence", ""])
        evidence = alert["failures"] + [alert["success"]]
        native = any("record_id" in event or "timestamp_raw" in event for event in evidence)
        if native:
            lines.extend(["| UTC time | Record ID | Original SystemTime | Event UID | Event | Input line |",
                          "| --- | --- | --- | --- | --- | --- |"])
        else:
            lines.extend(["| UTC time | Event UID | Event | Input line |", "| --- | --- | --- | --- |"])
        for event in evidence:
            kind = "4624 success" if event is alert["success"] else "4625 failure"
            metadata = (f"{escape(event.get('record_id', ''))} | {escape(event.get('timestamp_raw', ''))} | "
                        if native else "")
            lines.append(f"| {escape(event['timestamp'])} | {metadata}{escape(event['event_uid'])} | {kind} | "
                         f"{escape(event['provenance']['input_file'])}:{event['provenance']['line']} |")
        lines.extend(["", "### Suggested investigation (not confirmed observations)", ""])
        lines.extend(f"- {escape(question)}" for question in alert["open_questions"])
        lines.extend(["- Review authorization, credential changes and endpoint records before deciding on escalation.",
                      "- Consider stale credentials or user mistakes as benign explanations. No response action is executed.", ""])
    lines.extend(["## Data quality", ""])
    if result["issues"]:
        lines.extend(["| Kind | Input line | Explanation |", "| --- | --- | --- |"])
        for issue in result["issues"]:
            lines.append(f"| {escape(issue['kind'])} | {issue['provenance']['line']} | {escape(issue['reason'])} |")
    else:
        lines.append("No data quality issues were observed in this input.")
    ordering_limit = "The lower time boundary is inclusive; the success timestamp is excluded."
    if any("record_id" in alert["success"] for alert in result["alerts"]):
        ordering_limit = ("The lower time boundary is inclusive; failures in the success microsecond "
                          "count only when both events have record IDs and the failures have lower record IDs.")
    lines.extend(["", "## Limits", "",
                  "Only equal domain, user, source IP, destination host and logon type correlate. "
                  + ordering_limit + " Previous successes do not reset the window.", "",
                  "Missing logs, distributed sources, slow attempts, password spraying and other logon types can evade this rule. "
                  "Legitimate retries can trigger it. This bounded in-memory batch result is not a streaming SIEM or proof of compromise. "
                  "Synthetic data and Python verification do not validate Windows ingestion or SPL execution.", ""])
    return "\n".join(lines)
