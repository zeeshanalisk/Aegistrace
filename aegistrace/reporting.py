"""Evidence-first export helpers."""
from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import asdict
from typing import Any

from .models import TriageResult


def safe_csv_cell(value: Any) -> str:
    """Neutralise spreadsheet formula prefixes in text exported to CSV."""
    text = str(value if value is not None else "")
    probe = text.lstrip()
    if probe.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _markdown_text(value: Any) -> str:
    """Escape untrusted log-derived values before embedding them in Markdown."""
    text = str(value if value is not None else "").replace("\r", " ").replace("\n", " ")
    text = html.escape(text, quote=True)
    for char, entity in (("[", "&#91;"), ("]", "&#93;"), ("`", "&#96;"), ("*", "&#42;"), ("_", "&#95;"), ("|", "&#124;")):
        text = text.replace(char, entity)
    return text


def report_dict(result: TriageResult) -> dict[str, Any]:
    return {
        "product": "AegisTrace",
        "report_type": "defensive_security_triage",
        "summary": {
            "events_analysed": len(result.events),
            "findings": len(result.findings),
            "incidents": len(result.incidents),
            "critical_incidents": result.critical_count,
            "high_incidents": result.high_count,
        },
        "incidents": [asdict(incident) for incident in result.incidents],
        "findings": [asdict(finding) for finding in result.findings],
        "events": [event.to_dict() for event in result.events],
        "pipeline": result.pipeline_steps,
        "warnings": result.warnings,
        "safety_note": "Recommendations are advisory. No remediation action was executed.",
    }


def to_json(result: TriageResult) -> str:
    return json.dumps(report_dict(result), indent=2, ensure_ascii=False)


def to_markdown(result: TriageResult) -> str:
    lines = [
        "# AegisTrace Security Triage Report", "",
        "> Defensive analysis only. Recommendations require an authorised human decision.", "",
        "## Executive summary", "",
        f"- Events analysed: **{len(result.events)}**",
        f"- Findings: **{len(result.findings)}**",
        f"- Correlated incidents: **{len(result.incidents)}**",
        f"- Critical incidents: **{result.critical_count}**",
        f"- High incidents: **{result.high_count}**", "",
        "## Incident queue", "",
    ]
    if not result.incidents:
        lines.append("No supported detection rules fired for this dataset.")
    for incident in result.incidents:
        lines.extend([
            f"### {incident.incident_id} — {incident.title}", "",
            f"**Severity:** {incident.severity}  |  **Risk score:** {incident.risk_score}/100  |  **Confidence:** {incident.confidence}", "",
            f"**First seen:** {incident.first_seen or 'Not available'}  ",
            f"**Last seen:** {incident.last_seen or 'Not available'}  ",
            f"**Source IP:** {_markdown_text(incident.source_ip or 'Not present in source logs')}  ",
            f"**Users:** {_markdown_text(', '.join(incident.users) or 'Not identified')}  ",
            f"**Hosts:** {_markdown_text(', '.join(incident.hostnames) or 'Not identified')}", "",
            "**Why it was raised**", "",
        ])
        lines.extend([f"- {_markdown_text(item)}" for item in incident.evidence] or ["- Evidence summary unavailable."])
        if incident.mitre:
            lines.extend(["", "**MITRE ATT&CK references**", ""])
            lines.extend([f"- {item}" for item in incident.mitre])
        lines.extend(["", "**Recommended human investigation**", ""])
        lines.extend([f"{i}. {step}" for i, step in enumerate(incident.recommendations, 1)])
        lines.append("")
    if result.warnings:
        lines.extend(["## Input warnings", ""])
        lines.extend([f"- {warning}" for warning in result.warnings])
        lines.append("")
    lines.extend(["## Safety statement", "", "AegisTrace does not block IP addresses, disable accounts, terminate sessions or modify endpoints. Validate evidence and follow your organisation's approved incident-response process."])
    return "\n".join(lines)


def to_findings_csv(result: TriageResult) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["incident_id", "severity", "risk_score", "confidence", "source_ip", "users", "hosts", "detections", "first_seen", "last_seen", "evidence"])
    for incident in result.incidents:
        writer.writerow([safe_csv_cell(incident.incident_id), safe_csv_cell(incident.severity), incident.risk_score, safe_csv_cell(incident.confidence),
                         safe_csv_cell(incident.source_ip), safe_csv_cell(";".join(incident.users)), safe_csv_cell(";".join(incident.hostnames)),
                         safe_csv_cell(";".join(incident.finding_ids)), safe_csv_cell(incident.first_seen), safe_csv_cell(incident.last_seen),
                         safe_csv_cell(";".join(incident.evidence))])
    return output.getvalue()
