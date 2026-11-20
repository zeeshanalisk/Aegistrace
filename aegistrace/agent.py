"""Orchestrated local triage agent: detect, correlate, prioritise, recommend."""
from __future__ import annotations

from .models import TriageResult, SecurityEvent
from .rules import correlate_findings, detect_findings


def run_triage(events: list[SecurityEvent], warnings: list[str] | None = None) -> TriageResult:
    if not events:
        raise ValueError("At least one security event is required for triage.")
    steps = [
        {"name": "Ingest & normalise", "status": "Complete", "detail": f"{len(events):,} event records accepted"},
    ]
    findings = detect_findings(events)
    steps.append({"name": "Detect suspicious patterns", "status": "Complete", "detail": f"{len(findings):,} rule findings generated"})
    incidents = correlate_findings(events, findings)
    steps.append({"name": "Correlate related evidence", "status": "Complete", "detail": f"{len(incidents):,} incidents grouped"})
    steps.append({"name": "Prioritise & prepare playbooks", "status": "Complete", "detail": "Severity, confidence and human-reviewed response steps assigned"})
    steps.append({"name": "Human oversight", "status": "Required", "detail": "No account, host or network action is executed"})
    return TriageResult(events, findings, incidents, steps, warnings or [])
