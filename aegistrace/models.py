"""Typed data models for AegisTrace's local-first triage pipeline."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: datetime | None
    event_type: str
    username: str = "unknown"
    source_ip: str = ""
    hostname: str = "unknown-host"
    event_id: str = ""
    source: str = "generic"
    raw_message: str = ""
    logon_type: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat() if self.timestamp else ""
        return data


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    description: str
    source_ip: str = ""
    users: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    event_indexes: list[int] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    mitre_id: str = ""
    mitre_name: str = ""
    recommendations: list[str] = field(default_factory=list)
    evidence_summary: list[str] = field(default_factory=list)


@dataclass
class Incident:
    incident_id: str
    title: str
    severity: str
    risk_score: int
    confidence: str
    source_ip: str
    users: list[str]
    hostnames: list[str]
    finding_ids: list[str]
    finding_titles: list[str]
    event_indexes: list[int]
    first_seen: str
    last_seen: str
    mitre: list[str]
    recommendations: list[str]
    evidence: list[str]


@dataclass
class TriageResult:
    events: list[SecurityEvent]
    findings: list[Finding]
    incidents: list[Incident]
    pipeline_steps: list[dict[str, str]]
    warnings: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for item in self.incidents if item.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for item in self.incidents if item.severity == "HIGH")
