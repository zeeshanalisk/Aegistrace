"""Optional Gemini narrative layer. Sends only anonymised aggregate metadata."""
from __future__ import annotations

import os

from .models import TriageResult


def _masked_payload(result: TriageResult) -> str:
    """Build a privacy-minimised summary: no raw messages, usernames, IPs or hostnames."""
    counts = {level: sum(1 for item in result.incidents if item.severity == level)
              for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    lines = [f"Event count: {len(result.events)}", f"Incident count: {len(result.incidents)}", f"Severity counts: {counts}"]
    for number, incident in enumerate(result.incidents, start=1):
        lines.append(
            f"Incident {number}: severity={incident.severity}; risk_score={incident.risk_score}; "
            f"confidence={incident.confidence}; detections={','.join(incident.finding_ids)}; "
            f"evidence_items={len(incident.event_indexes)}; MITRE={','.join(item.split(' — ')[0] for item in incident.mitre)}"
        )
    return "\n".join(lines)


def generate_ai_summary(result: TriageResult, api_key: str | None = None, model: str | None = None) -> str:
    key = api_key or os.getenv("GEMINI_API_KEY", "")
    if not key:
        raise RuntimeError("No Gemini API key found. Set GEMINI_API_KEY or enter a key in the app sidebar.")
    try:
        from google import genai
    except ImportError as exc:
        raise RuntimeError("Install the optional AI dependency with: pip install -r requirements-ai.txt") from exc

    model_name = model or os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    prompt = f"""You are a cautious SOC reporting assistant. Analyse only the aggregate, anonymised incident metadata below.
Do not invent events, identities, root causes, geolocation, attribution or certainty. Do not recommend automatic blocking or account disabling.
Write a concise executive summary with: (1) what the observed detections establish, (2) what remains unverified, and (3) the top three human investigation priorities. Explicitly distinguish observed evidence from hypotheses.

ANONYMISED METADATA:
{_masked_payload(result)}
"""
    client = genai.Client(api_key=key)
    response = client.models.generate_content(model=model_name, contents=prompt)
    text = (response.text or "").strip()
    if not text:
        raise RuntimeError("Gemini returned an empty response. The local triage report is still available.")
    return text
