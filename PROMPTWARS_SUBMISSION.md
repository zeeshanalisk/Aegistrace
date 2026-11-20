# Hack2Skill submission text

## Challenge

**PS06: AI-Powered Cybersecurity Triage**

## Project title

**AegisTrace — AI-Powered Security Operations & Threat Triage Agent**

## Short description

AegisTrace is a local-first defensive security triage agent that analyses Windows security-event exports and Linux authentication logs. It detects brute-force attempts, password spraying, successful logins following repeated failures, privileged access, security-group changes, new account creation and audit-log clearing. It correlates related evidence into incidents, prioritises risk, maps detections to MITRE ATT&CK and recommends safe, human-reviewed investigation steps. Its optional Gemini narrative uses only anonymised aggregate incident metadata. The core detection engine is deterministic, explainable, testable and works without an API key. No remediation action is executed automatically.

## Problem solved

Small IT teams may have authentication and account-management events spread across log files without a dedicated SOC. AegisTrace reduces manual triage by transforming raw records into prioritised incidents with the underlying evidence, confidence, mapped technique and next investigation steps visible in one place.

## AI and agent approach

A multi-stage workflow performs bounded ingestion, event normalisation, rule-based suspicious-activity detection, time-window correlation, incident prioritisation, evidence presentation and playbook generation. The deterministic engine is the source of truth. An optional Google Gemini integration generates an executive narrative from anonymised aggregate metadata only, after explicit operator consent. It cannot alter findings or execute response actions.

## Innovation / differentiator

- Local-first core with no external API dependency.
- Evidence-first incidents instead of unexplained alert scores.
- Windows and Linux log ingestion in one small prototype.
- Explicit human oversight and safe remediation guidance.
- Optional privacy-minimised AI narrative.
- Unit tests for parsers, detection thresholds, correlation and report exports.