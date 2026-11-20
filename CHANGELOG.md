# Changelog

## 1.0.0 — 15 November 2026

- Added bounded CSV, JSON, JSONL and Linux authentication-log ingestion.
- Added transparent Windows/Linux authentication and account-management detections.
- Added source/host and time-window incident correlation, prioritisation and investigation playbooks.
- Added optional privacy-minimised Gemini narrative.
- Added Markdown, JSON and CSV exports; CSV formula-prefix neutralisation and Markdown escaping.
- Added synthetic datasets, unit tests, CI workflow, threat model and demo script.

## Cloud Run submission readiness

- Added a non-root Dockerfile that binds Streamlit to Cloud Run's `PORT`.
- Added `.dockerignore` to keep the deployment context small and exclude local secrets/cache.
- Added Cloud Run deployment and smoke-test instructions for `asia-south1`.

