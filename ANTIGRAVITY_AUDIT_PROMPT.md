# Google Antigravity audit prompt

Open this repository in Google Antigravity and use Planning Mode (`/plan`) before asking it to modify anything. Paste the prompt below. Review every proposed diff; do not accept changes that weaken the privacy boundary or introduce automatic remediation.

---

You are auditing AegisTrace, a defensive cybersecurity triage prototype for PromptWars X Agent X 2.0 PS06.

First inspect the entire repository without changing files. Produce a short plan and a findings list covering:

1. Correctness of Windows CSV / JSON / Linux auth.log parsing.
2. Detection-rule edge cases, time-window boundaries, missing timestamps and incident correlation.
3. Security of file upload handling, API-key handling, data privacy and dependency choices.
4. Unit-test coverage and reproducible commands.
5. Accessibility and usability of the Streamlit interface.
6. Alignment with PS06: log analysis, correlation, suspicious-activity detection and safe remediation recommendations.

Then, only after the plan is reviewed, implement minimal fixes that are supported by tests. Do not add offensive capabilities, shell execution, arbitrary file access, background telemetry, automatic IP blocking, account disabling, session termination, endpoint changes or network response APIs. Do not send raw logs or identifiers to Gemini. Preserve the synthetic-only demo data. Add or update tests for every changed detection or parser behavior. Run `python -m unittest discover -s tests -v` and report the exact result; never claim tests pass unless they ran successfully.

Keep the repository small, with a single `main` branch. At the end, report changed files, test output, remaining limitations and any setup steps that still require the participant.
