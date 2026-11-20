# AegisTrace Security Triage Report

> Defensive analysis only. Recommendations require an authorised human decision.

## Executive summary

- Events analysed: **20**
- Findings: **6**
- Correlated incidents: **3**
- Critical incidents: **2**
- High incidents: **1**

## Incident queue

### AT-AFAEC804 — Correlated activity: 3 detection signals

**Severity:** CRITICAL  |  **Risk score:** 99/100  |  **Confidence:** HIGH

**First seen:** 2026-11-14T11:32:00+00:00  
**Last seen:** 2026-11-14T11:40:00+00:00  
**Source IP:** Not present in source logs  
**Users:** svc-backup  
**Hosts:** DC-01

**Why it was raised**

- Event type: account&#95;created
- Event ID: 4720
- Host: DC-01
- Event type: group&#95;membership&#95;added
- Event ID: 4728
- Event type: audit&#95;log&#95;cleared
- Event ID: 1102

**MITRE ATT&CK references**

- T1136 — Create Account
- T1098 — Account Manipulation
- T1070.001 — Clear Windows Event Logs

**Recommended human investigation**

1. Validate the account owner, creator and business justification.
2. Review group membership, first sign-in and assigned privileges.
3. Disable an unauthorised account only through an approved identity workflow.
4. Verify the actor, target account, group and corresponding access request.
5. Review recent authentication and privilege use by the changed account.
6. Revert unauthorised membership through an approved administrator after evidence preservation.
7. Preserve remaining endpoint and centralised log sources before they rotate.
8. Check who performed the action and correlate with change tickets and endpoint telemetry.
9. Escalate unexplained log clearing; restore audit coverage using your documented procedure.

### AT-C0382A0E — Correlated activity: 2 detection signals

**Severity:** CRITICAL  |  **Risk score:** 97/100  |  **Confidence:** HIGH

**First seen:** 2026-11-14T10:10:00+00:00  
**Last seen:** 2026-11-14T10:16:00+00:00  
**Source IP:** 203.0.113.77  
**Users:** administrator  
**Hosts:** APP-02

**Why it was raised**

- 5 failed authentication events
- A successful authentication followed the failure burst
- Target account: administrator
- Event type: privileged&#95;login
- Event ID: 4672
- Host: APP-02

**MITRE ATT&CK references**

- T1110 — Brute Force
- T1078 — Valid Accounts

**Recommended human investigation**

1. Treat the successful sign-in as potentially compromised until the account owner confirms it.
2. Inspect the session, device, MFA result and subsequent privileged activity.
3. Revoke active sessions and rotate credentials through the identity platform if compromise is confirmed.
4. Verify that the privileged sign-in was expected and tied to an approved change or administrator.
5. Review the associated account, host, logon type and activity immediately after sign-in.
6. Escalate unexpected privileged access to the incident owner; do not disable accounts automatically.

### AT-A19662FB — Possible password-spraying activity

**Severity:** HIGH  |  **Risk score:** 67/100  |  **Confidence:** MEDIUM

**First seen:** 2026-11-14T09:00:00+00:00  
**Last seen:** 2026-11-14T09:07:00+00:00  
**Source IP:** 198.51.100.24  
**Users:** alex, lee, maria, nina, sam  
**Hosts:** DC-01

**Why it was raised**

- 8 failed authentication events
- 5 distinct target accounts
- Single source IP across the failure burst

**MITRE ATT&CK references**

- T1110.003 — Password Spraying

**Recommended human investigation**

1. Check whether the source is an approved scanner, VPN gateway or corporate egress address.
2. Review sign-in activity across the targeted accounts and verify MFA outcomes.
3. Use your approved identity controls to throttle or block the source only after validation.

## Safety statement

AegisTrace does not block IP addresses, disable accounts, terminate sessions or modify endpoints. Validate evidence and follow your organisation's approved incident-response process.