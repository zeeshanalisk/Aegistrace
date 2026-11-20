"""Transparent detection rules and incident correlation."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from hashlib import sha256

from .models import Finding, Incident, SecurityEvent

SEVERITY_WEIGHT = {"LOW": 15, "MEDIUM": 35, "HIGH": 65, "CRITICAL": 90}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

PLAYBOOKS = {
    "AUTH_BRUTE_FORCE": [
        "Confirm whether the target account owner recognizes the activity.",
        "Review MFA, VPN and identity-provider logs for the same account and time window.",
        "Apply rate-limiting or temporary lockout controls through your approved identity workflow if activity is confirmed.",
    ],
    "AUTH_PASSWORD_SPRAY": [
        "Check whether the source is an approved scanner, VPN gateway or corporate egress address.",
        "Review sign-in activity across the targeted accounts and verify MFA outcomes.",
        "Use your approved identity controls to throttle or block the source only after validation.",
    ],
    "AUTH_SUCCESS_AFTER_FAILURE": [
        "Treat the successful sign-in as potentially compromised until the account owner confirms it.",
        "Inspect the session, device, MFA result and subsequent privileged activity.",
        "Revoke active sessions and rotate credentials through the identity platform if compromise is confirmed.",
    ],
    "PRIVILEGED_LOGIN": [
        "Verify that the privileged sign-in was expected and tied to an approved change or administrator.",
        "Review the associated account, host, logon type and activity immediately after sign-in.",
        "Escalate unexpected privileged access to the incident owner; do not disable accounts automatically.",
    ],
    "AUDIT_LOG_CLEARED": [
        "Preserve remaining endpoint and centralised log sources before they rotate.",
        "Check who performed the action and correlate with change tickets and endpoint telemetry.",
        "Escalate unexplained log clearing; restore audit coverage using your documented procedure.",
    ],
    "GROUP_MEMBERSHIP_CHANGE": [
        "Verify the actor, target account, group and corresponding access request.",
        "Review recent authentication and privilege use by the changed account.",
        "Revert unauthorised membership through an approved administrator after evidence preservation.",
    ],
    "ACCOUNT_CREATED": [
        "Validate the account owner, creator and business justification.",
        "Review group membership, first sign-in and assigned privileges.",
        "Disable an unauthorised account only through an approved identity workflow.",
    ],
    "ACCOUNT_LOCKOUT_BURST": [
        "Check whether the lockouts share an expected application, service account or stale credential source.",
        "Correlate identity-provider, VPN and endpoint events for the affected accounts.",
        "Resolve the source of repeated failures before restoring accounts under policy.",
    ],
}

MITRE = {
    "AUTH_BRUTE_FORCE": ("T1110.001", "Password Guessing"),
    "AUTH_PASSWORD_SPRAY": ("T1110.003", "Password Spraying"),
    "AUTH_SUCCESS_AFTER_FAILURE": ("T1110", "Brute Force"),
    "PRIVILEGED_LOGIN": ("T1078", "Valid Accounts"),
    "AUDIT_LOG_CLEARED": ("T1070.001", "Clear Windows Event Logs"),
    "GROUP_MEMBERSHIP_CHANGE": ("T1098", "Account Manipulation"),
    "ACCOUNT_CREATED": ("T1136", "Create Account"),
    "ACCOUNT_LOCKOUT_BURST": ("T1110", "Brute Force"),
}


def _fmt(dt: datetime | None) -> str:
    return dt.isoformat() if dt else ""


def _first_window_at_threshold(
    events: list[SecurityEvent], indexes: list[int], seconds: int,
    minimum_events: int, minimum_distinct_users: int = 0,
) -> list[int] | None:
    """Find the first qualifying sliding window in O(n log n) time and O(n) memory."""
    valid = [i for i in indexes if events[i].timestamp is not None]
    valid.sort(key=lambda i: events[i].timestamp)
    left = 0
    user_counts: dict[str, int] = defaultdict(int)
    distinct_users = 0
    for right, event_index in enumerate(valid):
        user = events[event_index].username
        if user and user != "unknown":
            if user_counts[user] == 0:
                distinct_users += 1
            user_counts[user] += 1
        while left <= right and (events[valid[right]].timestamp - events[valid[left]].timestamp).total_seconds() > seconds:
            old_user = events[valid[left]].username
            if old_user and old_user != "unknown":
                user_counts[old_user] -= 1
                if user_counts[old_user] == 0:
                    distinct_users -= 1
            left += 1
        if right - left + 1 >= minimum_events and distinct_users >= minimum_distinct_users:
            return valid[left:right + 1]
    return None


def _finding(rule_id: str, title: str, severity: str, confidence: str, description: str,
             events: list[SecurityEvent], indexes: list[int], source_ip: str = "", users: list[str] | None = None,
             hostnames: list[str] | None = None, evidence: list[str] | None = None) -> Finding:
    stamps = [events[i].timestamp for i in indexes if events[i].timestamp is not None]
    mitre_id, mitre_name = MITRE.get(rule_id, ("", ""))
    return Finding(
        rule_id=rule_id, title=title, severity=severity, confidence=confidence,
        description=description, source_ip=source_ip,
        users=sorted({u for u in (users or []) if u and u != "unknown"}),
        hostnames=sorted({h for h in (hostnames or []) if h and h != "unknown-host"}),
        event_indexes=sorted(set(indexes)), first_seen=_fmt(min(stamps) if stamps else None),
        last_seen=_fmt(max(stamps) if stamps else None), mitre_id=mitre_id, mitre_name=mitre_name,
        recommendations=PLAYBOOKS[rule_id], evidence_summary=evidence or [],
    )


def detect_findings(events: list[SecurityEvent]) -> list[Finding]:
    findings: list[Finding] = []
    by_ip_user: dict[tuple[str, str], list[int]] = defaultdict(list)
    by_ip: dict[str, list[int]] = defaultdict(list)
    by_host: dict[str, list[int]] = defaultdict(list)

    for idx, event in enumerate(events):
        if event.source_ip:
            by_ip[event.source_ip].append(idx)
            by_ip_user[(event.source_ip, event.username)].append(idx)
        if event.hostname and event.hostname != "unknown-host":
            by_host[event.hostname].append(idx)

    # One source repeatedly failing against one account: sliding 10-minute window.
    for (ip, user), indexes in by_ip_user.items():
        failed_indexes = [i for i in indexes if events[i].event_type == "login_failed"]
        success_indexes = [i for i in indexes if events[i].event_type == "login_success"]
        if not failed_indexes:
            continue
        window = _first_window_at_threshold(events, failed_indexes, 600, minimum_events=5)
        if window:
            last = events[window[-1]].timestamp
            success_after = [i for i in success_indexes if events[i].timestamp and last and timedelta(0) <= events[i].timestamp - last <= timedelta(minutes=15)]
            if success_after:
                combined = window + [success_after[0]]
                findings.append(_finding(
                    "AUTH_SUCCESS_AFTER_FAILURE", "Successful login after repeated failures", "CRITICAL", "HIGH",
                    f"{len(window)} failed sign-ins against '{user}' from {ip} were followed by a successful sign-in within 15 minutes. This sequence warrants immediate human investigation.",
                    events, combined, ip, [user], [events[i].hostname for i in combined],
                    [f"{len(window)} failed authentication events", "A successful authentication followed the failure burst", f"Target account: {user}"]
                ))
            else:
                findings.append(_finding(
                    "AUTH_BRUTE_FORCE", "Repeated authentication failures", "HIGH", "HIGH",
                    f"{len(window)} failed sign-ins against '{user}' from {ip} occurred inside a 10-minute window.",
                    events, window, ip, [user], [events[i].hostname for i in window],
                    [f"{len(window)} failed authentication events", f"Target account: {user}"]
                ))

    # Password spray: one source targets multiple accounts in 15 minutes.
    for ip, indexes in by_ip.items():
        failed = [i for i in indexes if events[i].event_type == "login_failed"]
        window = _first_window_at_threshold(events, failed, 900, minimum_events=8, minimum_distinct_users=5)
        if window:
            users = sorted({events[i].username for i in window if events[i].username != "unknown"})
            findings.append(_finding(
                "AUTH_PASSWORD_SPRAY", "Possible password-spraying activity", "HIGH", "MEDIUM",
                f"{len(window)} failed sign-ins from {ip} targeted {len(users)} distinct accounts within 15 minutes.",
                events, window, ip, users, [events[i].hostname for i in window],
                [f"{len(window)} failed authentication events", f"{len(users)} distinct target accounts", "Single source IP across the failure burst"]
            ))

    # Sensitive event IDs and endpoint actions.
    simple_rules = {
        "privileged_login": ("PRIVILEGED_LOGIN", "Privileged logon observed", "MEDIUM", "MEDIUM", "A privileged logon event was recorded. This is context for review, not proof of misuse."),
        "privileged_command": ("PRIVILEGED_LOGIN", "Privileged command observed", "MEDIUM", "MEDIUM", "A sudo command was recorded in the authentication log. Validate it against the change record and account owner."),
        "audit_log_cleared": ("AUDIT_LOG_CLEARED", "Security audit log cleared", "CRITICAL", "HIGH", "A security audit log-clearing event was recorded."),
        "group_membership_added": ("GROUP_MEMBERSHIP_CHANGE", "Security group membership changed", "HIGH", "HIGH", "An account was added to a security-enabled group."),
        "account_created": ("ACCOUNT_CREATED", "New account created", "MEDIUM", "MEDIUM", "A new local or domain account creation event was recorded."),
    }
    seen_simple: set[tuple[str, int]] = set()
    for idx, event in enumerate(events):
        rule = simple_rules.get(event.event_type)
        if not rule:
            continue
        rule_id, title, severity, confidence, description = rule
        key = (rule_id, idx)
        if key in seen_simple:
            continue
        findings.append(_finding(rule_id, title, severity, confidence, description,
                                 events, [idx], event.source_ip, [event.username], [event.hostname],
                                 [f"Event type: {event.event_type}", f"Event ID: {event.event_id or 'not supplied'}", f"Host: {event.hostname}"]))
        seen_simple.add(key)

    # Repeated account lockouts on a host can point to a shared bad-credential source.
    for host, indexes in by_host.items():
        locked = [i for i in indexes if events[i].event_type == "account_locked"]
        window = _first_window_at_threshold(events, locked, 600, minimum_events=3)
        if window:
            unique_users = {events[i].username for i in window if events[i].username != "unknown"}
            findings.append(_finding(
                "ACCOUNT_LOCKOUT_BURST", "Multiple account lockouts", "MEDIUM", "MEDIUM",
                f"{len(window)} account-lockout events occurred on {host} within 10 minutes.",
                events, window, "", list(unique_users), [host],
                [f"{len(window)} account-lockout events", f"Affected accounts: {len(unique_users)}"]
            ))

    # De-duplicate findings by rule, source and account/time range.
    unique: dict[tuple[str, str, tuple[str, ...], str], Finding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.source_ip, tuple(finding.users), finding.first_seen[:16])
        existing = unique.get(key)
        if existing is None or len(finding.event_indexes) > len(existing.event_indexes):
            unique[key] = finding
    return sorted(unique.values(), key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.first_seen, f.title))


def correlate_findings(events: list[SecurityEvent], findings: list[Finding]) -> list[Incident]:
    """Merge findings that share an IP/host and occur within a 30-minute window."""
    if not findings:
        return []
    ordered = sorted(findings, key=lambda f: f.first_seen or f.last_seen)
    groups: list[list[Finding]] = []
    last_group_for_identity: dict[str, int] = {}
    for finding in ordered:
        known_host = finding.hostnames[0] if finding.hostnames else ""
        identity = finding.source_ip or ("host:" + known_host if known_host else f"isolated:{finding.rule_id}:{finding.first_seen}")
        f_start = datetime.fromisoformat(finding.first_seen) if finding.first_seen else None
        previous_group_index = last_group_for_identity.get(identity)
        placed = False
        if previous_group_index is not None and f_start:
            previous = groups[previous_group_index][-1]
            p_end = datetime.fromisoformat(previous.last_seen) if previous.last_seen else None
            if p_end and abs((f_start - p_end).total_seconds()) <= 1800:
                groups[previous_group_index].append(finding)
                placed = True
        if not placed:
            groups.append([finding])
            last_group_for_identity[identity] = len(groups) - 1

    incidents: list[Incident] = []
    for group in groups:
        indexes = sorted({idx for finding in group for idx in finding.event_indexes})
        users = sorted({user for finding in group for user in finding.users})
        hosts = sorted({host for finding in group for host in finding.hostnames})
        ips = sorted({finding.source_ip for finding in group if finding.source_ip})
        severity = min((finding.severity for finding in group), key=lambda value: SEVERITY_ORDER.get(value, 9))
        risk = min(99, SEVERITY_WEIGHT.get(severity, 20) + min(9, (len(group) - 1) * 5) + min(10, len(indexes) // 3))
        confidence = "HIGH" if any(f.confidence == "HIGH" for f in group) and len(indexes) >= 3 else "MEDIUM"
        first_seen = min((f.first_seen for f in group if f.first_seen), default="")
        last_seen = max((f.last_seen for f in group if f.last_seen), default="")
        rule_ids = sorted({f.rule_id for f in group})
        title = group[0].title if len(group) == 1 else f"Correlated activity: {len(group)} detection signals"
        fingerprint = "|".join([";".join(rule_ids), ";".join(ips), ";".join(users), first_seen[:16]])
        incident_id = "AT-" + sha256(fingerprint.encode("utf-8")).hexdigest()[:8].upper()
        recs = list(dict.fromkeys(step for f in group for step in f.recommendations))
        evidence = list(dict.fromkeys(item for f in group for item in f.evidence_summary))
        mitre = list(dict.fromkeys(f"{f.mitre_id} — {f.mitre_name}" for f in group if f.mitre_id))
        incidents.append(Incident(
            incident_id, title, severity, risk, confidence, ", ".join(ips), users, hosts,
            rule_ids, [f.title for f in group], indexes, first_seen, last_seen, mitre, recs, evidence
        ))
    return sorted(incidents, key=lambda incident: (SEVERITY_ORDER.get(incident.severity, 9), -incident.risk_score, incident.first_seen))
