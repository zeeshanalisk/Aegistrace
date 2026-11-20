"""Safe, bounded ingestion for CSV, JSON, JSONL and Linux auth-style text logs."""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any

from .models import SecurityEvent

MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_RECORDS = 20_000
MAX_RAW_MESSAGE = 600

ALIASES = {
    "timestamp": ("timestamp", "time", "datetime", "timecreated", "date", "eventtime", "createdat", "systemtime", "utc_time"),
    "username": ("username", "user", "user_name", "targetusername", "target_user_name", "accountname", "account", "subjectusername", "targetaccount"),
    "source_ip": ("sourceip", "source_ip", "ipaddress", "ip_address", "ip", "clientip", "remoteaddress", "sourceaddress", "sourcenetworkaddress", "clientaddress", "remoteip", "rhost"),
    "hostname": ("hostname", "host", "computer", "machine", "device", "computername"),
    "event_id": ("eventid", "event_id", "eventcode", "event_code", "id"),
    "event_type": ("eventtype", "event_type", "action", "activity", "operation", "eventname", "status"),
    "raw_message": ("rawmessage", "raw_message", "message", "description", "details", "event", "messagecontent"),
    "logon_type": ("logontype", "logon_type", "logontypeid"),
}

WINDOWS_EVENT_MAP = {
    "4624": "login_success",
    "4625": "login_failed",
    "4672": "privileged_login",
    "4720": "account_created",
    "4728": "group_membership_added",
    "4732": "group_membership_added",
    "4756": "group_membership_added",
    "4740": "account_locked",
    "1102": "audit_log_cleared",
    "4722": "account_enabled",
    "4724": "password_reset",
}

LINUX_PATTERNS = [
    (re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)", re.I), "login_failed"),
    (re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)", re.I), "login_success"),
    (re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)", re.I), "login_failed"),
    (re.compile(r"authentication failure.*?rhost=(?P<ip>\S+).*?user=(?P<user>\S+)", re.I), "login_failed"),
    (re.compile(r"sudo:\s*(?P<user>[\w.-]+)\s*:\s*.*?COMMAND=(?P<command>.+)$", re.I), "privileged_command"),
    (re.compile(r"session opened for user (?P<user>root)\b", re.I), "privileged_login"),
    (re.compile(r"new user:.*?name=(?P<user>[^,\s]+)", re.I), "account_created"),
]


def _key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").strip().lower())


def _pick(row: dict[str, Any], field: str) -> Any:
    indexed = {_key(k): v for k, v in row.items() if k is not None}
    for alias in ALIASES[field]:
        value = indexed.get(_key(alias))
        if value not in (None, ""):
            return value
    return ""


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None or str(value).strip() == "":
        return None
    raw = str(value).strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        dt = None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%Y %b %d %H:%M:%S"):
            try:
                dt = datetime.strptime(raw, fmt)
                if fmt == "%b %d %H:%M:%S":
                    dt = dt.replace(year=datetime.now(timezone.utc).year)
                break
            except ValueError:
                continue
    if dt is None:
        return None
    if dt.tzinfo is None:
        # Preserve source wall-clock time as UTC for consistent comparisons.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _valid_ip(value: Any) -> str:
    candidate = str(value or "").strip().strip("[]").rstrip(",;")
    if not candidate or candidate in {"-", "unknown", "0.0.0.0", "::"}:
        return ""
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def classify_event(event_id: Any, event_type: Any, raw_message: Any) -> str:
    event_code = str(event_id or "").strip().replace(".0", "")
    if event_code in WINDOWS_EVENT_MAP:
        return WINDOWS_EVENT_MAP[event_code]
    text = f"{event_type or ''} {raw_message or ''}".lower()
    if any(token in text for token in ("failed password", "logon failure", "failed to log on", "login failed", "authentication failure", "invalid user", "failed login")):
        return "login_failed"
    if any(token in text for token in ("accepted password", "successful logon", "logged on successfully", "login success", "authentication succeeded")):
        return "login_success"
    if any(token in text for token in ("audit log was cleared", "log cleared", "audit log cleared")):
        return "audit_log_cleared"
    if any(token in text for token in ("member added", "added to.*group", "group membership added")):
        return "group_membership_added"
    if any(token in text for token in ("special privileges assigned", "privileged logon", "session opened for user root")):
        return "privileged_login"
    if any(token in text for token in ("new account", "new user", "account created")):
        return "account_created"
    if "sudo:" in text and "command=" in text:
        return "privileged_command"
    if "account locked" in text or "locked out" in text:
        return "account_locked"
    return "unknown"


def _event_from_row(row: dict[str, Any], source: str = "csv") -> SecurityEvent:
    event_id = str(_pick(row, "event_id") or "").strip()
    raw = str(_pick(row, "raw_message") or "")[:MAX_RAW_MESSAGE]
    event_type = classify_event(event_id, _pick(row, "event_type"), raw)
    user = str(_pick(row, "username") or "unknown").strip()[:100]
    ip = _valid_ip(_pick(row, "source_ip"))
    host = str(_pick(row, "hostname") or "unknown-host").strip()[:120]
    stamp = _parse_timestamp(_pick(row, "timestamp"))
    logon_type = str(_pick(row, "logon_type") or "").strip()[:30]
    return SecurityEvent(stamp, event_type, user or "unknown", ip, host or "unknown-host", event_id, source, raw, logon_type)


def _parse_linux_line(line: str, line_number: int) -> SecurityEvent:
    raw = line.strip()[:MAX_RAW_MESSAGE]
    stamp_match = re.match(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)", raw)
    timestamp = None
    hostname = "linux-host"
    message = raw
    if stamp_match:
        try:
            timestamp = _parse_timestamp(f"{datetime.now(timezone.utc).year} {stamp_match.group('month')} {int(stamp_match.group('day')):02d} {stamp_match.group('time')}")
        except Exception:
            timestamp = None
        hostname = stamp_match.group("host")
        message = raw[stamp_match.end():].strip()
    username = "unknown"
    source_ip = ""
    event_type = "unknown"
    for pattern, kind in LINUX_PATTERNS:
        match = pattern.search(message)
        if match:
            values = match.groupdict()
            username = values.get("user") or username
            source_ip = _valid_ip(values.get("ip"))
            event_type = kind
            break
    return SecurityEvent(timestamp, event_type, username[:100], source_ip, hostname[:120], "", "linux-auth.log", raw)


def parse_bytes(filename: str, payload: bytes) -> tuple[list[SecurityEvent], list[str]]:
    """Parse an uploaded file. Never execute or persist uploaded content."""
    if len(payload) > MAX_UPLOAD_BYTES:
        raise ValueError(f"File is too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
    if not payload:
        raise ValueError("The uploaded file is empty.")
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("Please upload a UTF-8 encoded CSV, JSON, JSONL or text log file.") from exc

    events: list[SecurityEvent] = []
    warnings: list[str] = []
    if suffix == "csv":
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ValueError("CSV needs a header row with fields such as timestamp, event_id, username and source_ip.")
        for line_number, row in enumerate(reader, start=2):
            if len(events) >= MAX_RECORDS:
                warnings.append(f"Input was capped at {MAX_RECORDS:,} records for predictable performance.")
                break
            if any(str(value or "").strip() for value in row.values()):
                events.append(_event_from_row(row, "windows-csv" if _pick(row, "event_id") else "csv"))
    elif suffix in {"json", "jsonl"}:
        rows: list[Any]
        if suffix == "jsonl":
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        else:
            decoded = json.loads(text)
            if isinstance(decoded, list):
                rows = decoded
            elif isinstance(decoded, dict):
                rows = decoded.get("events") or decoded.get("records") or decoded.get("data") or [decoded]
            else:
                raise ValueError("JSON must contain an object, an array, or an 'events'/'records' array.")
        if not isinstance(rows, list):
            raise ValueError("JSON 'events', 'records' or 'data' must be an array.")
        for row in rows[:MAX_RECORDS]:
            if isinstance(row, dict):
                events.append(_event_from_row(row, "json"))
        if len(rows) > MAX_RECORDS:
            warnings.append(f"Input was capped at {MAX_RECORDS:,} records for predictable performance.")
    elif suffix in {"log", "txt"}:
        for line_number, line in enumerate(text.splitlines(), start=1):
            if len(events) >= MAX_RECORDS:
                warnings.append(f"Input was capped at {MAX_RECORDS:,} lines for predictable performance.")
                break
            if line.strip():
                events.append(_parse_linux_line(line, line_number))
    else:
        raise ValueError("Unsupported file type. Use .csv, .json, .jsonl, .log or .txt.")

    if not events:
        raise ValueError("No usable records were found. Check the file format and header names.")
    missing_time = sum(1 for event in events if event.timestamp is None)
    if missing_time:
        warnings.append(f"{missing_time} record(s) had no parseable timestamp; they remain visible but are excluded from time-window correlation.")
    unknown = sum(1 for event in events if event.event_type == "unknown")
    if unknown:
        warnings.append(f"{unknown} record(s) were retained as 'unknown' because no supported event pattern matched.")
    return events, warnings


def demo_events() -> list[SecurityEvent]:
    """Return a small synthetic dataset designed to exercise multiple rules."""
    rows = [
        # Password spray: one source, multiple accounts.
        ("2026-11-14T09:00:00Z", "4625", "alex", "198.51.100.24", "DC-01", "Logon failure"),
        ("2026-11-14T09:01:00Z", "4625", "maria", "198.51.100.24", "DC-01", "Logon failure"),
        ("2026-11-14T09:02:00Z", "4625", "sam", "198.51.100.24", "DC-01", "Logon failure"),
        ("2026-11-14T09:03:00Z", "4625", "lee", "198.51.100.24", "DC-01", "Logon failure"),
        ("2026-11-14T09:04:00Z", "4625", "nina", "198.51.100.24", "DC-01", "Logon failure"),
        ("2026-11-14T09:05:00Z", "4625", "alex", "198.51.100.24", "DC-01", "Logon failure"),
        ("2026-11-14T09:06:00Z", "4625", "maria", "198.51.100.24", "DC-01", "Logon failure"),
        ("2026-11-14T09:07:00Z", "4625", "sam", "198.51.100.24", "DC-01", "Logon failure"),
        # Targeted brute force followed by success.
        ("2026-11-14T10:10:00Z", "4625", "administrator", "203.0.113.77", "APP-02", "Logon failure"),
        ("2026-11-14T10:11:00Z", "4625", "administrator", "203.0.113.77", "APP-02", "Logon failure"),
        ("2026-11-14T10:12:00Z", "4625", "administrator", "203.0.113.77", "APP-02", "Logon failure"),
        ("2026-11-14T10:13:00Z", "4625", "administrator", "203.0.113.77", "APP-02", "Logon failure"),
        ("2026-11-14T10:14:00Z", "4625", "administrator", "203.0.113.77", "APP-02", "Logon failure"),
        ("2026-11-14T10:15:00Z", "4624", "administrator", "203.0.113.77", "APP-02", "Successful logon"),
        ("2026-11-14T10:16:00Z", "4672", "administrator", "203.0.113.77", "APP-02", "Special privileges assigned"),
        # Persistence / audit tampering examples.
        ("2026-11-14T11:32:00Z", "4720", "svc-backup", "", "DC-01", "New account created"),
        ("2026-11-14T11:35:00Z", "4728", "svc-backup", "", "DC-01", "Member added to privileged group"),
        ("2026-11-14T11:40:00Z", "1102", "unknown", "", "DC-01", "Audit log was cleared"),
        # Normal traffic / controls.
        ("2026-11-14T12:05:00Z", "4624", "alex", "192.0.2.10", "LAPTOP-01", "Successful logon"),
        ("2026-11-14T12:09:00Z", "4625", "guest", "192.0.2.10", "LAPTOP-01", "Logon failure"),
    ]
    result: list[SecurityEvent] = []
    for timestamp, event_id, user, ip, host, message in rows:
        result.append(_event_from_row({
            "timestamp": timestamp,
            "event_id": event_id,
            "username": user,
            "source_ip": ip,
            "hostname": host,
            "message": message,
        }, "synthetic-demo"))
    return result
