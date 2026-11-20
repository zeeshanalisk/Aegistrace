import unittest
from datetime import datetime, timedelta, timezone

from aegistrace.agent import run_triage
from aegistrace.ai_summary import _masked_payload
from aegistrace.ingest import demo_events, parse_bytes
from aegistrace.models import SecurityEvent
from aegistrace.reporting import safe_csv_cell, to_findings_csv, to_json, to_markdown
from aegistrace.rules import detect_findings


class IngestionTests(unittest.TestCase):
    def test_windows_csv_aliases_and_event_ids(self):
        payload = (
            "TimeCreated,EventID,TargetUserName,IpAddress,Computer,Message\n"
            "2026-11-14T10:00:00Z,4625,admin,203.0.113.9,WS-01,An account failed to log on\n"
            "2026-11-14T10:01:00Z,4624,admin,203.0.113.9,WS-01,An account was successfully logged on\n"
        ).encode()
        events, warnings = parse_bytes("sample.csv", payload)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_type, "login_failed")
        self.assertEqual(events[1].event_type, "login_success")
        self.assertEqual(events[0].source_ip, "203.0.113.9")

    def test_json_array(self):
        payload = b'[{"timestamp":"2026-11-14T10:00:00Z","event_id":4625,"username":"admin","source_ip":"203.0.113.9"}]'
        events, _ = parse_bytes("sample.json", payload)
        self.assertEqual(events[0].event_type, "login_failed")

    def test_linux_auth_log(self):
        payload = (
            b"Nov 14 10:00:00 srv01 sshd[123]: Failed password for invalid user admin from 203.0.113.9 port 55221 ssh2\n"
            b"Nov 14 10:01:00 srv01 sshd[124]: session opened for user alice by (uid=0)\n"
            b"Nov 14 10:02:00 srv01 sshd[125]: session opened for user root by (uid=0)\n"
        )
        events, _ = parse_bytes("auth.log", payload)
        self.assertEqual(events[0].event_type, "login_failed")
        self.assertEqual(events[0].username, "admin")
        self.assertEqual(events[0].source_ip, "203.0.113.9")
        self.assertEqual(events[1].event_type, "unknown")
        self.assertEqual(events[2].event_type, "privileged_login")

    def test_json_lines(self):
        payload = b'{"timestamp":"2026-11-14T10:00:00Z","event_id":4625,"username":"admin","source_ip":"203.0.113.9"}\n'
        events, _ = parse_bytes("sample.jsonl", payload)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "login_failed")

    def test_upload_size_is_bounded(self):
        with self.assertRaises(ValueError):
            parse_bytes("too-large.csv", b"a" * (5 * 1024 * 1024 + 1))


class DetectionTests(unittest.TestCase):
    def _event(self, minutes, kind, user="admin", ip="203.0.113.9", event_id="4625", host="HOST-01"):
        stamp = datetime(2026, 11, 14, 10, 0, tzinfo=timezone.utc) + timedelta(minutes=minutes)
        return SecurityEvent(stamp, kind, user, ip, host, event_id, "test", kind)

    def test_brute_force(self):
        events = [self._event(i, "login_failed") for i in range(5)]
        findings = detect_findings(events)
        self.assertIn("AUTH_BRUTE_FORCE", {item.rule_id for item in findings})

    def test_success_after_failure_is_critical(self):
        events = [self._event(i, "login_failed") for i in range(5)]
        events.append(self._event(6, "login_success", event_id="4624"))
        result = run_triage(events)
        self.assertTrue(any(item.rule_id == "AUTH_SUCCESS_AFTER_FAILURE" for item in result.findings))
        self.assertEqual(result.incidents[0].severity, "CRITICAL")

    def test_password_spray(self):
        users = ["alex", "maria", "sam", "lee", "nina", "alex", "maria", "sam"]
        events = [self._event(i, "login_failed", user=user) for i, user in enumerate(users)]
        findings = detect_findings(events)
        self.assertIn("AUTH_PASSWORD_SPRAY", {item.rule_id for item in findings})

    def test_audit_log_cleared(self):
        events = [self._event(0, "audit_log_cleared", event_id="1102")]
        findings = detect_findings(events)
        finding = next(item for item in findings if item.rule_id == "AUDIT_LOG_CLEARED")
        self.assertEqual(finding.severity, "CRITICAL")

    def test_same_source_findings_are_correlated(self):
        events = [self._event(i, "login_failed") for i in range(5)]
        events.append(self._event(6, "login_success", event_id="4624"))
        events.append(self._event(7, "privileged_login", event_id="4672"))
        result = run_triage(events)
        self.assertEqual(len(result.incidents), 1)
        self.assertIn("PRIVILEGED_LOGIN", result.incidents[0].finding_ids)
        self.assertIn("AUTH_SUCCESS_AFTER_FAILURE", result.incidents[0].finding_ids)

    def test_demo_has_expected_scenarios(self):
        result = run_triage(demo_events())
        rule_ids = {finding.rule_id for finding in result.findings}
        self.assertTrue({"AUTH_PASSWORD_SPRAY", "AUTH_SUCCESS_AFTER_FAILURE", "AUDIT_LOG_CLEARED"}.issubset(rule_ids))

    def test_normal_baseline_has_no_incident(self):
        baseline = [e for e in demo_events() if e.source_ip == "192.0.2.10"]
        self.assertEqual(run_triage(baseline).incidents, [])

    def test_lockout_burst(self):
        events = [self._event(i, "account_locked", user=f"user{i}", event_id="4740") for i in range(3)]
        findings = detect_findings(events)
        self.assertIn("ACCOUNT_LOCKOUT_BURST", {item.rule_id for item in findings})

    def test_unknown_records_are_retained(self):
        events, warnings = parse_bytes("events.csv", b"timestamp,message\n2026-11-14T10:00:00Z,custom event\n")
        self.assertEqual(events[0].event_type, "unknown")
        self.assertTrue(any("unknown" in warning for warning in warnings))


class ReportingTests(unittest.TestCase):
    def test_all_exports_are_generated(self):
        result = run_triage(demo_events())
        self.assertIn("AegisTrace Security Triage Report", to_markdown(result))
        self.assertIn('"product": "AegisTrace"', to_json(result))
        self.assertIn("incident_id,severity", to_findings_csv(result))

    def test_csv_formula_prefix_is_neutralised(self):
        self.assertEqual(safe_csv_cell("=1+1"), "'=1+1")
        self.assertEqual(safe_csv_cell(" @SUM(A1:A2)"), "' @SUM(A1:A2)")

    def test_markdown_escapes_untrusted_log_values(self):
        event = SecurityEvent(datetime(2026, 11, 14, 10, tzinfo=timezone.utc), "account_created", "<script>alert(1)</script>", "", "DC-01", "4720", "test", "new account")
        report = to_markdown(run_triage([event]))
        self.assertNotIn("<script>", report)
        self.assertIn("&lt;script&gt;", report)

    def test_gemini_payload_contains_no_raw_identifiers_or_messages(self):
        result = run_triage(demo_events())
        payload = _masked_payload(result)
        self.assertNotIn("administrator", payload)
        self.assertNotIn("203.0.113.77", payload)
        self.assertNotIn("APP-02", payload)
        self.assertNotIn("Special privileges assigned", payload)
        self.assertIn("AUTH_SUCCESS_AFTER_FAILURE", payload)


if __name__ == "__main__":
    unittest.main()
