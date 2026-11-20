# AegisTrace threat model

## Scope

AegisTrace is a prototype for defensive analysis of authentication and account-management logs. It is not an endpoint agent, SIEM collector, automated response system or forensic evidence vault.

## Assets

- Uploaded log records held temporarily in the active Streamlit session
- Optional Gemini API key supplied through an environment variable or password field
- Generated incident and export reports

## Trust boundaries

1. **Uploaded file → parser:** files are untrusted data. The parser limits upload size and record count, decodes UTF-8, recognises a fixed set of extensions and never evaluates uploaded content as code.
2. **Parser → detection engine:** normalised event fields are treated as evidence only when their source values can be parsed. Unknown events are retained but do not trigger unsupported detections.
3. **App → Gemini:** this boundary is disabled by default. It requires explicit consent and sends only aggregate counts, severities, rule IDs, confidence and evidence counts. No raw log content, account identifiers, IPs or hostnames are included.
4. **Recommendations → operator:** all remediation steps are advisory. No response API or privileged action is wired into the application.

## Main risks and controls

| Risk | Control | Residual limitation |
|---|---|---|
| Oversized or malformed upload | 5 MB limit, 20,000 record cap, UTF-8 and format checks | Streamlit host still needs sensible resource limits |
| Malicious file content | Parse as text/CSV/JSON only; no shell, code or macro execution | Do not upload files to untrusted hosting environments |
| Sensitive log disclosure | Local deterministic processing; no database; AI opt-in with anonymised aggregate payload | Hosting provider/session infrastructure is outside this prototype's control |
| Prompt injection in log messages | Raw messages are not sent to Gemini | Future AI features must preserve this boundary |
| False positives | Transparent rules, confidence labels, evidence, source records and human review | Thresholds require environment-specific tuning |
| Unsafe remediation | No blocking, disabling, termination or endpoint APIs exist | Operators must follow their organisation's change/IR policy |
| API-key leakage | Environment/secret manager support; `.gitignore` excludes secrets | Users must never paste keys into committed files |

## Abuse cases explicitly out of scope

- Offensive scanning, credential guessing or exploitation
- Automatic blocking or account disabling
- Threat actor attribution or geolocation claims
- Replacement of a qualified incident responder

## Operational guidance

Use synthetic data for demos. Before analysing real logs, follow your organisation's data classification, privacy, retention and access policies. Review findings against source systems and preserve original logs independently where forensic integrity matters.
