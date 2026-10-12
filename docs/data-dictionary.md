# Data Dictionary

This dictionary documents the fields used by the SOC Phishing Investigation Lab. The dataset is synthetic. Not every event type contains every field.

## Core fields

| Field | Type | Description | Example |
|---|---|---|---|
| `event_id` | string | Unique synthetic event identifier used for deduplication | `EVT-0021` |
| `lab_id` | string | Identifier for the lab dataset | `PHISH-2026-A` |
| `case_id` | string | Incident/case identifier | `CASE-002` |
| `event_type` | string | Telemetry category | `email_received`, `user_action`, `identity_signin` |
| `timestamp` | ISO-8601 string | Source event timestamp in UTC | `2026-09-20T10:06:30Z` |

## Email fields

| Field | Description | Example |
|---|---|---|
| `sender_display` | Human-readable display name shown in the email client | `Microsoft 365 Security` |
| `sender` | Sender email address | `security-alert@micr0soft-security.example` |
| `reply_to` | Reply-To email address, when present | `d.reeve.personal@fastmail-request.example` |
| `recipient` | Recipient email address | `alice.harris@bluepeak.example` |
| `subject` | Email subject | `Unusual Microsoft 365 sign-in - verify now` |
| `spf` | SPF result | `pass`, `fail` |
| `dkim` | DKIM result | `pass`, `fail`, `none` |
| `dmarc` | DMARC result | `pass`, `fail` |
| `gateway_action` | Mail gateway disposition | `delivered`, `blocked` |
| `attachment_name` | Attachment filename | `Payroll_Adjustment_Q3.docm` |
| `attachment_sha256` | SHA-256 of synthetic attachment evidence | `6f9636...afd2` |
| `url` | URL contained in the message | `https://login-security-m365.example/session/validate` |
| `url_domain` | Parsed domain from `url` | `login-security-m365.example` |

## User-action fields

| Field | Description | Example |
|---|---|---|
| `user` | User associated with the action | synthetic user identity |
| `action` | User interaction with an email or URL | `clicked_link`, `opened_attachment` |

## Identity fields

| Field | Description | Example |
|---|---|---|
| `source_ip` | Source IP for sign-in or network event | `203.0.113.200` |
| `result` | Authentication result | `success`, `failure` |
| `mfa` | MFA outcome/state used by the synthetic event | `not_satisfied` |

## Threat-intelligence / enrichment fields

| Field | Description | Example |
|---|---|---|
| `domain` | Domain being enriched | `secure-payroll-support.example` |
| `verdict` | Local synthetic TI assessment | `malicious`, `benign` |
| `hash` / `attachment_sha256` | File indicator used for enrichment | SHA-256 value |

## Derived SPL fields

These fields are created by searches rather than stored in the original event.

| Field | Created by | Purpose |
|---|---|---|
| `_time` | `strptime(timestamp,...)` | Converts ISO-8601 timestamp into Splunk epoch time |
| `sender_clean` | `mvindex(sender,0)` | Normalizes duplicated/multivalue sender fields |
| `reply_clean` | `mvindex(reply_to,0)` | Normalizes duplicated/multivalue Reply-To fields |
| `sender_domain` | `split()` + `mvindex()` | Extracts the sender domain |
| `reply_domain` | `split()` + `mvindex()` | Extracts the Reply-To domain |
| `auth_failure_count` | `eval` | Counts SPF/DKIM/DMARC problems |
| `click_epoch` | conditional `eval` | Timestamp of link-click event |
| `signin_epoch` | conditional `eval` | Timestamp of suspicious sign-in |
| `suspicious_ip` | conditional `eval` | Source IP tied to suspicious sign-in |
| `seconds_after_click` | epoch subtraction | Time between click and suspicious sign-in |
| `risk_score` | additive scoring logic | Triage prioritization score |
| `triage_priority` | `case()` | Converts risk score to High/Medium/Low/Review |

## Multivalue-field note

During the lab, fields were sometimes displayed twice, for example two copies of the same sender, subject, or timestamp. This can occur when JSON fields are automatically extracted at index/search time and `spath` extracts them again. Queries that perform string parsing should first normalize the field with:

```spl
| eval sender_clean=mvindex(sender,0)
```

Use `mvcount(field)` to confirm whether a field is multivalue.

## Synthetic-data conventions

- `.example` domains are reserved for documentation and safe examples.
- `203.0.113.0/24` and similar documentation ranges are not treated as real attacker infrastructure in this lab.
- Hashes, identities, and case records are synthetic evidence generated for training.
