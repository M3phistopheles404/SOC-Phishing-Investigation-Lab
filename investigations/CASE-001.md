# Investigation: CASE-001 - Suspicious Payroll Attachment

## Summary

CASE-001 is a synthetic payroll-themed phishing message delivered to `alice.harris@bluepeak.example`. The message failed SPF and DMARC, had no DKIM signature, carried a macro-enabled Word attachment, was delivered by the gateway, and the user opened the attachment. Local lab threat intelligence identified the sender domain and attachment hash as malicious.

## Email details

| Field | Value |
|---|---|
| Case ID | CASE-001 |
| Display name | BluePeak Payroll |
| Sender | `payroll-update@secure-payroll-support.example` |
| Recipient | `alice.harris@bluepeak.example` |
| Subject | `Action required: payroll adjustment form` |
| SPF | fail |
| DKIM | none |
| DMARC | fail |
| Attachment | `Payroll_Adjustment_Q3.docm` |
| Attachment SHA-256 | `6f9636261ea27b36c2c4f6ed88536702d679561dbb1a3020a7d3dce18cefafd2` |
| Gateway action | delivered |
| User interaction | attachment opened |
| Local threat-intel verdict | malicious |

## Indicators and reasoning

### 1. Sender identity
The sender domain is not the BluePeak corporate domain used by the recipient organization. The display name `BluePeak Payroll` attempts to create internal trust while the address uses `secure-payroll-support.example`.

### 2. Authentication failures
The message failed SPF and DMARC and did not present a DKIM signature. These failures support the spoofing/phishing hypothesis but are not used as the sole verdict.

### 3. Social engineering
The subject `Action required: payroll adjustment form` creates urgency and uses a payroll theme, both of which can pressure the recipient into opening the attachment.

### 4. Attachment risk
`Payroll_Adjustment_Q3.docm` is a macro-enabled Microsoft Word document. In the lab, its SHA-256 is associated with a malicious threat-intelligence verdict.

### 5. Exposure
The gateway delivered the email and the user opened the attachment. This makes CASE-001 higher priority than an otherwise similar message that was blocked before user exposure.

## Disposition

**Malicious phishing - attachment delivery and user interaction confirmed in the synthetic lab.**

## Recommended containment / response

1. Isolate the endpoint if execution or suspicious child-process activity is observed.
2. Quarantine or remove the message from other mailboxes.
3. Block the sender domain and attachment hash according to policy.
4. Search endpoint telemetry for Office spawning PowerShell, cmd, script hosts, or unusual network connections.
5. Reset credentials if there is evidence of credential access or secondary phishing activity.
6. Hunt for the same attachment hash, sender domain, subject, and Message-ID across the environment.
7. Preserve the original email and endpoint telemetry for incident documentation.

## Lessons demonstrated

- Authentication failure triage
- Suspicious attachment analysis
- User-exposure assessment
- IOC correlation
- Containment prioritization
