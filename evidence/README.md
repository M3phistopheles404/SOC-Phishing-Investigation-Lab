# Synthetic Email Evidence

This folder is intended to contain the synthetic `.eml` evidence files used in the phishing investigation lab.

The repository documentation is based on synthetic cases and should not be interpreted as evidence from a real organization or real users. Domains use the reserved `.example` namespace and IP addresses use documentation ranges.

## Evidence handling workflow

For each `.eml` file:

1. Preserve the original file unchanged.
2. Record the case identifier.
3. Parse and review the following headers:
   - Date
   - Message-ID
   - From
   - To
   - Subject
   - Reply-To
   - Return-Path
   - Received
   - Authentication-Results
4. Record SPF, DKIM, and DMARC results.
5. Extract URLs and attachment metadata.
6. Compute or record hashes for attachments where available.
7. Correlate the message with Splunk telemetry such as user actions, gateway alerts, DNS/proxy activity, identity sign-ins, and local threat-intelligence events.

## Cases represented by the lab

### CASE-001 - Suspicious payroll attachment

Observed indicators:

- Sender: `payroll-update@secure-payroll-support.example`
- Recipient: `alice.harris@bluepeak.example`
- Subject: `Action required: payroll adjustment form`
- SPF: fail
- DKIM: none
- DMARC: fail
- Attachment: `Payroll_Adjustment_Q3.docm`
- SHA-256: `6f9636261ea27b36c2c4f6ed88536702d679561dbb1a3020a7d3dce18cefafd2`
- Gateway action: delivered
- User interaction: attachment opened
- Local threat intelligence: malicious

### CASE-002 - Credential-phishing link

Observed indicators:

- Display name: `Microsoft 365 Security`
- Sender: `security-alert@micr0soft-security.example`
- Subject: `Unusual Microsoft 365 sign-in - verify now`
- URL: `https://login-security-m365.example/session/validate`
- Gateway action: delivered
- Email authentication: SPF/DKIM/DMARC passed
- User link click: 2026-09-20 10:06:30 UTC
- Suspicious successful sign-in: 2026-09-20 10:10:40 UTC
- Time difference: 250 seconds
- Source IP: `203.0.113.200`

### CASE-005 - Executive impersonation / BEC

Observed indicators:

- Display name: `Daniel Reeve - CEO`
- Sender: `daniel.reeve@executive-consulting.example`
- Reply-To: `d.reeve.personal@fastmail-request.example`
- Subject: `Urgent request before client meeting`
- Sender domain: `executive-consulting.example`
- Reply-To domain: `fastmail-request.example`
- SPF/DKIM/DMARC: passed
- Primary suspicious signal: identity/Reply-To mismatch plus urgency

## Evidence integrity

Because the lab is synthetic, no real chain-of-custody claim is made. For a real incident, evidence should be preserved in accordance with the organization's incident-response and forensic-handling procedures.
