# Detection: Reply-To Domain Mismatch

## Objective

Identify received emails where the Reply-To domain differs from the sender domain. This can reveal business-email-compromise, executive impersonation, vendor fraud, or social-engineering attempts that pass normal email-authentication checks.

A mismatch is a triage indicator, not automatic proof of maliciousness. Legitimate ticketing, CRM, marketing, and outsourced communication systems can intentionally use different Reply-To domains.

## Data source

- Splunk index: `phishing_lab`
- Event type: `email_received`
- Lab identifier: `PHISH-2026-A`

## SPL

```spl
index=phishing_lab earliest=0
| spath
| search lab_id="PHISH-2026-A" event_type="email_received"
| dedup event_id
| eval sender_clean=mvindex(sender,0)
| eval reply_clean=mvindex(reply_to,0)
| eval sender_domain=lower(mvindex(split(sender_clean,"@"),1))
| eval reply_domain=lower(mvindex(split(reply_clean,"@"),1))
| where isnotnull(reply_domain) AND reply_domain!="" AND sender_domain!=reply_domain
| table case_id sender_clean sender_display reply_clean subject sender_domain reply_domain spf dkim dmarc gateway_action
```

## Why `mvindex(...,0)` is used

The lab encountered duplicated field values when automatic JSON extraction and `spath` exposed the same field more than once. `mvindex(field,0)` normalizes the field to the first value before domain parsing.

## Expected lab finding - CASE-005

- Display name: `Daniel Reeve - CEO`
- Sender: `daniel.reeve@executive-consulting.example`
- Reply-To: `d.reeve.personal@fastmail-request.example`
- Subject: `Urgent request before client meeting`
- Sender domain: `executive-consulting.example`
- Reply-To domain: `fastmail-request.example`
- SPF/DKIM/DMARC: pass

## Analysis

CASE-005 demonstrates why analysts should not treat authentication success as proof that an email is safe. The message passes SPF, DKIM, and DMARC, yet its identity and response path are suspicious:

1. The display name claims to be the CEO.
2. The subject creates urgency.
3. The sender domain and Reply-To domain differ.
4. The Reply-To address is styled like a personal CEO mailbox.

This combination supports a BEC / executive-impersonation hypothesis and should trigger out-of-band validation of the request.

## Analyst triage questions

1. Is the sender domain an approved corporate or partner domain?
2. Is the Reply-To mismatch expected for this sender?
3. Does the request involve money, credentials, gift cards, payroll, banking changes, or sensitive data?
4. Is the executive/vendor identity consistent with normal communication patterns?
5. Can the requester be validated using a known-good communication channel?

## False positives / limitations

Common legitimate reasons for a mismatch include:

- CRM platforms
- Marketing platforms
- Ticketing systems
- Managed service providers
- Shared mailboxes
- Customer-support platforms

The detection should therefore feed analyst triage rather than automatically block all mismatches.
