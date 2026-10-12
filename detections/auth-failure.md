# Detection: Email Authentication Failure

## Objective

Identify received emails where SPF, DKIM, or DMARC indicates an authentication problem that may support a spoofing or phishing hypothesis.

This detection is intentionally a triage signal rather than a maliciousness verdict. Legitimate senders can be misconfigured, forwarded messages can affect authentication, and some legitimate systems may lack DKIM. The analyst must correlate authentication failures with sender identity, message content, attachments, URLs, user activity, and gateway disposition.

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
| eval spf_clean=lower(mvindex(spf,0)), dkim_clean=lower(mvindex(dkim,0)), dmarc_clean=lower(mvindex(dmarc,0))
| eval auth_failure_count=if(spf_clean="fail",1,0)+if(in(dkim_clean,"fail","none"),1,0)+if(dmarc_clean="fail",1,0)
| where auth_failure_count>0
| table case_id sender recipient subject spf_clean dkim_clean dmarc_clean attachment_name gateway_action auth_failure_count
| sort - auth_failure_count
```

## Logic

The detection adds one point for each of the following:

- SPF failure
- DKIM failure or no DKIM signature
- DMARC failure

It returns only events where the resulting count is greater than zero.

## Expected lab findings

### CASE-001

- SPF: fail
- DKIM: none
- DMARC: fail
- Attachment: `Payroll_Adjustment_Q3.docm`
- Gateway action: delivered
- Authentication failure count: 3

The fact that the message was delivered despite multiple authentication failures makes this case operationally important because the recipient was exposed to the suspicious attachment.

### CASE-006

- SPF: fail
- DKIM: fail
- DMARC: fail
- Attachment: `Parcel_Documents.zip`
- Gateway action: blocked

The email is malicious in the synthetic scenario but has lower immediate exposure because the gateway blocked it.

## Analyst triage questions

1. Does the visible From domain match an approved sender domain?
2. Was the message delivered, quarantined, or blocked?
3. Is there a suspicious attachment or URL?
4. Did the user interact with the message?
5. Does local threat intelligence identify the sender domain, URL, or hash as malicious?
6. Are there related messages to other recipients?

## False positives / limitations

- Forwarding can break SPF alignment.
- Mailing lists and third-party senders may produce unexpected authentication results.
- DKIM may be absent on legitimate mail.
- An email can pass SPF, DKIM, and DMARC and still be malicious, as CASE-005 demonstrates.

## Severity guidance

- High: delivered + authentication failures + malicious attachment/URL + user interaction
- Medium: delivered + authentication failures but no confirmed interaction
- Low/Informational: blocked/quarantined with no user exposure, while still preserving the malicious classification if evidence supports it
