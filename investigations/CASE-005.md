# Investigation: CASE-005 - Business Email Compromise / Executive Impersonation

## Summary

CASE-005 demonstrates an important SOC lesson: an email can pass SPF, DKIM, and DMARC and still be suspicious. The synthetic message impersonates CEO Daniel Reeve, uses urgency, and directs replies to a domain different from the sender domain.

## Email details

| Field | Value |
|---|---|
| Case ID | CASE-005 |
| Display name | Daniel Reeve - CEO |
| Sender | `daniel.reeve@executive-consulting.example` |
| Reply-To | `d.reeve.personal@fastmail-request.example` |
| Subject | `Urgent request before client meeting` |
| Sender domain | `executive-consulting.example` |
| Reply-To domain | `fastmail-request.example` |
| SPF | pass |
| DKIM | pass |
| DMARC | pass |

## Key findings

### 1. Authentication passed
SPF, DKIM, and DMARC passed. This means the sending infrastructure was authenticated for the domain it used; it does not prove the human identity or business request is legitimate.

### 2. Reply-To mismatch
The sender domain is `executive-consulting.example`, while replies are redirected to `fastmail-request.example`.

### 3. Executive impersonation
The display name claims to be the CEO. The Reply-To address is styled like a personal mailbox for the executive.

### 4. Urgency
The subject `Urgent request before client meeting` creates time pressure, a common BEC social-engineering technique.

## Disposition

**Suspicious BEC / executive-impersonation attempt.**

The mismatch does not by itself prove maliciousness, so a real SOC should validate the request using an established out-of-band communication channel.

## Recommended response

1. Do not reply directly to the suspicious message.
2. Validate the request using a known-good phone number, corporate chat account, or previously established contact method.
3. Search for other recipients of the same sender/Reply-To combination.
4. Review whether the request involves payment, gift cards, payroll, credentials, banking changes, or sensitive data.
5. Add the sender/Reply-To domains to monitoring or blocking controls if the investigation confirms malicious intent.
6. Record the detection as a BEC use case because authentication checks alone would not have caught it.

## Detection lesson

Email authentication validates domain-level sending authorization and alignment. It does not guarantee that the business context, human identity, or requested action is legitimate.
