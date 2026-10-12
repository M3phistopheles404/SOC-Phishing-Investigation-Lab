# Investigation: CASE-002 - Credential-Phishing Link and Account Impact

## Summary

CASE-002 is a synthetic Microsoft 365 credential-phishing scenario. The email passed SPF, DKIM, and DMARC, demonstrating that authentication success does not make a message safe. The sender used a `micr0soft` lookalike domain and a login-themed URL. The message was delivered, the user clicked the link, and a suspicious successful sign-in occurred 250 seconds later from `203.0.113.200` with MFA not satisfied.

## Email details

| Field | Value |
|---|---|
| Case ID | CASE-002 |
| Display name | Microsoft 365 Security |
| Sender | `security-alert@micr0soft-security.example` |
| Subject | `Unusual Microsoft 365 sign-in - verify now` |
| URL | `https://login-security-m365.example/session/validate` |
| SPF | pass |
| DKIM | pass |
| DMARC | pass |
| Gateway action | delivered |

## Correlated timeline

| Event | Time (UTC) | Details |
|---|---|---|
| Phishing link clicked | 2026-09-20 10:06:30 | User clicked the credential-phishing URL |
| Suspicious successful sign-in | 2026-09-20 10:10:40 | Successful sign-in with MFA not satisfied from `203.0.113.200` |
| Time difference | 250 seconds | Sign-in occurred 4 minutes 10 seconds after the click |

## Key evidence

### 1. Brand lookalike
The sender uses `micr0soft-security.example`, replacing the letter `o` in Microsoft with the digit `0`.

### 2. Login-themed URL
The URL `login-security-m365.example/session/validate` is designed to resemble a Microsoft 365 security verification flow while using a non-Microsoft domain.

### 3. Delivery and user interaction
The gateway delivered the message and the user clicked the link. This establishes exposure to the phishing lure.

### 4. Post-click identity activity
A suspicious successful sign-in occurred 250 seconds after the click from documentation IP `203.0.113.200`. In the synthetic telemetry, MFA was not satisfied for this sign-in.

## Analyst assessment

The event chain is consistent with credential phishing followed by suspected use of captured credentials. The temporal relationship is strong, but a real investigation would still validate user identity, device, geography, session details, conditional-access results, and post-authentication activity before claiming credential theft as a proven fact.

## MITRE ATT&CK mapping

- T1566.002 - Phishing: Spearphishing Link
- T1078 - Valid Accounts, if stolen credentials were used for the successful sign-in

## Severity

**High** - delivered credential-phishing message, confirmed link interaction, and suspicious successful identity activity shortly afterward.

## Recommended containment / remediation

1. Revoke active sessions for the affected user.
2. Force a password reset using a trusted administrative workflow.
3. Re-register or validate MFA as required by policy.
4. Review sign-ins before and after the suspicious event for source IP, device, geography, application, and risk changes.
5. Block or sinkhole the phishing URL/domain where appropriate.
6. Search for the same sender, subject, URL, and source IP across all users.
7. Review mailbox rules, OAuth grants, forwarding rules, and other persistence mechanisms if the account was accessible.
8. Preserve logs and document the response timeline.

## Detection opportunity

Correlate suspicious email-link clicks with identity sign-ins for the same user within a short time window, then raise priority when the sign-in has abnormal source, device, geography, MFA, or risk characteristics.
