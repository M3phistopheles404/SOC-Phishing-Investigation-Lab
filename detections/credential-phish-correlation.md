# Detection: Credential-Phishing Click-to-Sign-In Correlation

## Objective

Correlate a user clicking a phishing link with a subsequent successful identity sign-in where MFA was not satisfied. The goal is to identify a possible credential-theft sequence and quantify the time between the user's interaction and the suspicious authentication.

## Data sources

- Splunk index: `phishing_lab`
- `user_action` events
- `identity_signin` events
- Lab identifier: `PHISH-2026-A`

## SPL

```spl
index=phishing_lab earliest=0
| spath
| search lab_id="PHISH-2026-A" case_id="CASE-002"
| dedup event_id
| eval _time=strptime(timestamp,"%Y-%m-%dT%H:%M:%SZ")
| eval click_epoch=if(event_type="user_action" AND action="clicked_link",_time,null())
| eval signin_epoch=if(event_type="identity_signin" AND result="success" AND mfa="not_satisfied",_time,null())
| eval suspicious_ip=if(event_type="identity_signin" AND result="success" AND mfa="not_satisfied",source_ip,null())
| stats min(click_epoch) as click_epoch min(signin_epoch) as signin_epoch values(suspicious_ip) as suspicious_ip by case_id
| eval seconds_after_click=signin_epoch-click_epoch
| eval click_time=strftime(click_epoch,"%Y-%m-%d %H:%M:%S UTC"), signin_time=strftime(signin_epoch,"%Y-%m-%d %H:%M:%S UTC")
| table case_id click_time signin_time seconds_after_click suspicious_ip
```

## How the correlation works

- `click_epoch` is populated only for a `user_action` event whose action is `clicked_link`.
- `signin_epoch` is populated only for a successful `identity_signin` event where MFA is not satisfied.
- `suspicious_ip` captures the source IP for the same suspicious sign-in condition.
- `stats min(...)` selects the earliest relevant click and suspicious sign-in for the case.
- Subtracting the two epoch timestamps calculates the number of seconds between the events.

## Expected lab result

| case_id | click_time | signin_time | seconds_after_click | suspicious_ip |
|---|---|---|---:|---|
| CASE-002 | 2026-09-20 10:06:30 UTC | 2026-09-20 10:10:40 UTC | 250 | 203.0.113.200 |

## Interpretation

A suspicious successful sign-in occurred 250 seconds after the user clicked the credential-phishing link. Temporal proximity alone does not mathematically prove credential theft, but when combined with the brand-lookalike sender, malicious-looking login URL, successful sign-in condition, and unsatisfied MFA, it creates a high-confidence incident requiring account containment and broader identity review.

## MITRE ATT&CK mapping

- T1566.002 - Phishing: Spearphishing Link
- T1078 - Valid Accounts (relevant if stolen credentials were used successfully)

## Recommended alert logic for a production-like lab

Raise a high-priority correlation alert when:

1. A user clicks a URL from a message already scored as suspicious or malicious.
2. The same user has a successful sign-in within a defined time window such as 5-15 minutes.
3. The sign-in is anomalous because of source IP, device, geography, MFA state, or other identity-risk indicators.

## False positives / limitations

- The user may legitimately sign in shortly after clicking a security-related email.
- A successful sign-in does not automatically prove the phishing page collected credentials.
- Production detection should match the same user identity and include device/geolocation/baseline context.
- `203.0.113.200` is a documentation IP used by this synthetic lab.
