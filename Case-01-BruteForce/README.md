# Case 01 — Windows Brute Force Investigation

## Overview

This investigation analyzes suspicious Windows authentication activity using Windows Security Event Logs.

Multiple failed authentication attempts were observed from the same source IP address within a very short period of time. Shortly afterward, a successful Remote Desktop Protocol (RDP) login was recorded from the same source IP.

The objective of this investigation was to determine:

- Which account was targeted
- How many failed authentication attempts occurred
- The source IP address
- The logon type used
- The reason for authentication failure
- Whether a successful login followed the failed attempts
- Whether the activity was consistent with brute-force or credential-guessing behavior
- What actions a SOC analyst should recommend

---

## Investigation Environment

| Item | Details |
|---|---|
| Platform | TryHackMe |
| Operating System | Windows |
| Log Source | Windows Security Event Log |
| Evidence File | `Practice-Security.evtx` |
| Host | `THM-PC` |
| Investigation Tool | Windows Event Viewer |
| Failed Login Event | Event ID `4625` |
| Successful Login Event | Event ID `4624` |

---

# Investigation Summary

Analysis of the Windows Security logs identified **14 failed authentication attempts** occurring within approximately four seconds.

The failed attempts targeted:

`support`

The attempts originated from:

`10.10.53.248`

The failed authentication events used:

`Logon Type 3 — Network`

Shortly afterward, a successful Event ID `4624` authentication was identified.

The successful login used:

`Logon Type 10 — RemoteInteractive`

and authenticated the account:

`Administrator`

The successful authentication originated from the **same source IP address**:

`10.10.53.248`

The combination of rapid authentication failures followed by a successful RDP login from the same source IP is highly suspicious and consistent with **credential-guessing or brute-force activity followed by successful remote authentication**.

However, the failed attempts targeted the `support` account while the successful authentication used `Administrator`. Therefore, the evidence does **not** prove that the `support` account itself was successfully brute-forced.

---

# Investigation

## 1. Identify Failed Authentication Events

Windows Event Viewer was used to filter the Security log for:

`Event ID 4625`

Event ID 4625 represents:

> An account failed to log on.

The filtered results identified:

**14 failed authentication events**

The events occurred between approximately:

`10:53:26 PM – 10:53:30 PM`

This means numerous authentication attempts were generated within only a few seconds.

Such rapid authentication activity is unusual for normal manual login behavior and may indicate automated password guessing.

### Evidence

![Event ID 4625 Failed Login Overview](screenshots/01-4625-failed-logins-overview.png)

### Finding

- Event ID: `4625`
- Failed attempts: `14`
- Approximate duration: `4 seconds`

---

## 2. Analyze Failed Logon Type

One of the Event ID 4625 records was examined in detail.

The event showed:

`Logon Type: 3`

Windows **Logon Type 3** represents a **Network logon**.

This indicates that the authentication request originated through the network rather than through a direct interactive login at the local system.

### Evidence

![Failed Login Logon Type 3](screenshots/02-failed-logon-type-3.png)

### Finding

`Logon Type 3 — Network`

---

## 3. Identify the Targeted Account

The `Account For Which Logon Failed` section of Event ID 4625 was reviewed.

The targeted account was:

`support`

### Evidence

![Target Account Support](screenshots/03-target-account-support.png)

### Finding

The source system repeatedly attempted authentication against the:

`support`

account.

---

## 4. Determine the Failure Reason

The failed authentication event contained the following information:

| Field | Value |
|---|---|
| Failure Reason | `Unknown user name or bad password` |
| Status | `0xC000006D` |
| Sub Status | `0xC0000064` |

The status indicates a general logon failure, while Sub Status `0xC0000064` is consistent with an invalid, misspelled, or non-existent user account.

The rapid repetition of these failures further increases the likelihood of automated credential guessing.

### Evidence

![Failed Login Failure Reason](screenshots/04-failure-reason.png)

### Finding

The authentication attempts failed because the supplied username/password combination could not be successfully authenticated.

---

## 5. Identify the Source IP Address

The `Network Information` section of the Event ID 4625 record was examined.

The following information was identified:

| Field | Value |
|---|---|
| Workstation Name | `b1465f` |
| Source Network Address | `10.10.53.248` |
| Source Port | `0` |
| Logon Process | `NtLmSsp` |

### Evidence

![Failed Login Source IP](screenshots/05-failed-login-source-ip.png)

### Finding

The source IP responsible for the failed authentication attempts was:

`10.10.53.248`

This IP should be considered an important investigation indicator for correlation with related authentication activity.

---

# Successful Login Investigation

After investigating the failed authentication attempts, the Security log was searched for successful logins using:

`Event ID 4624`

Event ID 4624 represents:

> An account was successfully logged on.

A total of **19 Event ID 4624 records** were present in the log.

Not every successful login is suspicious because Windows generates legitimate authentication events for services, local users, network activity, and system processes.

Therefore, the successful authentication events were reviewed individually to identify activity related to the suspicious source IP.

### Evidence

![Event ID 4624 Successful Login Overview](screenshots/06-4624-successful-login-overview.png)

---

## 6. Identify the Suspicious Successful Logon Type

A relevant Event ID 4624 record showed:

`Logon Type: 10`

Windows Logon Type 10 represents:

`RemoteInteractive`

This type of authentication is commonly associated with **Remote Desktop Protocol (RDP)**.

### Evidence

![RDP Logon Type 10](screenshots/07-rdp-logon-type-10.png)

### Finding

A successful RemoteInteractive login occurred shortly after the failed authentication attempts.

This significantly increased the severity of the investigation because it indicated successful remote access to the Windows host.

---

## 7. Identify the Successfully Authenticated Account

The `New Logon` section of Event ID 4624 was examined.

The following account information was identified:

| Field | Value |
|---|---|
| Account Name | `Administrator` |
| Account Domain | `THM-PC` |
| Security ID | `THM-PC\Administrator` |

### Evidence

![Successful Administrator Login](screenshots/08-successful-login-administrator.png)

### Finding

The successful RDP authentication used the local:

`Administrator`

account.

This is particularly important because the account has significant privileges on the affected Windows host.

### Important Distinction

The failed login attempts targeted:

`support`

while the successful authentication used:

`Administrator`

Therefore, the available evidence does **not** demonstrate that the `support` account itself was successfully brute-forced.

However, the timing and matching source IP make the Administrator RDP login highly suspicious and require further investigation.

---

## 8. Correlate the Successful Login Source IP

The `Network Information` section of the successful Event ID 4624 record showed:

| Field | Value |
|---|---|
| Workstation Name | `THM-PC` |
| Source Network Address | `10.10.53.248` |
| Source Port | `0` |
| Process Name | `C:\Windows\System32\svchost.exe` |

### Evidence

![Successful Login Source IP](screenshots/09-successful-login-source-ip.png)

### Correlation

Failed authentication source:

`10.10.53.248`

Successful RDP authentication source:

`10.10.53.248`

The **same source IP address** was associated with both the failed authentication attempts and the later successful RDP login.

This is one of the strongest correlations identified during the investigation.

---

## 9. Analyze Authentication Details

Additional authentication details from Event ID 4624 showed:

| Field | Value |
|---|---|
| Logon Process | `User32` |
| Authentication Package | `Negotiate` |
| Logon Type | `10` |
| Elevated Token | `Yes` |

### Evidence

![Successful Login Authentication Details](screenshots/10-successful-login-authentication-details.png)

### Finding

The successful session was a:

`RemoteInteractive`

login with an:

`Elevated Token`

Because the authenticated account was `Administrator`, the session would provide significant privileges on the affected Windows host.

---

## Investigation Timeline

The table below summarizes the key timestamps observed during the authentication activity; multiple Event ID 4625 records occurred at some of these timestamps.

| Time | Event ID | Activity |
|------|----------|----------|
| 10:53:26 PM | 4625 | Multiple failed logon attempts observed |
| 10:53:27 PM | 4625 | Continued failed authentication attempts |
| 10:53:28 PM | 4625 | Failed logon attempts against the support account |
| 10:53:30 PM | 4625 | Final observed failed logon attempts |
| 10:53:41 PM | 4624 | Successful Logon Type 10 for Administrator |

### Timeline Analysis

A total of **14 failed authentication attempts** occurred between approximately:

`10:53:26 PM – 10:53:30 PM`

Approximately **11 seconds after the last observed failed authentication attempt**, a successful Event ID 4624 RemoteInteractive login occurred.

The successful login originated from the same source IP:

`10.10.53.248`

and authenticated:

`Administrator`

This sequence is highly suspicious.

---

# Key Findings

| Finding | Value |
|---|---|
| Failed Login Event ID | `4625` |
| Number of Failed Attempts | `14` |
| Failed Login Target | `support` |
| Failed Logon Type | `3 — Network` |
| Failure Reason | `Unknown user name or bad password` |
| Status | `0xC000006D` |
| Sub Status | `0xC0000064` |
| Source IP | `10.10.53.248` |
| Source Workstation | `b1465f` |
| Failed Authentication Process | `NtLmSsp` |
| Successful Login Event ID | `4624` |
| Successful Account | `Administrator` |
| Successful Logon Type | `10 — RemoteInteractive` |
| Successful Login Source IP | `10.10.53.248` |
| Authentication Package | `Negotiate` |
| Logon Process | `User32` |
| Elevated Token | `Yes` |
| Affected Host | `THM-PC` |

---

# Indicators of Compromise / Investigation Indicators

## Primary Indicator

| Type | Value | Reason |
|---|---|---|
| IP Address | `10.10.53.248` | Generated repeated failed authentication attempts and later successful RDP authentication |

## Additional Investigation Indicators

- Targeted account: `support`
- Successfully authenticated account: `Administrator`
- Failed authentication Event ID: `4625`
- Successful authentication Event ID: `4624`
- Network Logon Type: `3`
- RemoteInteractive Logon Type: `10`
- Failed authentication process: `NtLmSsp`
- Successful authentication process: `User32`

---

# Attack Pattern

The observed activity can be represented as:

```text
Source IP: 10.10.53.248
        |
        v
Multiple authentication attempts
        |
        v
14 × Event ID 4625
        |
        v
Target Account: support
        |
        v
Logon Type 3
        |
        v
Authentication failures
        |
        v
Approximately 11 seconds later
        |
        v
Event ID 4624
        |
        v
Account: Administrator
        |
        v
Logon Type 10
        |
        v
Successful RDP authentication
```

---

# Analyst Assessment

# MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Brute Force | `T1110` | Multiple authentication failures occurred within a very short period |
| Password Guessing | `T1110.001` | Activity is consistent with repeated credential-guessing attempts |
| Remote Services: RDP | `T1021.001` | A successful Logon Type 10 RemoteInteractive session was observed |

> MITRE ATT&CK mapping represents techniques consistent with the observed evidence and does not by itself prove attacker intent.

---

# Verdict

**Suspicious Authentication Activity – Possible Brute-Force / Credential-Guessing Followed by Successful Remote Access**

Fourteen failed authentication attempts were observed from `10.10.53.248` within approximately four seconds against the `support` account.

Approximately 11 seconds after the final failed attempt, the same source IP successfully authenticated to the `Administrator` account using Logon Type 10 (RemoteInteractive).

The evidence does not prove that the `support` account itself was compromised because the successful authentication involved a different account. However, the timing, common source IP, privileged Administrator account, and RDP logon make the activity highly suspicious and warrant further investigation.

---

# Recommended SOC Actions

- Investigate the source IP `10.10.53.248`.
- Verify whether the Administrator RDP login was authorized.
- Review additional activity associated with the Administrator account.
- Review Event IDs around the suspicious authentication timeframe.
- Reset credentials if compromise is suspected.
- Restrict unnecessary RDP access.
- Apply account lockout and strong password policies.
- Enable MFA for remote administrative access where available.
- Monitor for additional authentication attempts from the same source.

---

# Conclusion

The investigation identified a rapid sequence of failed network authentication attempts followed shortly afterward by a successful privileged RDP login from the same source IP.

The activity is consistent with suspicious credential-guessing behavior and requires escalation for further investigation.

---

**Case Status:** Investigation Complete ✅
