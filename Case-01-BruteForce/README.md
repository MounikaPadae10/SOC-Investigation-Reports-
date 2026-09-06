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

The remote system repeatedly attempted authentication against the:

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

These values indicate that Windows could not successfully authenticate the supplied credentials.

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

This IP became the primary investigation indicator for correlating additional authentication activity.

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

# Timeline

| Time | Event | Account | Source IP | Result |
|---|---|---|---|---|
| 10:53:26 PM | Event ID 4625 | `support` | `10.10.53.248` | Failed |
| 10:53:27 PM | Event ID 4625 | `support` | `10.10.53.248` | Failed |
| 10:53:28 PM | Event ID 4625 | `support` | `10.10.53.248` | Failed |
| 10:53:30 PM | Event ID 4625 | `support` | `10.10.53.248` | Failed |
| 10:53:41 PM | Event ID 4624 | `Administrator` | `10.10.53.248` | Successful RDP Login |

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

# MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Brute Force | `T1110` | Multiple authentication failures occurred within a very short period |
| Password Guessing | `T1110.001` | Activity is consistent with repeated credential-guessing attempts |
| Remote Services: RDP | `T1021.001` | A successful Logon Type 10 RemoteInteractive session was observed |

> MITRE ATT&CK mapping represents techniques consistent with the observed evidence and does not by itself prove attacker intent.

---

# Attack Pattern

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

---

# Analyst Assessment

## Verdict

**Highly Suspicious — Possible Brute Force / Credential Guessing Followed by Successful Remote Access**

The following factors contributed to the assessment:

- 14 failed authentication attempts occurred within approximately four seconds.
- The attempts originated from a single source IP.
- A successful RDP authentication occurred approximately 11 seconds later.
- The successful authentication originated from the same source IP.
- The successful account was `Administrator`.
- The resulting session had an elevated token.

However, the failed authentication attempts targeted `support`, while the successful authentication used `Administrator`.

Therefore, the investigation cannot conclusively state that the `support` account was successfully brute-forced.

The correct conclusion is that **suspicious credential-guessing activity was followed shortly afterward by successful privileged RDP authentication from the same source IP**.

---

# Recommended SOC Actions

If this activity were observed in a production environment, the following actions should be considered:

1. **Validate the source IP**
   - Determine whether `10.10.53.248` is an authorized internal or remote-access system.

2. **Investigate the Administrator account**
   - Confirm whether the RDP login was expected and authorized.

3. **Review additional authentication activity**
   - Search for additional Event IDs `4624` and `4625` involving the same IP and accounts.

4. **Investigate post-login activity**
   - Review process creation, PowerShell activity, services, scheduled tasks, and other events following the successful login.

5. **Reset potentially compromised credentials**
   - Reset credentials if unauthorized access is confirmed or strongly suspected.

6. **Restrict unnecessary RDP access**
   - Limit RDP exposure to approved systems and trusted network ranges.

7. **Apply account lockout controls**
   - Configure appropriate lockout thresholds to reduce password-guessing risk.

8. **Enable multi-factor authentication**
   - Require MFA for privileged and remote-access accounts where supported.

9. **Block or isolate suspicious sources**
   - Block the source IP or isolate the affected host if malicious activity is confirmed.

10. **Escalate for incident response**
    - Escalate the investigation if evidence of unauthorized privileged access or post-compromise activity is identified.

---

# Investigation Limitations

This investigation is based on the available Windows Security Event Log evidence.

The evidence confirms:

- Repeated failed authentication attempts against `support`
- A successful RDP authentication using `Administrator`
- Both activities originated from `10.10.53.248`
- The events occurred within a very short time window

The available evidence does **not** independently confirm:

- Who controlled the source IP
- Whether the activity was authorized
- Whether the `support` account was compromised
- Whether malicious activity occurred after the Administrator login

Additional endpoint, network, EDR, process, and authentication telemetry would be required for complete incident confirmation.

---

# Skills Demonstrated

This investigation demonstrates practical experience with:

- Windows Security Event Log analysis
- Event ID 4625 investigation
- Event ID 4624 investigation
- Authentication event correlation
- Windows Logon Type analysis
- RDP investigation
- Source IP correlation
- Account activity analysis
- Timeline reconstruction
- Indicator identification
- MITRE ATT&CK mapping
- SOC alert triage
- Incident assessment
- Remediation recommendations

---

# Conclusion

The investigation identified a burst of **14 failed authentication attempts** against the `support` account from `10.10.53.248`.

Approximately **11 seconds after the final observed failure**, the same source IP successfully authenticated to the Windows host through RDP using the `Administrator` account.

The successful session used **Logon Type 10 (RemoteInteractive)** and had an **elevated token**.

Although the evidence does not prove that the `support` account itself was successfully brute-forced, the close timing, matching source IP, and subsequent privileged RDP authentication make the activity highly suspicious and warrant further investigation.

---

**Case Status:** Investigation Complete ✅
