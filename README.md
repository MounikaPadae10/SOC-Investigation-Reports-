# 🛡️ SOC Investigation Reports

A collection of hands-on Security Operations Center (SOC) investigations
covering authentication attacks, malware, phishing, ransomware, and
suspicious PowerShell activity.

The purpose of this repository is to demonstrate practical SOC analyst
skills including alert triage, log analysis, incident investigation,
IOC identification, MITRE ATT&CK mapping, and incident documentation.

---

## 🔍 Investigation Cases

| Case | Investigation | Status |
|------|---------------|--------|
| 01 | [Brute Force Investigation](./Case-01-BruteForce/) | ✅ Completed |
| 02 | [Ransomware Investigation](./Case-02-Ransomware/) | ⏳ Planned |
| 03 | [Phishing Investigation](./Case-03-Phishing/) | ⏳ Planned |
| 04 | [Malware Investigation](./Case-04-Malware/) | ⏳ Planned |
| 05 | [Suspicious PowerShell Investigation](./Case-05-PowerShell/) | ⏳ Planned |

---

## 🧰 Tools & Technologies

- Splunk
- Wireshark
- Windows Event Viewer
- Sysmon
- PowerShell
- VirusTotal
- MITRE ATT&CK
- TryHackMe

---

## 🔎 Skills Demonstrated

- SOC Alert Triage
- Windows Event Log Analysis
- SIEM Investigation
- Network Traffic Analysis
- Threat Detection
- IOC Identification
- Incident Response
- MITRE ATT&CK Mapping
- Security Incident Documentation

---

## 📂 Investigation Methodology

Each investigation follows a structured SOC investigation process to ensure consistent analysis, evidence collection, and incident documentation.

### Investigation Workflow

**1. Alert Triage**  
Review the security alert and identify the affected user, host, IP address, timestamp, and severity.

**2. Evidence Collection**  
Collect relevant logs, security events, network traffic, process information, and other available evidence.

**3. Analysis & Correlation**  
Analyze SIEM logs, Windows events, Sysmon telemetry, or network traffic and correlate related activity.

**4. IOC Identification**  
Identify relevant Indicators of Compromise (IOCs), such as IP addresses, domains, file hashes, URLs, filenames, and user accounts.

**5. Timeline Reconstruction**  
Reconstruct the sequence of events to understand how the activity started, progressed, and affected the environment.

**6. MITRE ATT&CK Mapping**  
Map confirmed attacker behavior to the appropriate MITRE ATT&CK tactics and techniques.

**7. Incident Verdict**  
Classify the activity based on the available evidence and determine whether the incident represents malicious, suspicious, or benign behavior.

**8. Containment & Remediation**  
Document recommended actions to contain the threat, remediate affected systems, and reduce the likelihood of recurrence.

### SOC Investigation Flow

`Alert → Triage → Evidence → Analysis → IOCs → Timeline → MITRE ATT&CK → Verdict → Containment & Remediation`

---

## 📸 Evidence

Screenshots and other sanitized evidence are stored inside the corresponding
case directory.

Sensitive information, credentials, malicious binaries, and unsafe artifacts
are not included.

---

## 🎯 Objective

This repository was created as part of my practical cybersecurity training
and SOC analyst preparation.

The investigations demonstrate my ability to analyze security events,
identify suspicious activity, document findings, and communicate incident
details in a structured SOC investigation report.

---

## ⚠️ Disclaimer

All investigations in this repository were performed in authorized lab,
training, or simulated environments for educational purposes only.
