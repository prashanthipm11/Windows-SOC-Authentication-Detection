# Windows SOC Authentication Detection & Investigation Lab

## Overview

This project is a lightweight Security Operations Center (SOC) home lab designed to detect and investigate failed Windows authentication activity.

The project monitors the Windows Security event log for **Event ID 4625**, identifies failed authentication activity within a defined time window, enriches detected events with process and service information, correlates related Windows Security events, and generates an incident report when the alert threshold is reached.

The lab was designed to practice fundamental SOC analyst skills including:

* Security event monitoring
* Authentication log analysis
* Detection engineering
* Event correlation
* Process investigation
* Service investigation
* Alert triage
* Incident documentation
* Incident reporting

---

## Project Architecture

```text
Windows Security Event Log
          |
          v
Event ID 4625 Detection
          |
          v
5-Minute Detection Window
          |
          v
Failed Authentication Count
          |
          v
Threshold Check (5 Events)
          |
          +------------------+
          |                  |
       Below 5            5 or More
          |                  |
          v                  v
   No Alert          SOC Alert Generated
                             |
                             v
                    Event Investigation
                             |
                             +--> Target Account
                             +--> Logon Type
                             +--> Process ID
                             +--> Executable Path
                             +--> Source IP
                             +--> Service Information
                             |
                             v
                    Security Event Correlation
                             |
                             +--> 4624 - Successful Logon
                             +--> 4625 - Failed Logon
                             +--> 4648 - Explicit Credential Logon
                             +--> 4672 - Special Privileges Assigned
                             |
                             v
                       Incident Report
                             |
                             v
                 Analyst Assessment & Actions
```

---

## Detection Logic

The detector monitors the Windows **Security** event log for:

**Event ID 4625 — An account failed to log on**

Production detection settings:

* Detection window: **5 minutes**
* Alert threshold: **5 failed authentication events**
* Alert ID: **WIN-AUTH-4625**
* Severity: **Medium**

The detector retrieves Event ID 4625 events that occurred within the previous five minutes.

The alert is triggered when:

```text
Failed Logons >= 5
```

If fewer than five failed authentication events are detected, the script reports:

```text
STATUS: No alert threshold reached.
```

The detector does not automatically classify authentication activity as malicious. The events require investigation and contextual analysis.

---

## Event Enrichment

For each detected Event ID 4625, the script extracts information from the Windows event XML data, including:

* Event timestamp
* Event ID
* Target account
* Logon type
* Authentication status
* Sub-status
* Logon process
* Authentication package
* Process name
* Process ID
* Source IP address

The Process ID from the Windows event is converted from hexadecimal format and used to investigate the associated process.

The script uses Windows CIM information to identify:

* Executable path
* Associated Windows service
* Service name
* Service display name

This provides additional context for the analyst during investigation.

---

## Security Event Correlation

When the alert threshold is reached, the detector performs additional event correlation.

Related Windows Security events are searched within a **±10-second window** around each detected Event ID 4625.

The following event IDs are correlated:

| Event ID | Description                                |
| -------- | ------------------------------------------ |
| 4624     | Successful logon                           |
| 4625     | Failed logon                               |
| 4648     | Logon using explicit credentials           |
| 4672     | Special privileges assigned to a new logon |

Correlation helps provide additional context around the authentication activity.

The presence of a related event does not automatically indicate malicious activity. Events must be interpreted in context.

---

## Controlled Lab Test

A controlled authentication failure was generated in the Windows lab environment to validate the detector.

The detector successfully identified:

* Event ID: **4625**
* Logon Type: **2**
* Process: **svchost.exe**
* Process ID: **0xa3c**
* Executable Path: **C:\WINDOWS\system32\svchost.exe**
* Source IP: **127.0.0.1**

The detector generated an incident report and performed Security event correlation.

The controlled test produced related events including:

* 4624
* 4625
* 4648
* 4672

The test demonstrated that the detection, event parsing, process investigation, correlation, and reporting components were functioning as designed.

---

## Incident Investigation

When the alert threshold is reached, the detector creates:

```text
Windows_SOC_Incident_Report.txt
```

The report contains:

### Alert Information

* Alert ID
* Severity
* Detection time
* Detection rule
* Number of failed authentication events

### Event Details

* Event timestamp
* Event ID
* Target account
* Logon type
* Status
* Sub-status
* Logon process
* Authentication package
* Process
* Process ID
* Executable path
* Service name
* Service display name
* Source IP

### Correlated Security Events

The report records nearby Windows Security events from the configured correlation window.

### Initial Assessment

The report provides investigation guidance covering:

* Affected account
* Logon type
* Source IP
* Process responsible
* Frequency and timing

### Disposition

The current report uses:

```text
Status: Requires Investigation
```

This is intentional. The detector identifies authentication activity requiring investigation but does not automatically determine that the activity is malicious.

---

## Recommended Analyst Actions

The incident report recommends:

1. Review the affected account.
2. Review the source IP address.
3. Review the logon type.
4. Investigate the process responsible for the event.
5. Correlate related Windows Security events.
6. Determine whether the activity is authorized.
7. Escalate if repeated or suspicious authentication activity is confirmed.

---

## Technical Environment

* Windows 11 Home
* Windows PowerShell
* Windows Security Event Log
* PowerShell `Get-WinEvent`
* PowerShell XML event parsing
* PowerShell CIM process investigation
* Windows service investigation
* Local Windows SOC home lab

---

## Project Structure

```text
Windows-SOC-Authentication-Detection
|
+-- README.md
|
+-- Detection
|   |
|   +-- Windows_SOC_Detector.ps1
|
+-- Reports
|   |
|   +-- Windows_SOC_Incident_Report.txt
|
+-- Evidence
    |
    +-- detection-test.txt
```

---

## Skills Demonstrated

### SOC Operations

* Alert triage
* Authentication monitoring
* Event investigation
* Security event correlation
* Incident documentation
* Incident reporting

### Windows Security

* Windows Security Event Log
* Event ID 4624
* Event ID 4625
* Event ID 4648
* Event ID 4672
* Windows logon types
* Process investigation
* Service investigation

### PowerShell

* `Get-WinEvent`
* Event filtering
* XML event parsing
* `Get-CimInstance`
* Process investigation
* Service investigation
* Script error handling
* Automated incident reporting

### Detection Engineering

* Time-based detection
* Detection thresholds
* Event correlation
* Event enrichment
* Alert generation
* Investigation workflow

---

## Future Improvements

Potential future improvements include:

* Add detection for account lockout events
* Detect suspicious remote authentication
* Add brute-force detection by source IP
* Improve event correlation using account and process context
* Add additional Windows Security event correlations
* Export alerts in structured JSON format
* Forward authentication events to Splunk
* Build authentication dashboards
* Add additional detection rules
* Improve automated severity classification

---

## Disclaimer

This project is a controlled cybersecurity learning lab performed on a local Windows environment.

The authentication failure used for testing was intentionally generated for detection validation.

The project is intended for cybersecurity education, SOC analyst skill development, and portfolio demonstration.
