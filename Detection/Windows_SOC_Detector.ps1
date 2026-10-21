# Windows SOC Authentication Detector

$scriptPath = $MyInvocation.MyCommand.Path

Write-Host "===== WINDOWS SOC AUTHENTICATION DETECTOR ====="
Write-Host "Starting detection..."








































# Check for Administrator privileges
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentUser)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    Write-Host "Administrator privileges are required."
    Write-Host "Requesting elevation..."

    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

    Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs

    exit
}
Write-Host "Administrator privileges confirmed."





































# Detection settings
$windowMinutes = 5
$start = (Get-Date).AddMinutes(-$windowMinutes)
$threshold = 5
$alertId = "WIN-AUTH-4625"
$severity = "Medium"

$correlationSeconds = 10
$correlationEventIds = 4624,4625,4648,4672

# Retrieve failed logon events
$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = $start
} -ErrorAction SilentlyContinue

$count = ($events | Measure-Object).Count

if ($count -gt 0) {

    Write-Host ""
    Write-Host "===== FAILED LOGON DETAILS ====="

    foreach ($event in $events) {

        $xml = [xml]$event.ToXml()

        $eventData = @{}

        foreach ($data in $xml.Event.EventData.Data) {
            $eventData[$data.Name] = $data.'#text'
        }

        Write-Host ""
       Write-Host "Time: $($event.TimeCreated)"
Write-Host "Event ID: $($event.Id)"
Write-Host "Target Account: $($eventData['TargetUserName'])"
Write-Host "Logon Type: $($eventData['LogonType'])"
Write-Host "Process: $($eventData['ProcessName'])"
Write-Host "Process ID: $($eventData['ProcessId'])"
$processId = [Convert]::ToInt32($eventData['ProcessId'].Replace("0x",""),16)

$process = Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue

if ($process) {
    Write-Host "Executable Path: $($process.ExecutablePath)"
} else {
    Write-Host "Executable Path: Process not found"
}
Write-Host "Source IP: $($eventData['IpAddress'])"    }
}



Write-Host ""
Write-Host "===== DETECTION RESULTS ====="
Write-Host "Time Window: Last $windowMinutes Minutes"
Write-Host "Event ID: 4625"
Write-Host "Failed Logons: $count"
Write-Host "Alert Threshold: $threshold"





















































# Alert decision
if ($count -ge $threshold) {
$reportPath = "$HOME\Windows_SOC_Incident_Report.txt"

$report = @"
========================================
WINDOWS SOC INCIDENT REPORT
========================================

Alert ID: $alertId
Severity: $severity
Detection Time: $(Get-Date)

Detection Rule:
$threshold or more failed Windows logons
within the last $windowMinutes minutes.

Event ID: 4625
Failed Logons Detected: $count

========================================
EVENT DETAILS
========================================
"@

foreach ($event in $events) {

    $xml = [xml]$event.ToXml()

    $eventData = @{}

    foreach ($data in $xml.Event.EventData.Data) {
        $eventData[$data.Name] = $data.'#text'
    }
$processId = [Convert]::ToInt32($eventData['ProcessId'].Replace("0x",""),16)

$process = Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue

if ($process) {
    $executablePath = $process.ExecutablePath
} else {
    $executablePath = "Process not found"
}
$service = Get-CimInstance Win32_Service -Filter "ProcessId = $processId" -ErrorAction SilentlyContinue

if ($service) {
    $serviceName = $service.Name -join ", "
    $serviceDisplayName = $service.DisplayName -join ", "
} else {
    $serviceName = "No associated service"
    $serviceDisplayName = "No associated service"
}
$correlationStart = $event.TimeCreated.AddSeconds(-$correlationSeconds)
$correlationEnd = $event.TimeCreated.AddSeconds($correlationSeconds)

$relatedEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = $correlationEventIds
    StartTime = $correlationStart
    EndTime   = $correlationEnd
} -ErrorAction SilentlyContinue

$report += @"

Time: $($event.TimeCreated)
Event ID: $($event.Id)
Target Account: $($eventData['TargetUserName'])
Logon Type: $($eventData['LogonType'])
Status: $($eventData['Status'])
SubStatus: $($eventData['SubStatus'])
Logon Process: $($eventData['LogonProcessName'])
Authentication Package: $($eventData['AuthenticationPackageName'])
Process: $($eventData['ProcessName'])
Process ID: $($eventData['ProcessId'])
Executable Path: $executablePath
Service Name: $serviceName
Service Display Name: $serviceDisplayName
Source IP: $($eventData['IpAddress'])

----------------------------------------

CORRELATED SECURITY EVENTS
----------------------------------------

"@

foreach ($relatedEvent in $relatedEvents) {

    $report += @"
Time: $($relatedEvent.TimeCreated)
Event ID: $($relatedEvent.Id)
Provider: $($relatedEvent.ProviderName)

"@
}
}

$report += @"

========================================
INITIAL ASSESSMENT
========================================

The detected events are Windows Event ID 4625
failed authentication events.

The analyst should review:
- Target account
- Logon type
- Source IP address
- Process responsible for the event
- Frequency and timing of the events

A localhost source address (127.0.0.1) indicates that
the event originated from the local machine. This alone
does not establish whether the activity is benign or malicious.

The presence of svchost.exe should also be investigated
in context because svchost.exe is a legitimate Windows
host process used by multiple services.

========================================
DISPOSITION
========================================

Status: Requires Investigation

The detector identifies suspicious authentication activity
but does not automatically classify the activity as malicious.

The analyst should determine whether the events were
authorized or associated with expected system activity.

========================================
RECOMMENDED ACTIONS
========================================

1. Review the affected account.
2. Review the source IP address.
3. Review the logon type.
4. Investigate the process responsible for the event.
5. Correlate related Windows Security events.
6. Determine whether the activity is authorized.
7. Escalate if repeated or suspicious authentication
   activity is confirmed.

========================================
END OF REPORT
========================================
"@

$report | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host ""
Write-Host "Incident report created:"
Write-Host $reportPath
    Write-Host ""
    Write-Host "===== SOC ALERT ====="
    Write-Host "Alert ID: $alertId"
    Write-Host "Severity: $severity"
    Write-Host "Detection: Windows failed authentication activity detected"

    Write-Host ""
Write-Host "ALERT: $threshold or more failed logons detected within the last $windowMinutes minutes!"
Write-Host "ACTION: Investigate the authentication events immediately."
}
else {
    Write-Host ""
    Write-Host "STATUS: No alert threshold reached."
}




