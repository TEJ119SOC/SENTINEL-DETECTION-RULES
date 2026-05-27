📊 SOC Dashboard Template — Microsoft Sentinel Workbook
A reference guide for building a SOC performance and threat visibility dashboard in Microsoft Sentinel Workbooks. This template covers the key panels, KQL queries, and metrics every SOC dashboard should display.
---
🎯 Dashboard Purpose
A well-built SOC dashboard gives analysts and management instant visibility into:
Current threat landscape — what is happening right now
SOC performance — how fast are we detecting and responding
Trend analysis — are attacks increasing or decreasing
Coverage gaps — what are we not seeing
---
🗂️ Recommended Dashboard Panels
Panel 1 — Alert Volume by Severity (Last 24 Hours)
```kql
SecurityAlert
| where TimeGenerated >= ago(24h)
| summarize AlertCount = count() by AlertSeverity, bin(TimeGenerated, 1h)
| render timechart
```
Visualisation: Line chart — one line per severity level
Purpose: Spot sudden spikes in alert volume that may indicate an active attack
---
Panel 2 — Top 10 Alert Types Today
```kql
SecurityAlert
| where TimeGenerated >= ago(24h)
| summarize Count = count() by AlertName
| top 10 by Count
| render barchart
```
Visualisation: Horizontal bar chart
Purpose: Identify which detection rules are firing most — tune high-volume rules to reduce false positives
---
Panel 3 — Incidents by Status
```kql
SecurityIncident
| where TimeGenerated >= ago(7d)
| summarize Count = count() by Status
| render piechart
```
Visualisation: Pie chart — New / Active / Closed
Purpose: Track backlog — too many "New" incidents = analysts falling behind
---
Panel 4 — Mean Time to Respond (MTTR)
```kql
SecurityIncident
| where TimeGenerated >= ago(30d)
| where Status == "Closed"
| extend
    CreatedTime  = TimeGenerated,
    ClosedTime   = ClosedTime,
    MTTR_Hours   = datetime_diff('hour', ClosedTime, CreatedTime)
| summarize
    AvgMTTR_Hours = avg(MTTR_Hours),
    MinMTTR_Hours = min(MTTR_Hours),
    MaxMTTR_Hours = max(MTTR_Hours)
  by bin(TimeGenerated, 1d)
| render timechart
```
Visualisation: Line chart
Purpose: Core SOC KPI — track whether response times are improving or degrading
---
Panel 5 — Failed Sign-ins by Country (Map)
```kql
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType != "0"
| summarize FailedLogins = count() by Location
| render map
```
Visualisation: World map with heat overlay
Purpose: Instantly spot countries generating high volumes of failed logins
---
Panel 6 — Top Targeted User Accounts
```kql
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType != "0"
| summarize FailedAttempts = count() by UserPrincipalName
| top 10 by FailedAttempts
| render barchart
```
Visualisation: Bar chart
Purpose: Identify accounts under active attack — prioritise monitoring and protection
---
Panel 7 — Endpoint Alerts by Host
```kql
SecurityAlert
| where TimeGenerated >= ago(24h)
| where AlertType has_any ("endpoint", "malware", "process")
| summarize AlertCount = count() by CompromisedEntity
| top 10 by AlertCount
| render barchart
```
Visualisation: Bar chart
Purpose: Identify the most at-risk or already compromised endpoints
---
Panel 8 — MITRE ATT&CK Technique Coverage
```kql
SecurityAlert
| where TimeGenerated >= ago(30d)
| where isnotempty(Tactics)
| summarize Count = count() by Tactics
| render piechart
```
Visualisation: Pie or donut chart
Purpose: Show which MITRE ATT&CK tactics your detections are covering — and which are missing
---
Panel 9 — Alert True Positive Rate
```kql
SecurityIncident
| where TimeGenerated >= ago(30d)
| where Status == "Closed"
| summarize
    TruePositives  = countif(Classification == "TruePositive"),
    FalsePositives = countif(Classification == "FalsePositive"),
    Total          = count()
  by bin(TimeGenerated, 1d)
| extend TPRate = round(todouble(TruePositives) / todouble(Total) * 100, 1)
| render timechart
```
Visualisation: Line chart
Purpose: Track detection quality — a rising TP rate means better tuned rules
---
Panel 10 — Daily Incident Summary (Management View)
```kql
SecurityIncident
| where TimeGenerated >= ago(24h)
| summarize
    Total     = count(),
    Critical  = countif(Severity == "High"),
    Closed    = countif(Status == "Closed"),
    Open      = countif(Status != "Closed")
```
Visualisation: Stat tiles / KPI cards
Purpose: One-glance daily summary for SOC Manager and CISO reporting
---
📋 Key SOC KPIs to Track
KPI	Target	Description
Mean Time to Detect (MTTD)	< 1 hour	Time from attack start to alert firing
Mean Time to Respond (MTTR)	< 4 hours	Time from alert to containment
False Positive Rate	< 20%	Percentage of alerts that are not real threats
True Positive Rate	> 80%	Percentage of alerts that are real threats
Alert Backlog	0 at end of shift	Unreviewed alerts carried over
P1 Incidents This Week	Track trend	Critical incidents — should be decreasing
---
🛠️ How to Build This in Sentinel
Go to Microsoft Sentinel → Workbooks → Add Workbook
Click Edit → Add Query
Paste any KQL query from the panels above
Select the Visualisation type noted for each panel
Set the time range parameter at the top of the workbook
Click Done Editing → Save
Pin your workbook to the Sentinel Overview page for quick access
---
📚 References
Microsoft Sentinel Workbooks Documentation
KQL Quick Reference
MITRE ATT&CK Navigator
