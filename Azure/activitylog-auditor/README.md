# 📋 Activity Log Auditor

Audits Azure Activity Log diagnostic settings across your subscription — checking for logging gaps, missing categories, short retention, and absent alerting on critical operations. Azure equivalent of the [cloudtrail-auditor](../../AWS/cloudtrail-auditor/).

---

## ✨ Features

- Detects subscriptions with no Activity Log diagnostic setting configured
- Flags settings with no active log destination (Log Analytics, Storage Account, or Event Hub)
- Checks for missing critical log categories: `Administrative`, `Security`, `Policy`, `Alert`
- Retention audit:
  - Storage account destination: checks `retentionPolicy.days`
  - Log Analytics destination: checks workspace `retentionInDays`
  - Event Hub destination: flagged as unverifiable (no native retention surface)
- Checks for Activity Log alerts on critical operations: role assignment changes, policy changes, resource group deletions
- Numeric severity scoring (1–10)
- JSON, CSV, and colour-coded HTML output

---

## ⚙️ Requirements

- PowerShell 7+
- `Az.Accounts`, `Az.Monitor`
- `Az.OperationalInsights` (optional — used for workspace retention checks if a Log Analytics destination is found)

```powershell
Install-Module Az.Accounts, Az.Monitor -Scope CurrentUser
Connect-AzAccount
```

---

## 🚀 Usage

### Azure CloudShell

Upload `activitylog_auditor.ps1` and run:

```powershell
.\activitylog_auditor.ps1
```

### Options

```powershell
.\activitylog_auditor.ps1                          # Current subscription, all formats
.\activitylog_auditor.ps1 -AllSubscriptions        # All accessible subscriptions
.\activitylog_auditor.ps1 -Format html             # HTML output only
.\activitylog_auditor.ps1 -Format stdout           # Print JSON to console
.\activitylog_auditor.ps1 -Output my_report        # Custom output file prefix
```

---

## 📊 Severity Scoring

| Finding | Severity | Score |
|---------|----------|-------|
| No diagnostic setting configured | CRITICAL | 9 |
| No log destination configured | CRITICAL | 9 |
| Missing critical log category | HIGH | 7 |
| No Activity Log alerts configured | HIGH | 6 |
| Log retention under 90 days | MEDIUM | 5 |
| Workspace retention under 90 days | MEDIUM | 4 |
| Event Hub retention unverifiable | LOW | 1 |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
