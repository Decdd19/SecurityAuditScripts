# Network Exposure Auditor — Design Spec

**Date:** 2026-04-06
**Scope:** New Windows on-prem auditor — active LAN port scan for dangerous service exposure
**Location:** `OnPrem/Windows/netexpose-auditor/`

---

## Goal

Provide a single PowerShell script that an assessor runs from a laptop on the client's LAN to identify hosts with dangerous services exposed on the network. Covers the most common Irish SMB findings: RDP, SMB, WinRM, LDAP, NetBIOS, RPC, MSSQL.

---

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-Target` | `string` | required | Single IP (`192.168.1.10`) or CIDR range (`192.168.1.0/24`) |
| `-ExtraPorts` | `int[]` | `@()` | Additional ports to probe on top of defaults |
| `-Output` | `string` | `netexpose_report` | Output file prefix |
| `-Format` | `string` | `all` | `json \| csv \| html \| all \| stdout` |
| `-TimeoutMs` | `int` | `1000` | TCP connect timeout in milliseconds |
| `-ThrottleLimit` | `int` | `50` | `ForEach-Object -Parallel` concurrency limit |

---

## Default Port Map

| Finding ID | Port | Service | Severity | CIS Control | Score |
|------------|------|---------|----------|-------------|-------|
| NE-01 | 3389 | RDP | CRITICAL | CIS 12.2 | 9 |
| NE-02 | 445 | SMB | CRITICAL | CIS 12.2 | 9 |
| NE-03 | 139 | NetBIOS | HIGH | CIS 12.2 | 6 |
| NE-04 | 135 | RPC | MEDIUM | CIS 12.2 | 4 |
| NE-05 | 5985 | WinRM HTTP | HIGH | CIS 12.2 | 7 |
| NE-06 | 5986 | WinRM HTTPS | HIGH | CIS 12.2 | 6 |
| NE-07 | 389 | LDAP | MEDIUM | CIS 12.2 | 4 |
| NE-08 | 636 | LDAPS | LOW | CIS 12.2 | 2 |
| NE-09 | 1433 | MSSQL | HIGH | CIS 12.2 | 7 |

Extra ports (`-ExtraPorts`) produce findings with `FindingType: ExposedCustomPort`, severity MEDIUM, score 4, finding ID `NE-XX`.

---

## Architecture

### `Expand-CidrRange [string]$Target → [string[]]`

Converts `-Target` to a flat list of IPs:
- Single IP: passes through as-is
- CIDR: uses .NET `[System.Net.IPAddress]` bitwise math to enumerate host range, skipping network and broadcast addresses
- Invalid input: throws a descriptive error

### `Get-NetworkExposureFindings` (main scan)

Takes the IP list and port list. Dispatches via `ForEach-Object -Parallel -ThrottleLimit $ThrottleLimit`. Each iteration calls:

```powershell
Test-NetConnection -ComputerName $ip -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
```

Returns a finding object for every host+port where `TcpTestSucceeded -eq $true`.

### Stub block

If `Test-NetConnection` is not available (Pester environment), stub it to return `[PSCustomObject]@{ TcpTestSucceeded = $false }`. Tests override with `Mock`.

### Output layer

`ConvertTo-NetExposeJsonReport` / `ConvertTo-NetExposeCsvReport` / `ConvertTo-NetExposeHtmlReport` — same schema as all other auditors:

```json
{
  "generated_at": "...",
  "target": "192.168.1.0/24",
  "summary": { "CRITICAL": 2, "HIGH": 3, "MEDIUM": 1, "LOW": 0 },
  "findings": [ ... ]
}
```

### Finding shape

```powershell
[PSCustomObject]@{
    FindingType    = 'ExposedService'       # or 'ExposedCustomPort' for -ExtraPorts
    Host           = '192.168.1.10'
    Port           = 3389
    Service        = 'RDP'
    Severity       = 'CRITICAL'
    CisControl     = 'CIS 12.2'
    Score          = 9
    Recommendation = 'Restrict RDP (3389) to a management VLAN or VPN. Disable if unused.'
}
```

---

## Testing Strategy (~15 Pester tests)

### `Describe 'Expand-CidrRange'`
- Single IP returns that IP unchanged
- /30 returns exactly 2 host IPs (skips network + broadcast)
- /24 returns exactly 254 IPs
- Invalid string throws

### `Describe 'Get-NetworkExposureFindings'`
- Open RDP port → NE-01 CRITICAL finding with correct Host/Port/Service
- Open SMB port → NE-02 CRITICAL finding
- Closed port → no finding emitted
- Multiple open ports on same host → one finding per port
- `-ExtraPorts` appended → finding with `ExposedCustomPort` type, MEDIUM severity
- All ports closed → empty findings array

### `Describe 'ConvertTo-NetExposeJsonReport'`
- Emits `generated_at`, `target`, `summary`, `findings` fields
- Summary counts match findings array contents

### `Describe 'Integration'`
- CIDR target expands, scan runs end-to-end with mocked `Test-NetConnection`, findings collected correctly

---

## Integration

- Add `netexpose_report.json` to `KNOWN_PATTERNS` and `AZURE_WINDOWS_PATTERNS` in `tools/exec_summary.py`
- Add `"netexpose": "NetExpose / LAN Port Scan"` to `PILLAR_LABELS`
- Add `"netexpose": "OnPrem/Windows/netexpose-auditor/netexpose_auditor.ps1"` to `WINDOWS_PS1` in `audit.py`
- Add entry to `$WindowsAuditors` array in `Run-Audit.ps1`
- Update root `README.md`: directory tree + auditor table

---

## Out of Scope

- UDP scanning
- Service banner grabbing / version detection
- OS fingerprinting
- Authenticated checks (no credentials required)
- Automatic remediation
