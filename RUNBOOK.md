# Engagement Runbook

End-to-end workflow for a SecurityAuditScripts engagement: pre-flight → run → report → brief.

---

## Pre-flight checklist

Complete before arriving on-site or starting a remote session.

### Your machine (Linux/Mac — for Python auditors)

- [ ] Python 3.10+ available (`python3 --version`)
- [ ] pip dependencies installed (`pip install -r requirements.txt` from repo root)
- [ ] AWS credentials configured if doing AWS (`aws sts get-caller-identity`)
- [ ] Client domain name confirmed (e.g. `acme.ie`)

### Windows machine (your laptop or client's — for Azure/M365/Windows auditors)

- [ ] PowerShell 7+ (`pwsh --version`)
- [ ] Az module: `Install-Module Az -Scope CurrentUser -Force`
- [ ] Microsoft.Graph module: `Install-Module Microsoft.Graph -Scope CurrentUser -Force`
- [ ] ExchangeOnlineManagement module (for exchange auditor): `Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force`
- [ ] Authenticated to Azure: `Connect-AzAccount` (use Global Admin or Security Reader)
- [ ] Authenticated to Graph: `Connect-MgGraph -Scopes "User.Read.All","Policy.Read.All","DeviceManagementManagedDevices.Read.All","RoleManagement.Read.Directory","Application.Read.All"`
- [ ] Exchange connected (if running exchange auditor): `Connect-ExchangeOnline`
- [ ] Client's LAN CIDR range noted (ask IT manager: "What subnet are your office machines on?" — typically `192.168.1.0/24` or `10.0.0.0/24`)
- [ ] Running as local administrator if auditing on-prem Windows hosts

---

## Phase 1 — No-credentials quick start (run first, anywhere)

These auditors need only the client's domain. Run them from your Linux/Mac machine while waiting for credentials.

```bash
cd ~/Claude/SecurityAuditScripts
python3 audit.py --client "Acme Corp" --email --ssl --http-headers \
  --domain acme.ie --output ./reports/
```

Produces: `email_report`, `ssl_report`, `http_headers_report`. Takes ~30 seconds.
Good opener: shows the external posture before you touch anything inside the tenant.

---

## Phase 2 — Azure / M365 / Windows (Run-Audit.ps1 on Windows)

Run this on the Windows machine with the Az + Graph modules authenticated.

```powershell
cd \path\to\SecurityAuditScripts

# Azure + M365 + Windows on-prem (everything except netexpose)
.\Run-Audit.ps1 -Client "Acme Corp" -All -AllSubscriptions -Open

# Azure only
.\Run-Audit.ps1 -Client "Acme Corp" -Azure -AllSubscriptions

# M365 only
.\Run-Audit.ps1 -Client "Acme Corp" -M365

# Windows on-prem only (run as administrator)
.\Run-Audit.ps1 -Client "Acme Corp" -Windows
```

Output lands in `.\acme_corp_YYYYMMDD\`.

### Network exposure scan (separate step — needs CIDR)

```powershell
.\OnPrem\Windows\netexpose-auditor\netexpose_auditor.ps1 `
  -Target 192.168.1.0/24 `
  -Output .\acme_corp_YYYYMMDD\netexpose_report
```

Adjust `-TimeoutMs 500` on fast LANs, `-ThrottleLimit 25` if the network is congested.

---

## Phase 3 — AWS (audit.py on Linux/Mac)

```bash
# Full AWS audit
python3 audit.py --client "Acme Corp" --aws \
  --profile acme-prod --regions eu-west-1 \
  --output ./reports/

# Linux on-prem (run directly on target host)
python3 audit.py --client "Acme Corp" --linux --output ./reports/
```

---

## Phase 4 — Copy-back and generate executive summary

1. Copy the client folder from the Windows machine to your Linux machine:

   ```bash
   # Example via scp (adjust path)
   scp -r user@windowshost:C:/SecurityAuditScripts/acme_corp_20260407/ \
     ./reports/Acme-Corp-2026-04-07/
   ```

   Or use a USB drive, shared folder, or OneDrive. The folder just needs to contain all `*_report.json` files in one directory.

2. Generate the executive summary:

   ```bash
   python3 tools/exec_summary.py \
     --input-dir ./reports/Acme-Corp-2026-04-07/ \
     --output    ./reports/Acme-Corp-2026-04-07/exec_summary.html \
     --client-name "Acme Corp"
   ```

   Or if you ran `Run-Audit.ps1` with Python available on the Windows machine, the summary is generated automatically (pass `-Open` to open it in the browser immediately).

---

## Phase 5 — Brief the client

The executive summary HTML is self-contained — open it in any browser, no internet required. Walk the client through:

1. **Overall score and grade** — frame as "this is where you are today; here's what B looks like"
2. **CRITICAL findings first** — each has a remediation step written for an IT manager, not a security engineer
3. **Quick wins table** — "here are 5 things your IT person can fix this afternoon"
4. **Pillar cards** — show which areas are clean vs need attention

Avoid reading finding detail verbatim. Translate: "RDP exposed on 3 hosts" → "anyone on your Wi-Fi could try to log into those servers directly."

---

## Module/permissions reference

| Auditor group | Auth required | Module |
|---|---|---|
| Azure (all) | Az context | `Az` |
| Entra / M365 (users, CA, MFA) | Graph | `Microsoft.Graph` |
| Exchange Online | Exchange session | `ExchangeOnlineManagement` |
| Windows on-prem | Local admin | (built-in PS cmdlets) |
| AWS | CLI profile | `aws` CLI |
| Email / SSL / HTTP headers | None | (DNS + TCP only) |
| netexpose | None (LAN access) | (built-in .NET TCP) |
