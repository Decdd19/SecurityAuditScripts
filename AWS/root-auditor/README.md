# 👑 Root Account Auditor

Audits the security posture of your AWS root account. Checks MFA status, active access keys, recent root usage, password policy strength, alternate contacts, and AWS Organizations membership — producing a colour-coded HTML report alongside JSON and CSV outputs.

---

## ✨ Features

- Root account MFA status (virtual and hardware MFA detection)
- Root access key detection — flags any active root keys
- Root account last login and recent usage detection
- IAM credential report analysis
- Account password policy evaluation against best practices
- Alternate contact checks (Billing, Operations, Security)
- AWS Organizations management account detection
- AWS Support plan tier detection
- Numeric severity scoring (1–10)
- JSON, CSV, and colour-coded HTML output

---

## ⚙️ Requirements

- Python 3.7+
- `boto3` — `pip install boto3`

### IAM Permissions Required

```json
{
  "Effect": "Allow",
  "Action": ["iam:GetAccountSummary", "iam:GetAccountPasswordPolicy",
             "iam:GenerateCredentialReport", "iam:GetCredentialReport",
             "iam:ListVirtualMFADevices", "sts:GetCallerIdentity",
             "organizations:DescribeOrganization", "support:DescribeSeverityLevels",
             "account:GetAlternateContact"],
  "Resource": "*"
}
```

> `support:DescribeSeverityLevels` and `account:GetAlternateContact` are optional — the script handles missing permissions gracefully.

---

## 🚀 Usage

### AWS CloudShell
1. Upload `root_auditor.py` via **Actions → Upload file**
2. Run:
```bash
python3 root_auditor.py
```

### Options

```bash
python3 root_auditor.py --format html --output root_report      # HTML only
python3 root_auditor.py --format all                            # JSON + CSV + HTML
python3 root_auditor.py --format csv                            # CSV only
python3 root_auditor.py --profile prod-account                  # Specific AWS profile
```

---

## 📊 Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| Root MFA not enabled | +5 |
| Active root access keys present | +4 |
| Root account used recently (<90 days) | +3 |
| Weak password policy | +2 |
| Missing alternate contacts | +1 |

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | No MFA and/or active root access keys |
| 5–7 | HIGH | No MFA or active keys |
| 2–4 | MEDIUM | Weak password policy or missing contacts |
| 0–1 | LOW | Minor gaps only |

---

## 🔑 Root Account Best Practices

- **Never** create or use root access keys — delete them immediately if they exist
- Enable hardware MFA on the root account where possible
- Do not use root for day-to-day operations — create IAM users or roles
- Set all three alternate contacts (Billing, Operations, Security)
- Enable a strong password policy across the account

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
