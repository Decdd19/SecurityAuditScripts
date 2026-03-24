# 🛡️ Security Hub Auditor

Audits AWS Security Hub enablement and active findings across all regions. Checks whether Security Hub is enabled, counts active findings by severity, and evaluates enabled compliance standards (CIS, PCI DSS, FSBP) and their control pass rates.

---

## ✨ Features

- Security Hub enablement check per region — not enabled → CRITICAL
- Active finding counts by severity (CRITICAL, HIGH, MEDIUM, LOW)
- Enabled compliance standards detection (CIS AWS Foundations, PCI DSS, FSBP)
- Control pass rate per standard — flags standards below 50% pass rate
- Multi-region sweep across all 18 standard AWS regions
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
  "Action": [
    "securityhub:DescribeHub",
    "securityhub:GetFindings",
    "securityhub:GetEnabledStandards",
    "securityhub:DescribeStandardsControls",
    "ec2:DescribeRegions",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

---

## 🚀 Usage

### AWS CloudShell
1. Upload `securityhub_auditor.py` via **Actions → Upload file**
2. Run:
```bash
python3 securityhub_auditor.py
```

### Options

```bash
python3 securityhub_auditor.py --format html --output sh_report      # HTML only
python3 securityhub_auditor.py --format all                          # JSON + CSV + HTML
python3 securityhub_auditor.py --regions eu-west-1 us-east-1         # Specific regions
python3 securityhub_auditor.py --profile prod-account                # Specific AWS profile
```

---

## 📊 Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| Security Hub not enabled in region | +9 (CRITICAL) |
| Active CRITICAL findings | +2 per finding (max +4) |
| Active HIGH findings | +1 per finding (max +2) |
| No compliance standards enabled | +2 |
| Standard with <50% control pass rate | +1 per standard (max +2) |

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | Security Hub not enabled |
| 4–7 | HIGH | Active CRITICAL findings |
| 2–3 | MEDIUM | No standards or low pass rate |
| 0–1 | LOW | Enabled, clean, standards passing |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
