# 🔍 CloudTrail Auditor

Audits AWS CloudTrail configuration across all regions. Checks for logging gaps, missing KMS encryption, CloudWatch integration, log file validation, and sweeps all 18 AWS regions to identify any with zero trail coverage.

---

## ✨ Features

- Checks all trails for active logging status and last delivery errors
- Multi-region trail coverage verification
- Log file validation (integrity checking) status
- CloudWatch Logs integration check
- KMS encryption on log files
- S3 bucket public access check for trail log buckets
- Management and data event selector analysis
- Sweeps all 18 AWS regions for coverage gaps
- SNS notification status
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
  "Action": ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
             "cloudtrail:GetEventSelectors", "s3:GetPublicAccessBlock",
             "sts:GetCallerIdentity"],
  "Resource": "*"
}
```

---

## 🚀 Usage

### AWS CloudShell
1. Upload `cloudtrail_auditor.py` via **Actions → Upload file**
2. Run:
```bash
python3 cloudtrail_auditor.py
```

### Options

```bash
python3 cloudtrail_auditor.py --format html --output cloudtrail_report      # HTML only
python3 cloudtrail_auditor.py --format all                                  # JSON + CSV + HTML
python3 cloudtrail_auditor.py --format csv                                  # CSV only
python3 cloudtrail_auditor.py --profile prod-account                        # Specific AWS profile
```

---

## 📊 Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| Trail not actively logging | +5 |
| Trail S3 bucket is public | +3 |
| No KMS encryption | +2 |
| No CloudWatch Logs integration | +2 |
| Log file validation disabled | +1 |
| Single-region trail only | +1 |
| Global service events not captured | +1 |

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | Trail inactive or logs publicly accessible |
| 5–7 | HIGH | No KMS or CloudWatch, multiple gaps |
| 2–4 | MEDIUM | Missing validation or single-region only |
| 0–1 | LOW | Minor gaps only |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
