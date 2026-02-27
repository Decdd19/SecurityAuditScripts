# 🪣 S3 Bucket Auditor

Audits every S3 bucket in your AWS account for common security misconfigurations. Checks public access, encryption, versioning, logging, and bucket policies — producing a colour-coded HTML report alongside JSON and CSV outputs.

---

## ✨ Features

- Public access detection — ACLs, bucket policies, and Block Public Access config
- Encryption check — flags unencrypted buckets, distinguishes AES256 vs KMS
- Versioning status — flags disabled versioning and checks MFA Delete
- Access logging — identifies buckets with no access logs configured
- Lifecycle policy detection — flags buckets with no lifecycle rules
- Bucket policy analysis — parses for public Allow statements
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
  "Action": ["s3:ListAllMyBuckets", "s3:GetBucket*", "s3:GetPublicAccessBlock",
             "s3:ListBucket", "sts:GetCallerIdentity"],
  "Resource": "*"
}
```

---

## 🚀 Usage

### AWS CloudShell
1. Upload `s3_auditor.py` via **Actions → Upload file**
2. Run:
```bash
python3 s3_auditor.py
```

### Options

```bash
python3 s3_auditor.py --format html --output s3_report      # HTML only
python3 s3_auditor.py --format all                          # JSON + CSV + HTML
python3 s3_auditor.py --format csv                          # CSV only
python3 s3_auditor.py --profile prod-account                # Specific AWS profile
```

---

## 📊 Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| Bucket publicly accessible | +5 |
| Public bucket policy | +3 |
| Block Public Access not fully enabled | +2 |
| No encryption at rest | +2 |
| No versioning | +1 |
| No access logging | +1 |

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | Publicly accessible bucket |
| 5–7 | HIGH | Public policy or multiple misconfigs |
| 2–4 | MEDIUM | Missing encryption or versioning |
| 0–1 | LOW | Minor gaps only |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
