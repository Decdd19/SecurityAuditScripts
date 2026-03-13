# ☁️ Cloud Audit Scripts

[![CI](https://github.com/Decdd19/SecurityAuditScripts/actions/workflows/ci.yml/badge.svg)](https://github.com/Decdd19/SecurityAuditScripts/actions/workflows/ci.yml)

A collection of security auditing scripts for AWS and other cloud platforms. Built for cloud security engineers, sysadmins, and anyone who wants visibility into their cloud environment without relying solely on commercial tooling.

> **Purpose:** Practical, standalone scripts that give you real security insight. No agents, no SaaS dependencies — just run and review.

---

## 📁 Repository Structure

```
SecurityAuditScripts/
├── README.md
└── aws/
    ├── README.md
    ├── iam-privilege-mapper/
    │   ├── iam_mapper_v2.py
    │   └── README.md
    ├── s3-auditor/
    │   ├── s3_auditor.py
    │   └── README.md
    ├── cloudtrail-auditor/
    │   ├── cloudtrail_auditor.py
    │   └── README.md
    ├── security-group-auditor/
    │   ├── sg_auditor.py
    │   └── README.md
    └── root-account-auditor/
        ├── root_auditor.py
        └── README.md
```

> More scripts covering additional AWS services and other cloud platforms coming soon.

---

## 🛠️ Scripts

### AWS

| Script | Description | Output |
|--------|-------------|--------|
| [IAM Privilege Mapper](./aws/iam-privilege-mapper/) | Maps IAM users, roles, and groups. Identifies high-risk permissions, privilege escalation paths, stale credentials, and MFA gaps. | JSON, CSV, HTML |
| [S3 Bucket Auditor](./aws/s3-auditor/) | Audits all S3 buckets for public access, missing encryption, versioning, logging, and lifecycle policies. | JSON, CSV, HTML |
| [CloudTrail Auditor](./aws/cloudtrail-auditor/) | Checks CloudTrail coverage across all regions for logging gaps, missing KMS encryption, and CloudWatch integration. | JSON, CSV, HTML |
| [Security Group Auditor](./aws/security-group-auditor/) | Scans all security groups across all regions for dangerous open ports, unrestricted ingress, and unused groups. | JSON, CSV, HTML |
| [Root Account Auditor](./aws/root-account-auditor/) | Audits root account security posture including MFA, access keys, password policy, and alternate contacts. | JSON, CSV, HTML |

---

## ⚙️ General Requirements

- Python 3.7+
- `boto3` (`pip install boto3`)
- AWS credentials configured (see below)

### AWS Authentication

All AWS scripts use `boto3` and will pick up credentials in the following order:

1. **AWS CloudShell** — credentials are pre-configured, just upload and run
2. **Environment variables:**
   ```bash
   export AWS_ACCESS_KEY_ID=your_key
   export AWS_SECRET_ACCESS_KEY=your_secret
   export AWS_DEFAULT_REGION=us-east-1
   ```
3. **AWS CLI profile** (`aws configure`) — most scripts support `--profile` flag
4. **IAM role** — if running on EC2/Lambda, the instance/execution role is used automatically

---

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/Decdd19/SecurityAuditScripts.git
cd SecurityAuditScripts

# Install dependencies
pip install boto3

# Run a script (example)
python3 aws/iam-privilege-mapper/iam_mapper_v2.py --format html --output iam_report
```

---

## 📌 Notes

- Scripts are **read-only** — they query APIs and do not make any changes to your environment
- Designed to run in **AWS CloudShell** with zero setup, or locally with credentials configured
- Output files are written to the current working directory unless specified otherwise
- All scripts support `--format` (json, csv, html, all) and `--profile` flags

---

## 🤝 Contributing

Feel free to open a PR or raise an issue if you have improvements, bug fixes, or want to add a script for another service.

---

## ⚠️ Disclaimer

These scripts are provided for **internal security auditing purposes only**. Always ensure you have appropriate authorisation before running security tooling against any cloud environment.
