# ☁️ Cloud Audit Scripts

A collection of security auditing scripts for AWS and other cloud platforms. Built for cloud security engineers, sysadmins, and anyone who wants visibility into their cloud environment without relying solely on commercial tooling.

> **Purpose:** Practical, standalone scripts that give you real security insight. No agents, no SaaS dependencies — just run and review.

---

## 📁 Repository Structure

```
cloud-audit-scripts/
├── aws/
│   └── iam-privilege-mapper/
│       ├── iam_mapper_v2.py
│       └── README.md
├── README.md
```

> More scripts covering additional AWS services and other cloud platforms coming soon.

---

## 🛠️ Scripts

### AWS

| Script | Description | Output |
|--------|-------------|--------|
| [IAM Privilege Mapper](./aws/iam-privilege-mapper/) | Maps IAM users, roles, and groups. Identifies high-risk permissions, privilege escalation paths, stale credentials, and MFA gaps. | JSON, CSV, HTML |

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
git clone https://github.com/yourusername/cloud-audit-scripts.git
cd cloud-audit-scripts

# Install dependencies
pip install boto3

# Run a script (example)
python3 aws/iam-privilege-mapper/iam_mapper_v2.py
```

---

## 📌 Notes

- Scripts are **read-only** — they query APIs and do not make any changes to your environment
- Designed to run in **AWS CloudShell** with zero setup, or locally with credentials configured
- Output files are written to the current working directory unless specified otherwise

---

## 🤝 Contributing

Feel free to open a PR or raise an issue if you have improvements, bug fixes, or want to add a script for another service.

---

## ⚠️ Disclaimer

These scripts are provided for **internal security auditing purposes only**. Always ensure you have appropriate authorisation before running security tooling against any cloud environment.
