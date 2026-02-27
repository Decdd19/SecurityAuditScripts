# 🔐 IAM Privilege Mapper v2

A Python script that enumerates all IAM users, roles, and groups in your AWS account, identifies high-risk permissions, flags privilege escalation paths, and produces a detailed security report.

---

## ✨ Features

- **Full IAM enumeration** — users, roles, and groups including inherited group permissions
- **High-risk action detection** — flags dangerous permissions like `iam:*`, `s3:*`, `sts:AssumeRole`, wildcards and more
- **Privilege escalation path analysis** — checks 10 known IAM privesc vectors (e.g. PassRole + Lambda, attach policy to self)
- **Stale credential detection** — flags access keys older than 90 days, never-used keys, dormant keys, and multiple active keys
- **MFA gap detection** — identifies console users without MFA enabled
- **Permission boundary awareness** — factors in boundaries when calculating risk score
- **Cross-account role trust detection** — flags roles assumable by external accounts
- **SCP analysis** — if running in an AWS Organisation, effective SCPs are factored in to reduce false positives
- **Numeric severity scoring** — each principal scored 1–10 based on weighted risk factors
- **Multiple output formats** — JSON, CSV, and a colour-coded HTML report

---

## 📋 Requirements

- Python 3.7+
- `boto3`

```bash
pip install boto3
```

### Required IAM Permissions

The script is **read-only** and requires the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:List*",
        "iam:Get*",
        "sts:GetCallerIdentity",
        "organizations:ListPoliciesForTarget",
        "organizations:DescribePolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

> The `organizations:*` permissions are optional — only needed for SCP analysis. The script will skip SCP checks gracefully if not available.

---

## 🚀 Usage

### AWS CloudShell (Recommended)

1. Open **AWS CloudShell** in your AWS Console
2. Click **Actions → Upload file** and upload `iam_mapper_v2.py`
3. Run:

```bash
python3 iam_mapper_v2.py
```

This will generate `iam_report.json`, `iam_report.csv`, and `iam_report.html` in your current directory.

---

### Command Line Options

```
python3 iam_mapper_v2.py [OPTIONS]

Options:
  --output,  -o    Output file prefix          (default: iam_report)
  --format,  -f    Output format               (default: all)
                   choices: json | csv | html | all | stdout
  --principal-type Limit scan to one type      (default: all)
                   choices: all | users | roles | groups
  --profile        AWS CLI profile to use      (default: current session)
```

### Examples

```bash
# Full scan, all output formats
python3 iam_mapper_v2.py

# CSV output only
python3 iam_mapper_v2.py --format csv

# HTML report with custom filename
python3 iam_mapper_v2.py --format html --output my_audit

# Scan users only, print to terminal
python3 iam_mapper_v2.py --principal-type users --format stdout

# Use a specific AWS CLI profile
python3 iam_mapper_v2.py --profile prod-account

# Scan roles only and save to a specific prefix
python3 iam_mapper_v2.py --principal-type roles --output roles_audit
```

---

## 📊 Output

### Terminal Summary

After every run a quick summary is printed:

```
╔══════════════════════════════════════════╗
║         IAM MAPPER v2 — SUMMARY          ║
╠══════════════════════════════════════════╣
║  Total principals:    42                 ║
║  CRITICAL:            3                  ║
║  HIGH:                8                  ║
║  MEDIUM:              11                 ║
║  LOW:                 20                 ║
║  No MFA (console):    2                  ║
║  Stale access keys:   5                  ║
║  Cross-account roles: 1                  ║
║  Admin policy holders:2                  ║
╚══════════════════════════════════════════╝
```

### Risk Levels

| Score | Level    | Meaning |
|-------|----------|---------|
| 8–10  | CRITICAL | Wildcard permissions, admin policy, or multiple privesc paths |
| 5–7   | HIGH     | High-risk actions or a privesc path present |
| 2–4   | MEDIUM   | Some elevated permissions, stale keys, or missing MFA |
| 0–1   | LOW      | Minimal permissions, no significant findings |

### Key Issues Column (CSV / HTML)

The **Key Issues** column flags the following for each user's access keys:

| Issue | Description |
|-------|-------------|
| `Key AKIA... is X days old` | Active key exceeds the 90-day rotation policy |
| `Key AKIA... has never been used` | Active key created but never called |
| `Key AKIA... unused for X days` | Active key dormant for over 90 days |
| `Multiple active access keys detected` | User has more than one active key simultaneously |

> The 90-day threshold can be adjusted by changing `ACCESS_KEY_MAX_AGE_DAYS` and `CREDENTIAL_UNUSED_DAYS` at the top of the script.

---

## 🔍 Privilege Escalation Paths Checked

| Path | Actions Required |
|------|-----------------|
| Attach policy to self | `iam:AttachUserPolicy` |
| Create & set new policy version | `iam:CreatePolicyVersion` + `iam:SetDefaultPolicyVersion` |
| PassRole + Lambda invoke | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` |
| PassRole + EC2 run | `iam:PassRole` + `ec2:RunInstances` |
| PassRole + CloudFormation | `iam:PassRole` + `cloudformation:CreateStack` |
| Add user to privileged group | `iam:AddUserToGroup` |
| Create access key for other user | `iam:CreateAccessKey` |
| Reset another user's password | `iam:UpdateLoginProfile` |
| Inline policy injection | `iam:PutUserPolicy` |
| Attach role policy escalation | `iam:AttachRolePolicy` |

---

## ⚠️ Disclaimer

This script is provided for **authorised internal security auditing only**. Ensure you have appropriate permissions before running against any AWS account.
