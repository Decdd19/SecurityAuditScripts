# 🟠 AWS Audit Scripts

Security auditing scripts for AWS environments. All scripts are read-only, require only standard IAM read permissions, and are designed to run in AWS CloudShell with zero setup.

---

## 📋 Scripts

| Script | Folder | Description |
|--------|--------|-------------|
| IAM Privilege Mapper | [iam-privilege-mapper](./iam-privilege-mapper/) | Maps IAM users, roles, and groups. Flags high-risk permissions, privilege escalation paths, stale credentials, and MFA gaps. |
| S3 Bucket Auditor | [s3-auditor](./s3-auditor/) | Audits all S3 buckets for public access, encryption, versioning, logging, and lifecycle policies. |
| CloudTrail Auditor | [cloudtrail-auditor](./cloudtrail-auditor/) | Checks CloudTrail across all regions for logging gaps, KMS encryption, and CloudWatch integration. |
| Security Group Auditor | [security-group-auditor](./security-group-auditor/) | Scans all security groups across all regions for open ports, unrestricted ingress, and unused groups. |
| Root Account Auditor | [root-account-auditor](./root-account-auditor/) | Audits root account MFA, access keys, password policy, and alternate contacts. |

---

## ⚙️ Requirements

- Python 3.7+
- `boto3` — `pip install boto3`
- AWS credentials (CloudShell, environment variables, or `aws configure`)

---

## 🚀 Run All Scripts (HTML output)

```bash
python3 iam-privilege-mapper/iam_mapper_v2.py --format html --output iam_report
python3 s3-auditor/s3_auditor.py --format html --output s3_report
python3 cloudtrail-auditor/cloudtrail_auditor.py --format html --output cloudtrail_report
python3 security-group-auditor/sg_auditor.py --format html --output sg_report
python3 root-account-auditor/root_auditor.py --format html --output root_report
```

---

## 🔐 Required IAM Permissions

All scripts require read-only access. At minimum:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:List*", "iam:Get*",
        "s3:List*", "s3:GetBucket*",
        "cloudtrail:Describe*", "cloudtrail:Get*", "cloudtrail:List*",
        "ec2:Describe*",
        "sts:GetCallerIdentity",
        "organizations:List*", "organizations:Describe*",
        "support:DescribeSeverityLevels"
      ],
      "Resource": "*"
    }
  ]
}
```

> In AWS CloudShell your session credentials are used automatically — no additional setup needed as long as your IAM user or role has the above permissions.
