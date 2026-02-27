# 🛡️ Security Group Auditor

Scans all EC2 security groups across every AWS region for dangerous misconfigurations. Flags open SSH, RDP, database ports, all-traffic rules, unused groups, and default security group misuse — producing a colour-coded HTML report alongside JSON and CSV outputs.

---

## ✨ Features

- Scans all regions automatically (or a single specified region)
- Detects ingress rules open to `0.0.0.0/0` or `::/0`
- Flags 15 high-risk ports including SSH, RDP, Telnet, MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Docker, and more
- All-traffic open rule detection (`-1` protocol)
- Unused security group detection (not attached to any resource)
- Default security group misuse flagging
- Unrestricted egress rule reporting
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
  "Action": ["ec2:DescribeSecurityGroups", "ec2:DescribeRegions",
             "ec2:DescribeNetworkInterfaces", "sts:GetCallerIdentity"],
  "Resource": "*"
}
```

---

## 🚀 Usage

### AWS CloudShell
1. Upload `sg_auditor.py` via **Actions → Upload file**
2. Run:
```bash
python3 sg_auditor.py
```

### Options

```bash
python3 sg_auditor.py --format html --output sg_report      # HTML only
python3 sg_auditor.py --format all                          # JSON + CSV + HTML
python3 sg_auditor.py --region eu-west-1                    # Single region only
python3 sg_auditor.py --format csv                          # CSV only
python3 sg_auditor.py --profile prod-account                # Specific AWS profile
```

---

## 📊 High-Risk Ports Checked

| Port | Service |
|------|---------|
| 22 | SSH |
| 3389 | RDP |
| 23 | Telnet |
| 21 | FTP |
| 1433 | MSSQL |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 27017 | MongoDB |
| 6379 | Redis |
| 9200 | Elasticsearch |
| 2375 | Docker (unencrypted) |
| 2379 | etcd |
| 445 | SMB |
| 5900 | VNC |
| 8080/8443 | HTTP/HTTPS Alt |

---

## 📊 Risk Scoring

| Factor | Score Impact |
|--------|-------------|
| All traffic open to world | +6 |
| SSH or RDP open to world | +4 |
| Other high-risk ports open | +1–3 |
| Default SG with open rules | +2 |
| Unrestricted egress | +1 |

| Score | Level | Meaning |
|-------|-------|---------|
| 8–10 | CRITICAL | All traffic or SSH/RDP open to world |
| 5–7 | HIGH | SSH or RDP open, or multiple high-risk ports |
| 2–4 | MEDIUM | Some elevated exposure |
| 0–1 | LOW | No significant open rules |

---

## ⚠️ Disclaimer

For authorised internal security auditing only.
