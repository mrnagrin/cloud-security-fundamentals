# Python Compliance Automation

Scripts that use `boto3` to pull live AWS configuration data and evaluate it
against compliance controls — the first step toward automated evidence
collection instead of manual screenshot-based audits.

## iam_compliance_audit.py

Connects to AWS IAM and audits every user in the account for:

| Check | Maps to | What it catches |
|---|---|---|
| MFA enabled | NIST 800-53 IA-2(1) | Users who can authenticate with password alone |
| Access key age (>90 days) | NIST 800-53 IA-5 | Stale credentials that should be rotated |
| Console password last used | NIST 800-53 AC-2 | Stale/inactive accounts that should be disabled |

**Output:** a timestamped CSV with one row per IAM user, plus a pass/fail
summary printed to the terminal — usable directly as audit evidence.

### Setup

```bash
pip install boto3
aws configure   # if not already set up
```

### Usage

```bash
python3 iam_compliance_audit.py
```

Optional flags:
```bash
python3 iam_compliance_audit.py --output my_report.csv
python3 iam_compliance_audit.py --profile my-named-profile
```

### Required IAM permissions

The IAM user/role running this script needs (read-only):
```
iam:ListUsers
iam:ListMFADevices
iam:ListAccessKeys
iam:GetAccessKeyLastUsed
iam:GetLoginProfile
```

### Sample output columns

```
username, user_created_date, mfa_enabled, has_console_password,
password_last_used_days_ago, flagged_stale_account, num_access_keys,
oldest_access_key_age_days, access_key_rotation_compliant, overall_compliant
```

### Why this matters

This is a small-scale version of what a Continuous Controls Monitoring (CCM)
platform does at an organizational level: instead of an auditor manually
checking IAM settings once a quarter, a script pulls the live configuration
on demand (or on a schedule) and evaluates it against the same control
objectives an auditor would test — MFA enforcement, credential rotation,
and account activity monitoring.
