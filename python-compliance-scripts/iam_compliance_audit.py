#!/usr/bin/env python3
"""
iam_compliance_audit.py

Compliance automation script — audits all IAM users in an AWS account and
reports on control-relevant attributes:
    - MFA enabled (maps to NIST 800-53 IA-2(1), AC-6)
    - Access key age (maps to NIST 800-53 IA-5, credential rotation)
    - Console password last used (maps to AC-2, account monitoring)
    - Whether the user has ever logged in (flags stale/unused accounts)

Output: a timestamped CSV report, suitable as audit evidence or as input
to a continuous controls monitoring (CCM) pipeline.

Usage:
    python3 iam_compliance_audit.py
    python3 iam_compliance_audit.py --output my_report.csv
    python3 iam_compliance_audit.py --profile my-aws-profile

Requires:
    pip install boto3
    AWS credentials configured (via `aws configure` or environment variables)
    IAM permissions needed: iam:ListUsers, iam:ListMFADevices,
                             iam:ListAccessKeys, iam:GetAccessKeyLastUsed,
                             iam:GetLoginProfile
"""

import argparse
import csv
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound


# ---- Control thresholds (adjust to your org's policy) ----
ACCESS_KEY_MAX_AGE_DAYS = 90   # NIST IA-5 / common credential rotation policy
STALE_ACCOUNT_DAYS = 90        # flags users who haven't logged in recently


def get_iam_client(profile_name=None):
    """Create a boto3 IAM client, optionally using a named profile."""
    try:
        session = boto3.Session(profile_name=profile_name) if profile_name else boto3.Session()
        return session.client("iam")
    except ProfileNotFound:
        print(f"Error: AWS profile '{profile_name}' not found. Check ~/.aws/config.")
        sys.exit(1)


def days_since(dt):
    """Return integer days between now (UTC) and a given datetime, or None."""
    if dt is None:
        return None
    now = datetime.now(timezone.utc)
    return (now - dt).days


def check_mfa(iam_client, username):
    """Return True if the user has at least one MFA device attached."""
    try:
        response = iam_client.list_mfa_devices(UserName=username)
        return len(response.get("MFADevices", [])) > 0
    except ClientError as e:
        print(f"  Warning: could not check MFA for {username}: {e}")
        return None


def check_access_keys(iam_client, username):
    """
    Return a list of dicts describing each access key's age and last-used date.
    Flags keys older than ACCESS_KEY_MAX_AGE_DAYS as non-compliant.
    """
    key_info = []
    try:
        response = iam_client.list_access_keys(UserName=username)
        for key in response.get("AccessKeyMetadata", []):
            key_id = key["AccessKeyId"]
            age_days = days_since(key["CreateDate"])

            try:
                last_used_resp = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                last_used = last_used_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
            except ClientError:
                last_used = None

            key_info.append({
                "key_id_suffix": key_id[-4:],  # never log the full key ID/secret
                "status": key["Status"],
                "age_days": age_days,
                "last_used_days_ago": days_since(last_used),
                "compliant": age_days is not None and age_days <= ACCESS_KEY_MAX_AGE_DAYS,
            })
    except ClientError as e:
        print(f"  Warning: could not check access keys for {username}: {e}")

    return key_info


def check_console_login(iam_client, username):
    """
    Return (has_console_password, days_since_last_login).
    Users with no login profile are API/CLI-only accounts.
    """
    try:
        iam_client.get_login_profile(UserName=username)
        has_password = True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            has_password = False
        else:
            print(f"  Warning: could not check login profile for {username}: {e}")
            has_password = None

    return has_password


def audit_users(iam_client):
    """Pull all IAM users and run each compliance check against them."""
    results = []
    paginator = iam_client.get_paginator("list_users")

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            print(f"Auditing user: {username}")

            mfa_enabled = check_mfa(iam_client, username)
            access_keys = check_access_keys(iam_client, username)
            has_console_password = check_console_login(iam_client, username)
            password_last_used_days = days_since(user.get("PasswordLastUsed"))

            # Flatten access key info for CSV — most users have 0-2 keys
            oldest_key_age = max(
                (k["age_days"] for k in access_keys if k["age_days"] is not None),
                default=None,
            )
            any_key_noncompliant = any(not k["compliant"] for k in access_keys)

            is_stale = (
                password_last_used_days is not None
                and password_last_used_days > STALE_ACCOUNT_DAYS
            )

            results.append({
                "username": username,
                "user_created_date": user["CreateDate"].strftime("%Y-%m-%d"),
                "mfa_enabled": mfa_enabled,
                "has_console_password": has_console_password,
                "password_last_used_days_ago": password_last_used_days,
                "flagged_stale_account": is_stale,
                "num_access_keys": len(access_keys),
                "oldest_access_key_age_days": oldest_key_age,
                "access_key_rotation_compliant": not any_key_noncompliant,
                "overall_compliant": bool(mfa_enabled) and not any_key_noncompliant and not is_stale,
            })

    return results


def write_csv(results, output_path):
    """Write audit results to a CSV file."""
    if not results:
        print("No IAM users found — nothing to write.")
        return

    fieldnames = list(results[0].keys())
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nReport written to: {output_path}")


def print_summary(results):
    """Print a quick pass/fail summary to the terminal."""
    total = len(results)
    compliant = sum(1 for r in results if r["overall_compliant"])
    no_mfa = sum(1 for r in results if r["mfa_enabled"] is False)
    stale = sum(1 for r in results if r["flagged_stale_account"])
    bad_keys = sum(1 for r in results if not r["access_key_rotation_compliant"])

    print("\n" + "=" * 50)
    print("IAM COMPLIANCE AUDIT SUMMARY")
    print("=" * 50)
    print(f"Total IAM users audited:      {total}")
    print(f"Fully compliant users:        {compliant}")
    print(f"Users without MFA:            {no_mfa}   (maps to NIST IA-2(1))")
    print(f"Users with stale access keys: {bad_keys}   (maps to NIST IA-5)")
    print(f"Stale/inactive accounts:      {stale}   (maps to NIST AC-2)")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(description="Audit IAM users for compliance controls.")
    parser.add_argument(
        "--output",
        default=f"iam_compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        help="Output CSV file path (default: timestamped filename)",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS named profile to use (default: default profile / env vars)",
    )
    args = parser.parse_args()

    iam_client = get_iam_client(args.profile)

    try:
        results = audit_users(iam_client)
    except NoCredentialsError:
        print("Error: No AWS credentials found. Run `aws configure` first.")
        sys.exit(1)
    except ClientError as e:
        print(f"AWS API error: {e}")
        sys.exit(1)

    write_csv(results, args.output)
    print_summary(results)


if __name__ == "__main__":
    main()
