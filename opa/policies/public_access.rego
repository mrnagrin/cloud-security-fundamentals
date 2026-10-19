package terraform.s3.public_access

import data.terraform.s3.lib
import rego.v1

# NIST 800-53 AC-3: Access Enforcement
# Every S3 bucket must block all four forms of public access.

control_type := "aws_s3_bucket_public_access_block"

required_flags := [
	"block_public_acls",
	"ignore_public_acls",
	"block_public_policy",
	"restrict_public_buckets",
]

# Bucket has no public access block at all
deny contains msg if {
	some bucket in lib.buckets
	count(lib.attached(bucket, control_type)) == 0
	msg := sprintf("AC-3: %s has no public access block", [bucket])
}

# Public access block exists but a setting is missing or not true
deny contains msg if {
	some bucket in lib.buckets
	some rc in lib.attached(bucket, control_type)
	some flag in required_flags
	object.get(rc.change.after, flag, false) != true
	msg := sprintf("AC-3: %s has %s not set to true", [bucket, flag])
}
