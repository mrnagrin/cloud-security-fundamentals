package terraform.s3.encryption

import data.terraform.s3.lib
import rego.v1

# NIST 800-53 SC-28: Protection of Information at Rest
# Every S3 bucket must have server-side encryption configured with an
# approved algorithm.

control_type := "aws_s3_bucket_server_side_encryption_configuration"

allowed_algorithms := {"AES256", "aws:kms"}

encrypted(rc) if {
	some rule in rc.change.after.rule
	some sse in rule.apply_server_side_encryption_by_default
	sse.sse_algorithm in allowed_algorithms
}

# Bucket has no encryption configuration at all
deny contains msg if {
	some bucket in lib.buckets
	count(lib.attached(bucket, control_type)) == 0
	msg := sprintf("SC-28: %s has no server-side encryption configuration", [bucket])
}

# Encryption configuration exists but doesn't use an approved algorithm
deny contains msg if {
	some bucket in lib.buckets
	some rc in lib.attached(bucket, control_type)
	not encrypted(rc)
	msg := sprintf("SC-28: %s does not use an approved encryption algorithm", [bucket])
}
