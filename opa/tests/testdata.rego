package terraform.s3.testdata

import rego.v1

# Builds a minimal fake Terraform plan for the unit tests: one S3 bucket
# plus whichever control resources a test passes in.

bucket_rc := {
	"address": "aws_s3_bucket.compliant",
	"type": "aws_s3_bucket",
	"change": {"actions": ["create"], "after": {"bucket": "demo-bucket"}},
}

bucket_cfg := {
	"address": "aws_s3_bucket.compliant",
	"type": "aws_s3_bucket",
	"expressions": {},
}

# Mirrors how Terraform records `bucket = aws_s3_bucket.compliant.id`
control_cfg(address, type) := {
	"address": address,
	"type": type,
	"expressions": {"bucket": {"references": [
		"aws_s3_bucket.compliant.id",
		"aws_s3_bucket.compliant",
	]}},
}

control_rc(address, type, after) := {
	"address": address,
	"type": type,
	"change": {"actions": ["create"], "after": after},
}

# `controls` is a list of {"address": ..., "type": ..., "after": ...}
plan(controls) := {
	"resource_changes": array.concat(
		[bucket_rc],
		[control_rc(c.address, c.type, c.after) | some c in controls],
	),
	"configuration": {"root_module": {"resources": array.concat(
		[bucket_cfg],
		[control_cfg(c.address, c.type) | some c in controls],
	)}},
}

encryption_control(algorithm) := {
	"address": "aws_s3_bucket_server_side_encryption_configuration.compliant",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"after": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": algorithm}]}]},
}

versioning_control(status) := {
	"address": "aws_s3_bucket_versioning.compliant",
	"type": "aws_s3_bucket_versioning",
	"after": {"versioning_configuration": [{"status": status}]},
}

public_access_control(value) := {
	"address": "aws_s3_bucket_public_access_block.compliant",
	"type": "aws_s3_bucket_public_access_block",
	"after": {
		"block_public_acls": value,
		"ignore_public_acls": value,
		"block_public_policy": value,
		"restrict_public_buckets": value,
	},
}
