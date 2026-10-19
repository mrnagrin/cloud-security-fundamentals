package terraform.s3.lib

import rego.v1

# Shared helpers for the S3 compliance policies.
# Input is the JSON produced by `terraform show -json <planfile>`.

# Addresses of every S3 bucket the plan keeps or creates
buckets contains rc.address if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket"
	not "delete" in rc.change.actions
}

# Planned resources of `control_type` that are attached to `bucket_addr`.
#
# The link is read from the configuration section of the plan: a control
# resource is attached to a bucket when its `bucket` argument references it
# (for example `bucket = aws_s3_bucket.compliant.id`). The bucket's ID isn't
# known until it exists, so the plan can't link them any other way.
attached(bucket_addr, control_type) := {rc |
	some rc in input.resource_changes
	rc.type == control_type
	not "delete" in rc.change.actions
	some cfg in input.configuration.root_module.resources
	cfg.address == rc.address
	some ref in cfg.expressions.bucket.references
	ref in {bucket_addr, sprintf("%s.id", [bucket_addr])}
}
