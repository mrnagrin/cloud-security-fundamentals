package terraform.s3.versioning

import data.terraform.s3.lib
import rego.v1

# NIST 800-53 CM-6: Configuration Settings
# Every S3 bucket must have versioning enabled so changes and deletions
# are recoverable.

control_type := "aws_s3_bucket_versioning"

versioning_enabled(rc) if {
	some cfg in rc.change.after.versioning_configuration
	cfg.status == "Enabled"
}

# Bucket has no versioning resource at all
deny contains msg if {
	some bucket in lib.buckets
	count(lib.attached(bucket, control_type)) == 0
	msg := sprintf("CM-6: %s has no versioning configuration", [bucket])
}

# Versioning resource exists but isn't set to Enabled
deny contains msg if {
	some bucket in lib.buckets
	some rc in lib.attached(bucket, control_type)
	not versioning_enabled(rc)
	msg := sprintf("CM-6: %s versioning is not Enabled", [bucket])
}
