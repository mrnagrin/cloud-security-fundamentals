package terraform.s3.versioning_test

import data.terraform.s3.testdata
import data.terraform.s3.versioning
import rego.v1

# CM-6 passes when versioning is Enabled
test_cm6_passes_when_versioning_enabled if {
	plan := testdata.plan([testdata.versioning_control("Enabled")])
	count(versioning.deny) == 0 with input as plan
}

# CM-6 fails when versioning is Suspended
test_cm6_fails_when_versioning_suspended if {
	plan := testdata.plan([testdata.versioning_control("Suspended")])
	count(versioning.deny) == 1 with input as plan
}
