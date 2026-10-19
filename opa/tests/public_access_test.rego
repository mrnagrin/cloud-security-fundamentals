package terraform.s3.public_access_test

import data.terraform.s3.public_access
import data.terraform.s3.testdata
import rego.v1

# AC-3 passes when all four public access settings are true
test_ac3_passes_when_all_public_access_blocked if {
	plan := testdata.plan([testdata.public_access_control(true)])
	count(public_access.deny) == 0 with input as plan
}

# AC-3 fails (one violation per setting) when all four are false
test_ac3_fails_when_public_access_allowed if {
	plan := testdata.plan([testdata.public_access_control(false)])
	count(public_access.deny) == 4 with input as plan
}
