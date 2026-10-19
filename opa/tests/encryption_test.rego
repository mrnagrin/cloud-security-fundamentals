package terraform.s3.encryption_test

import data.terraform.s3.encryption
import data.terraform.s3.testdata
import rego.v1

# SC-28 passes when the bucket is encrypted with AES-256
test_sc28_passes_when_encrypted if {
	plan := testdata.plan([testdata.encryption_control("AES256")])
	count(encryption.deny) == 0 with input as plan
}

# SC-28 fails when the bucket has no encryption configuration
test_sc28_fails_when_no_encryption if {
	plan := testdata.plan([])
	count(encryption.deny) == 1 with input as plan
}
