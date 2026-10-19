package terraform.s3.main

import data.terraform.s3.encryption
import data.terraform.s3.public_access
import data.terraform.s3.versioning
import rego.v1

# All violations across the three controls, in one place.
# An empty set means the plan satisfies SC-28, CM-6, and AC-3.
deny := (encryption.deny | versioning.deny) | public_access.deny
