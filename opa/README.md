# Policy as Code: OPA / Rego

Rego policies that read a Terraform plan and prove S3 compliance controls are
in place **before anything is deployed**. A non-compliant change fails the
check instead of reaching AWS.

## Controls checked

| Policy file | NIST 800-53 control | What it enforces |
|---|---|---|
| `policies/encryption.rego` | SC-28 Protection of Information at Rest | Every bucket has server-side encryption with an approved algorithm (`AES256` or `aws:kms`) |
| `policies/versioning.rego` | CM-6 Configuration Settings | Every bucket has versioning set to `Enabled` |
| `policies/public_access.rego` | AC-3 Access Enforcement | Every bucket has all four public access block settings set to `true` |

`policies/lib.rego` holds shared helpers that link each control resource to its
bucket. `policies/main.rego` combines all violations into one `deny` set; an
empty set means the plan is compliant.

## Unit tests

Six tests (a passing case and a failing case for each control) run against
small fake plans built in `tests/testdata.rego`.

```bash
opa test policies tests -v
```

Expected result: `PASS: 6/6`

## Check a real Terraform plan

From the `terraform/` folder, export the plan as JSON, then evaluate it:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
opa eval --format pretty --data ../opa/policies --input tfplan.json "data.terraform.s3.main.deny"
```

- `[]` means every control is in place.
- Any listed message is a violation, tagged with the control ID it breaks.

`tfplan` and `tfplan.json` are git-ignored because plans can contain sensitive values.

## How it fits together

1. **Terraform** (`../terraform`) declares the compliant bucket as code.
2. **OPA/Rego** (this folder) proves the plan meets the controls before it is applied.
3. **Python/boto3** (`../python-compliance-scripts`) audits what is live in AWS afterward.

Build it, prove it before deploy, and verify it after deploy.
