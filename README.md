# Cloud Security Fundamentals

A hands-on learning project for my move from IT audit and compliance into
GRC engineering. It covers AWS security basics, Linux CLI, Git, and a small
end-to-end example of compliance controls handled as code.

I'm still learning. This repo is where I practice and document what I build.

## The idea: build it, prove it, verify it

Three pieces work together on one example: a compliant S3 bucket.

| Step | Tool | What it does | Folder |
|---|---|---|---|
| 1. **Build** | Terraform | Deploys the bucket from code with encryption, versioning, and public access blocked | [`terraform/`](terraform/) |
| 2. **Prove before deploy** | OPA / Rego | Reads the Terraform plan and fails if a control is missing | [`opa/`](opa/) |
| 3. **Verify after deploy** | Python / boto3 | Pulls live IAM data from AWS and writes a CSV report | [`python-compliance-scripts/`](python-compliance-scripts/) |

### Controls covered (NIST 800-53)

| Control | Requirement | Where it's implemented |
|---|---|---|
| SC-28 | Protection of information at rest | Bucket encryption (AES-256) |
| CM-6 | Configuration settings | Bucket versioning enabled |
| AC-3 | Access enforcement | All four public access settings blocked |

The OPA policies include 6 unit tests (a passing and a failing case for each
control), and they pass against the deployed Terraform code.

## What's in this repo

```
.
├── terraform/                  Infrastructure as code for the compliant bucket
├── opa/                        Rego policies and unit tests
│   ├── policies/
│   └── tests/
├── python-compliance-scripts/  boto3 IAM audit script (MFA, key age, activity)
├── controls-mapping.md         Technical settings mapped to NIST 800-53 / SOC 2
├── commands-cheatsheet.md      Personal reference for Linux, Git, and AWS CLI
├── script.sh                   Shell script for permissions practice
└── hello.txt                   Basic file and Git practice
```

## Running each part

**Terraform** (needs the AWS CLI configured and Terraform installed)
```bash
cd terraform
terraform init
terraform plan
terraform apply
terraform destroy    # removes the demo bucket when finished
```

**OPA unit tests** (needs OPA installed)
```bash
opa test opa/policies opa/tests -v
```

**Check a real Terraform plan against the policies**
```bash
cd terraform
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
opa eval --format pretty --data ../opa/policies --input tfplan.json "data.terraform.s3.main.deny"
```
An empty result (`[]`) means every control is in place. Anything listed is a
violation, labeled with the control it breaks.

**Python IAM audit**
```bash
pip3 install boto3
python3 python-compliance-scripts/iam_compliance_audit.py
```

Plan files, state files, and generated CSV reports are git-ignored because
they can contain account data.

## What I've practiced

**AWS:** IAM users with MFA instead of the root account, S3 encryption and
Block Public Access, a bucket policy that denies non-HTTPS requests, and
checking settings from the AWS CLI.

**Infrastructure as code:** declaring AWS resources in Terraform, reading a
plan before applying it, and keeping state out of version control.

**Policy as code:** writing Rego rules against Terraform plan JSON and testing
them with OPA's built-in test runner.

**Python:** using boto3 to pull IAM configuration and turn it into audit
evidence.

**Linux and Git:** file permissions, branching, merging, resolving a merge
conflict, and working with a GitHub remote.

## Why I'm building this

I spent years on the audit and compliance side, testing whether controls
exist and work. The logic of a control is the same in the cloud: what it's
meant to achieve, how it's configured, how you get evidence, and how you test
it. What changes is where the evidence lives and how you collect it. This repo
is me learning to do that part with code.

## Next steps

- [ ] Extend the Python audit with a CloudTrail logging check
- [ ] Add more controls to the Terraform and Rego examples
- [ ] Run the OPA checks automatically in GitHub Actions
- [ ] Try AWS Config managed rules and Security Hub
- [ ] EC2 and SSH practice for real Linux user management
