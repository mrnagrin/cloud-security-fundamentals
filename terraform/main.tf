terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# -----------------------------------------------------------------------------
# Compliant S3 bucket, deployed from code
#
# Control mapping (NIST 800-53 Rev 5):
#   SC-28  Protection of Information at Rest  -> server-side encryption
#   CM-6   Configuration Settings             -> versioning enabled
#   AC-3   Access Enforcement                 -> all public access blocked
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "compliant" {
  bucket = var.bucket_name

  tags = {
    Owner = "marina"
    Project  = "cloud-security-fundamentals"
    Purpose  = "GRC engineering portfolio"
    Controls = "SC-28 CM-6 AC-3"
  }
}

# SC-28: encryption at rest (AES-256, S3-managed keys)
resource "aws_s3_bucket_server_side_encryption_configuration" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# CM-6: versioning enabled so changes and deletions are recoverable
resource "aws_s3_bucket_versioning" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  versioning_configuration {
    status = "Enabled"
  }
}

# AC-3: block every form of public access
resource "aws_s3_bucket_public_access_block" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
