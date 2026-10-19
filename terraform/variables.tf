variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-2"
}

variable "bucket_name" {
  description = "Globally unique S3 bucket name (must differ from your existing console-created bucket)"
  type        = string
  default     = "marina-grc-terraform-demo-2026"
}
