output "bucket_name" {
  description = "Name of the compliant bucket"
  value       = aws_s3_bucket.compliant.id
}

output "bucket_arn" {
  description = "ARN of the compliant bucket"
  value       = aws_s3_bucket.compliant.arn
}
