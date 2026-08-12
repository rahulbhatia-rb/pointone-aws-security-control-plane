variable "log_bucket_name" { type = string }

resource "aws_s3_bucket" "audit" {
  bucket              = var.log_bucket_name
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Production design would add:
# - organization CloudTrail
# - dedicated logging account
# - KMS key owned by security/logging boundary
# - Object Lock retention policy
# - bucket policy preventing application-role deletion
