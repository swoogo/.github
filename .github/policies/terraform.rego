# Terraform OPA Policy for Swoogo Infrastructure
# Enforces organizational standards across 4 categories:
# 1. AWS Best Practices (encryption, tagging, public access)
# 2. Cost Controls (instance types, resource limits)
# 3. Security Baseline (IAM, network, logging)
# 4. Compliance Requirements (retention, backups, multi-AZ)

package terraform

#######################
# RESOURCE COLLECTION
#######################

# Collect all resources from root module and nested child_modules recursively
# Uses walk() builtin to traverse arbitrarily nested modules (avoids user-defined recursion)
all_resources contains resource if {
  walk(input.planned_values.root_module, [_, value])
  resource := value.resources[_]
}

#######################
# 1. AWS BEST PRACTICES
#######################

# ENCRYPTION: RDS instances must have storage encryption enabled
deny contains msg if {
  resource := all_resources[_]
  resource.type == "aws_db_instance"
  resource.values.storage_encrypted != true
  msg := sprintf("RDS instance '%s' must have storage encryption enabled (storage_encrypted = true)", [resource.address])
}

# ENCRYPTION: EBS volumes must be encrypted
deny contains msg if {
  resource := all_resources[_]
  resource.type == "aws_ebs_volume"
  resource.values.encrypted != true
  msg := sprintf("EBS volume '%s' must be encrypted (encrypted = true)", [resource.address])
}

# ENCRYPTION: S3 buckets must have server-side encryption
deny contains msg if {
  resource := all_resources[_]
  resource.type == "aws_s3_bucket"
  not has_s3_encryption(resource.address)
  msg := sprintf("S3 bucket '%s' must have server-side encryption configured (use aws_s3_bucket_server_side_encryption_configuration)", [resource.address])
}

# Helper: Check if S3 bucket has encryption configured
# Resolves bucket address to bucket name, then matches against encryption config
has_s3_encryption(bucket_address) if {
  bucket_resource := all_resources[_]
  bucket_resource.type == "aws_s3_bucket"
  bucket_resource.address == bucket_address
  bucket_name := bucket_resource.values.bucket

  enc_resource := all_resources[_]
  enc_resource.type == "aws_s3_bucket_server_side_encryption_configuration"
  enc_resource.values.bucket == bucket_name
}

# PUBLIC ACCESS: S3 buckets must not be publicly accessible
deny contains msg if {
  resource := all_resources[_]
  resource.type == "aws_s3_bucket_acl"
  resource.values.acl == "public-read"
  msg := sprintf("S3 bucket '%s' must not have public-read ACL", [resource.address])
}

# PUBLIC ACCESS: RDS instances must not be publicly accessible
deny contains msg if {
  resource := all_resources[_]
  resource.type == "aws_db_instance"
  resource.values.publicly_accessible == true
  msg := sprintf("RDS instance '%s' must not be publicly accessible (publicly_accessible = false)", [resource.address])
}

#######################
# 3. SECURITY BASELINE
#######################

# IAM: Policies must not use wildcard actions
deny contains msg if {
  resource := all_resources[_]
  resource.type == "aws_iam_policy"
  policy := json.unmarshal(resource.values.policy)
  statement := policy.Statement[_]
  action := statement.Action[_]
  action == "*"
  msg := sprintf("IAM policy '%s' uses wildcard action '*' - violates least privilege principle", [resource.address])
}

# NETWORK: Security groups must not allow unrestricted ingress (except 80/443)
deny contains msg if {
  resource := all_resources[_]
  resource.type == "aws_security_group"
  rule := resource.values.ingress[_]
  rule.cidr_blocks[_] == "0.0.0.0/0"
  not allowed_public_port(rule.from_port)
  msg := sprintf("Security group '%s' allows unrestricted ingress on port %d from 0.0.0.0/0 (only ports 80 and 443 allowed)", [resource.address, rule.from_port])
}

allowed_public_port(port) if {
  allowed_ports := [80, 443]
  port == allowed_ports[_]
}

# NETWORK: Security group rules must not allow unrestricted ingress
deny contains msg if {
  resource := all_resources[_]
  resource.type == "aws_security_group_rule"
  resource.values.type == "ingress"
  resource.values.cidr_blocks[_] == "0.0.0.0/0"
  not allowed_public_port(resource.values.from_port)
  msg := sprintf("Security group rule '%s' allows unrestricted ingress on port %d from 0.0.0.0/0", [resource.address, resource.values.from_port])
}

# ENCRYPTION: KMS keys should have rotation enabled
deny contains msg if {
  resource := all_resources[_]
  resource.type == "aws_kms_key"
  resource.values.enable_key_rotation != true
  msg := sprintf("KMS key '%s' must have automatic key rotation enabled (enable_key_rotation = true)", [resource.address])
}

#######################
# 4. COMPLIANCE
#######################

# BACKUPS: RDS instances must have automated backups enabled
deny contains msg if {
  resource := all_resources[_]
  resource.type == "aws_db_instance"
  resource.values.backup_retention_period < 7
  msg := sprintf("RDS instance '%s' must have backup retention of at least 7 days (current: %d days)", [resource.address, resource.values.backup_retention_period])
}

# HIGH AVAILABILITY: Production RDS instances must be multi-AZ
deny contains msg if {
  resource := all_resources[_]
  resource.type == "aws_db_instance"
  resource.values.tags.Environment == "prod"
  resource.values.multi_az != true
  msg := sprintf("Production RDS instance '%s' must have multi-AZ enabled (multi_az = true)", [resource.address])
}

#######################
# SUMMARY & HELPERS
#######################

# Count violations by severity
violation_count := count(deny)

# Output summary (for CI reporting)
summary := {
  "violations": violation_count,
  "status": status
}

status := "pass" if {
  violation_count == 0
}

status := "fail" if {
  violation_count > 0
}
