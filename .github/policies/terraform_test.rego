# Tests for Terraform OPA Policy
# Run with: opa test .github/policies/ -v

package terraform_test

import data.terraform

# Helper: minimal compliant plan with no resources
test_compliant_plan_no_violations if {
  count(terraform.deny) == 0 with input as {
    "planned_values": {
      "root_module": {
        "resources": []
      }
    }
  }
}

# Helper: compliant RDS instance
test_compliant_rds_no_violations if {
  count(terraform.deny) == 0 with input as {
    "planned_values": {
      "root_module": {
        "resources": [{
          "address": "aws_db_instance.main",
          "type": "aws_db_instance",
          "values": {
            "storage_encrypted": true,
            "publicly_accessible": false,
            "backup_retention_period": 14,
            "multi_az": true,
            "tags": {"Environment": "prod"}
          }
        }]
      }
    }
  }
}

# Test: unencrypted RDS triggers deny
test_unencrypted_rds_denied if {
  violations := terraform.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [{
          "address": "aws_db_instance.test",
          "type": "aws_db_instance",
          "values": {
            "storage_encrypted": false,
            "publicly_accessible": false,
            "backup_retention_period": 14,
            "multi_az": true,
            "tags": {"Environment": "stage"}
          }
        }]
      }
    }
  }
  count(violations) > 0
  some msg in violations
  contains(msg, "storage encryption")
}

# Test: publicly accessible RDS triggers deny
test_public_rds_denied if {
  violations := terraform.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [{
          "address": "aws_db_instance.test",
          "type": "aws_db_instance",
          "values": {
            "storage_encrypted": true,
            "publicly_accessible": true,
            "backup_retention_period": 14,
            "multi_az": true,
            "tags": {"Environment": "stage"}
          }
        }]
      }
    }
  }
  count(violations) > 0
  some msg in violations
  contains(msg, "publicly accessible")
}

# Test: public S3 ACL triggers deny
test_public_s3_acl_denied if {
  violations := terraform.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [{
          "address": "aws_s3_bucket_acl.test",
          "type": "aws_s3_bucket_acl",
          "values": {
            "acl": "public-read"
          }
        }]
      }
    }
  }
  count(violations) > 0
  some msg in violations
  contains(msg, "public-read")
}

# Test: wildcard IAM action triggers deny
test_wildcard_iam_denied if {
  violations := terraform.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [{
          "address": "aws_iam_policy.test",
          "type": "aws_iam_policy",
          "values": {
            "policy": "{\"Statement\":[{\"Action\":[\"*\"],\"Effect\":\"Allow\",\"Resource\":\"*\"}]}"
          }
        }]
      }
    }
  }
  count(violations) > 0
  some msg in violations
  contains(msg, "wildcard")
}

# Test: unencrypted EBS volume triggers deny
test_unencrypted_ebs_denied if {
  violations := terraform.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [{
          "address": "aws_ebs_volume.test",
          "type": "aws_ebs_volume",
          "values": {
            "encrypted": false
          }
        }]
      }
    }
  }
  count(violations) > 0
  some msg in violations
  contains(msg, "encrypted")
}

# Test: KMS key without rotation triggers deny
test_kms_no_rotation_denied if {
  violations := terraform.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [{
          "address": "aws_kms_key.test",
          "type": "aws_kms_key",
          "values": {
            "enable_key_rotation": false
          }
        }]
      }
    }
  }
  count(violations) > 0
  some msg in violations
  contains(msg, "key rotation")
}

# Test: low backup retention triggers deny
test_low_backup_retention_denied if {
  violations := terraform.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [{
          "address": "aws_db_instance.test",
          "type": "aws_db_instance",
          "values": {
            "storage_encrypted": true,
            "publicly_accessible": false,
            "backup_retention_period": 3,
            "multi_az": true,
            "tags": {"Environment": "stage"}
          }
        }]
      }
    }
  }
  count(violations) > 0
  some msg in violations
  contains(msg, "backup retention")
}

# Test: prod RDS without multi-AZ triggers deny
test_prod_rds_no_multi_az_denied if {
  violations := terraform.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [{
          "address": "aws_db_instance.test",
          "type": "aws_db_instance",
          "values": {
            "storage_encrypted": true,
            "publicly_accessible": false,
            "backup_retention_period": 14,
            "multi_az": false,
            "tags": {"Environment": "prod"}
          }
        }]
      }
    }
  }
  count(violations) > 0
  some msg in violations
  contains(msg, "multi-AZ")
}

# Test: child module resources are collected
test_child_module_resources_collected if {
  violations := terraform.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [],
        "child_modules": [{
          "resources": [{
            "address": "module.db.aws_db_instance.this",
            "type": "aws_db_instance",
            "values": {
              "storage_encrypted": false,
              "publicly_accessible": false,
              "backup_retention_period": 14,
              "multi_az": true,
              "tags": {"Environment": "stage"}
            }
          }]
        }]
      }
    }
  }
  count(violations) > 0
}

# Test: summary status pass when no violations
test_summary_status_pass if {
  terraform.status == "pass" with input as {
    "planned_values": {
      "root_module": {
        "resources": []
      }
    }
  }
}

# Test: security group rule with unrestricted SSH ingress triggers deny
test_sg_rule_unrestricted_ingress_denied if {
  violations := terraform.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [{
          "address": "aws_security_group_rule.ssh",
          "type": "aws_security_group_rule",
          "values": {
            "type": "ingress",
            "from_port": 22,
            "to_port": 22,
            "cidr_blocks": ["0.0.0.0/0"]
          }
        }]
      }
    }
  }
  count(violations) > 0
  some msg in violations
  contains(msg, "unrestricted ingress")
}

# Test: security group rule allowing HTTPS from 0.0.0.0/0 is allowed
test_sg_rule_https_ingress_allowed if {
  count(terraform.deny) == 0 with input as {
    "planned_values": {
      "root_module": {
        "resources": [{
          "address": "aws_security_group_rule.https",
          "type": "aws_security_group_rule",
          "values": {
            "type": "ingress",
            "from_port": 443,
            "to_port": 443,
            "cidr_blocks": ["0.0.0.0/0"]
          }
        }]
      }
    }
  }
}

# Test: security group rule egress is not checked
test_sg_rule_egress_not_checked if {
  count(terraform.deny) == 0 with input as {
    "planned_values": {
      "root_module": {
        "resources": [{
          "address": "aws_security_group_rule.all_egress",
          "type": "aws_security_group_rule",
          "values": {
            "type": "egress",
            "from_port": 0,
            "to_port": 65535,
            "cidr_blocks": ["0.0.0.0/0"]
          }
        }]
      }
    }
  }
}

# Test: S3 bucket without encryption config triggers deny
test_s3_bucket_without_encryption_denied if {
  violations := terraform.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [{
          "address": "aws_s3_bucket.logs",
          "type": "aws_s3_bucket",
          "values": {
            "bucket": "my-logs-bucket"
          }
        }]
      }
    }
  }
  count(violations) > 0
  some msg in violations
  contains(msg, "server-side encryption")
}

# Test: S3 bucket with matching encryption config passes
test_s3_bucket_with_encryption_allowed if {
  count(terraform.deny) == 0 with input as {
    "planned_values": {
      "root_module": {
        "resources": [
          {
            "address": "aws_s3_bucket.logs",
            "type": "aws_s3_bucket",
            "values": {
              "bucket": "my-logs-bucket"
            }
          },
          {
            "address": "aws_s3_bucket_server_side_encryption_configuration.logs",
            "type": "aws_s3_bucket_server_side_encryption_configuration",
            "values": {
              "bucket": "my-logs-bucket"
            }
          }
        ]
      }
    }
  }
}

# Test: deeply nested child modules (2+ levels) have resources collected
test_deeply_nested_child_module_resources_collected if {
  violations := terraform.deny with input as {
    "planned_values": {
      "root_module": {
        "resources": [],
        "child_modules": [{
          "resources": [],
          "child_modules": [{
            "resources": [{
              "address": "module.vpc.module.sg.aws_ebs_volume.deep",
              "type": "aws_ebs_volume",
              "values": {
                "encrypted": false
              }
            }]
          }]
        }]
      }
    }
  }
  count(violations) > 0
  some msg in violations
  contains(msg, "encrypted")
}

# Test: summary status fail when violations exist
test_summary_status_fail if {
  terraform.status == "fail" with input as {
    "planned_values": {
      "root_module": {
        "resources": [{
          "address": "aws_ebs_volume.test",
          "type": "aws_ebs_volume",
          "values": {
            "encrypted": false
          }
        }]
      }
    }
  }
}
