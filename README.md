# Vision One CloudFormation Cleanup Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![AWS CLI v2](https://img.shields.io/badge/AWS%20CLI-v2-orange.svg)](https://aws.amazon.com/cli/)

Tools for identifying and removing orphaned AWS resources left behind after Trend Micro Vision One CloudFormation stack deletion failures.

> **Disclaimer**: This is an unofficial community tool, not affiliated with or supported by Trend Micro. Use at your own risk. Always review resources in dry-run mode before executing deletions.

## Problem

When Vision One CloudFormation stacks fail to delete, they often leave behind:
- S3 buckets (especially DSPM, Cloud Sentry, CALM)
- CloudWatch Log Groups
- Lambda functions
- SSM Parameters
- IAM Roles
- Failed nested stacks

This toolkit identifies these orphaned resources by their tags and naming patterns, then safely removes them.

## Files

| File | Purpose |
|------|---------|
| `v1-cleanup.py` | Main Python cleanup tool (full featured) |
| `v1-cleanup.sh` | Bash wrapper for convenience |
| `quick-scan.sh` | Fast bash-based discovery (read-only) |

## Requirements

### For Python tool (`v1-cleanup.py`)
- Python 3.8+
- boto3 (`pip install boto3`)
- AWS credentials configured

### For Bash scripts
- AWS CLI v2
- jq (`brew install jq` or `apt install jq`)
- AWS credentials configured

## Quick Start

```bash
# 1. Fast discovery (read-only, bash)
./quick-scan.sh

# 2. Detailed scan (Python, dry-run by default)
./v1-cleanup.sh --dry-run

# 3. Scan all regions
./v1-cleanup.sh --dry-run --all-regions

# 4. Export scan results to JSON
./v1-cleanup.sh --dry-run --output json > scan-results.json

# 5. Delete resources (requires confirmation)
./v1-cleanup.sh --execute --region us-east-1
```

## Usage Examples

### Scan current region (safe, no changes)
```bash
./v1-cleanup.sh
```

### Scan specific region
```bash
./v1-cleanup.sh --region us-west-2
```

### Scan all regions
```bash
./v1-cleanup.sh --all-regions
```

### Filter by stack name pattern
```bash
./v1-cleanup.sh --stack-name Vision-One-Cloud-Account
```

### Use specific AWS profile
```bash
./v1-cleanup.sh --profile my-aws-profile
```

### Export as JSON for review
```bash
./v1-cleanup.sh --dry-run --all-regions --output json > report.json
```

### Delete resources (with confirmation)
```bash
./v1-cleanup.sh --execute --region us-east-1
```

## Security Features

1. **Dry-run by default**: No changes are made unless `--execute` is explicitly specified
2. **Confirmation required**: Deletion requires typing `DELETE N RESOURCES` to confirm
3. **No credential storage**: Uses standard AWS credential chain (env vars, profiles, instance roles)
4. **No credentials in logs**: Sensitive data is never logged
5. **Audit trail**: All actions are logged to stdout with timestamps
6. **Dependency-aware deletion**: Resources are deleted in correct order

## Resource Identification

### By Tags
All Vision One resources are tagged with:
```
Key: TrendMicroProduct
Values: cam, ct, cs, dspm, fss, sentry
```

### By Naming Patterns

| Resource Type | Prefix/Pattern |
|--------------|----------------|
| S3 Buckets | `v1cs-cloud-audit-log-monitoring-*`, `cloud-one-sentry-*`, `v1-avtd-*` |
| Log Groups | `/aws/lambda/Vision-One-*`, `/aws/lambda/v1-*` |
| SSM Parameters | `/V1CS/*`, `/TrendMicro/*` |
| Lambda Functions | `v1-*`, `trendmicro-container-security-*` |
| IAM Roles | Contains `VisionOne`, `TrendMicro`, `v1-avtd` |
| CloudFormation | DELETE_FAILED stacks with V1 indicators |

## IAM Permissions Required

The IAM user/role running this tool needs these permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ReadPermissions",
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity",
                "ec2:DescribeRegions",
                "tag:GetResources",
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "logs:DescribeLogGroups",
                "ssm:GetParametersByPath",
                "lambda:ListFunctions",
                "cloudformation:ListStacks",
                "cloudformation:ListStackResources",
                "iam:ListRoles",
                "iam:ListAttachedRolePolicies",
                "iam:ListRolePolicies",
                "iam:ListInstanceProfilesForRole"
            ],
            "Resource": "*"
        },
        {
            "Sid": "DeletePermissions",
            "Effect": "Allow",
            "Action": [
                "s3:DeleteBucket",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
                "s3:ListBucket",
                "s3:ListBucketVersions",
                "logs:DeleteLogGroup",
                "ssm:DeleteParameter",
                "ssm:DeleteParameters",
                "lambda:DeleteFunction",
                "cloudformation:DeleteStack",
                "iam:DeleteRole",
                "iam:DeleteRolePolicy",
                "iam:DetachRolePolicy",
                "iam:RemoveRoleFromInstanceProfile"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:ResourceTag/TrendMicroProduct": [
                        "cam", "ct", "cs", "dspm", "fss", "sentry"
                    ]
                }
            }
        }
    ]
}
```

**Note**: The condition on delete permissions only works for resources that support tag-based conditions. For complete safety, review the dry-run output before executing.

## Output Formats

### Text (default)
Human-readable summary with counts and resource names.

### JSON
Machine-readable format for automation:
```json
{
  "account_id": "123456789012",
  "regions": ["us-east-1", "us-west-2"],
  "dry_run": true,
  "resources": {
    "s3_buckets": ["bucket-1", "bucket-2"],
    "log_groups": ["/aws/lambda/Vision-One-..."],
    "ssm_parameters": ["/V1CS/..."],
    "lambda_functions": ["v1-..."],
    "iam_roles": ["VisionOneRole"],
    "cloudformation_stacks": ["Vision-One-Stack"]
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Troubleshooting

### "No AWS credentials found"
Configure AWS credentials using one of:
- Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- AWS CLI: `aws configure`
- IAM instance role (on EC2)

### "boto3 is required"
Install the Python AWS SDK:
```bash
pip install boto3
```

### "jq is not installed"
Install jq for JSON parsing in bash scripts:
```bash
# macOS
brew install jq

# Ubuntu/Debian
apt install jq

# Amazon Linux/RHEL
yum install jq
```

### Permission denied errors
Ensure your IAM user/role has the required permissions listed above.

### Resources still exist after deletion
Some resources may have deletion protection or dependencies. Check:
1. S3 bucket policies preventing deletion
2. Lambda functions with reserved concurrency
3. IAM roles still attached to resources
4. CloudFormation stack resources with `DeletionPolicy: Retain`

## Installation

```bash
# Clone the repository
git clone https://github.com/jmlake569/v1-cloudformation-cleanup.git
cd v1-cloudformation-cleanup

# Install Python dependencies
pip install -r requirements.txt

# Make scripts executable
chmod +x v1-cleanup.py v1-cleanup.sh quick-scan.sh

# Verify AWS credentials are configured
aws sts get-caller-identity
```

## Contributing

Contributions are welcome! When adding support for new resource types:

1. Add detection pattern to the appropriate list in `v1-cleanup.py`
2. Add scan function to `ResourceScanner` class
3. Add delete function to `ResourceCleaner` class
4. Update `quick-scan.sh` with new patterns
5. Update this README
6. Test with `--dry-run` before submitting PR

Please open an issue first to discuss major changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided as-is with no warranty. It is designed to delete AWS resources, which is an irreversible action. Always:

1. Run with `--dry-run` first to review what will be deleted
2. Verify the resources listed are actually orphaned
3. Ensure you have backups of any important data
4. Test in a non-production account first

The authors are not responsible for any unintended data loss or AWS charges incurred from using this tool.
