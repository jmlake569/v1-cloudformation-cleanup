#!/usr/bin/env python3
"""
Vision One CloudFormation Resource Cleanup Tool

Identifies and removes orphaned AWS resources left behind after
Vision One CloudFormation stack deletion failures.

Security features:
- Dry-run mode is DEFAULT (must explicitly use --execute)
- Requires confirmation before any destructive action
- All actions are logged
- No credentials stored or logged
- Respects AWS credential chain (env vars, profiles, instance roles)

Usage:
    python3 v1-cleanup.py --dry-run                    # Safe scan, no changes
    python3 v1-cleanup.py --dry-run --all-regions      # Scan all regions
    python3 v1-cleanup.py --execute --region us-east-1 # Delete in specific region
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from typing import Optional, Dict, List, Set
from dataclasses import dataclass, field

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
except ImportError:
    print("ERROR: boto3 is required. Install with: pip install boto3")
    sys.exit(1)

# ============================================================================
# Configuration - Resource identification patterns
# ============================================================================

RESOURCE_TAGS = {
    "TrendMicroProduct": ["cam", "ct", "cs", "dspm", "fss", "sentry", "v1"]
}

S3_BUCKET_PREFIXES = [
    "v1cs-cloud-audit-log-monitoring-",
    "cloud-one-sentry-",
    "v1-avtd-",
    "v1-common-",
    "trendmicro-",
]

LOG_GROUP_PATTERNS = [
    "/aws/lambda/Vision-One-",
    "/aws/lambda/v1-",
    "/aws/lambda/trendmicro-container-security-",
    "/aws/lambda/v1cs-",
    "/aws/lambda/StackSet-V1DspmStackSet-",
    "/aws/lambda/StackSet-V1CommonStackSet-",
    "/aws/lambda/StackSet-V1SentryStackSet-",
]

SSM_PARAMETER_PREFIXES = [
    "/V1CS/",
    "/TrendMicro/",
]

LAMBDA_PREFIXES = [
    "v1-",
    "v1cs-",
    "trendmicro-container-security-",
    "Vision-One-",
]

IAM_ROLE_PATTERNS = [
    "VisionOne",
    "TrendMicro",
    "v1-avtd",
    "v1-common",
    "v1cs-",
]

# ============================================================================
# Data structures for tracking resources with their regions
# ============================================================================

@dataclass
class RegionalResources:
    """Track resources by region."""
    s3_buckets: Dict[str, Set[str]] = field(default_factory=dict)  # region -> set of bucket names
    log_groups: Dict[str, Set[str]] = field(default_factory=dict)  # region -> set of log group names
    ssm_parameters: Dict[str, Set[str]] = field(default_factory=dict)
    lambda_functions: Dict[str, Set[str]] = field(default_factory=dict)
    iam_roles: Set[str] = field(default_factory=set)  # IAM is global
    cloudformation_stacks: Dict[str, Set[str]] = field(default_factory=dict)

    def add_s3_bucket(self, region: str, bucket: str):
        if region not in self.s3_buckets:
            self.s3_buckets[region] = set()
        self.s3_buckets[region].add(bucket)

    def add_log_group(self, region: str, log_group: str):
        if region not in self.log_groups:
            self.log_groups[region] = set()
        self.log_groups[region].add(log_group)

    def add_ssm_parameter(self, region: str, param: str):
        if region not in self.ssm_parameters:
            self.ssm_parameters[region] = set()
        self.ssm_parameters[region].add(param)

    def add_lambda_function(self, region: str, func: str):
        if region not in self.lambda_functions:
            self.lambda_functions[region] = set()
        self.lambda_functions[region].add(func)

    def add_iam_role(self, role: str):
        self.iam_roles.add(role)

    def add_cfn_stack(self, region: str, stack: str):
        if region not in self.cloudformation_stacks:
            self.cloudformation_stacks[region] = set()
        self.cloudformation_stacks[region].add(stack)

    def total_count(self) -> int:
        count = len(self.iam_roles)
        for region_set in self.s3_buckets.values():
            count += len(region_set)
        for region_set in self.log_groups.values():
            count += len(region_set)
        for region_set in self.ssm_parameters.values():
            count += len(region_set)
        for region_set in self.lambda_functions.values():
            count += len(region_set)
        for region_set in self.cloudformation_stacks.values():
            count += len(region_set)
        return count

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "s3_buckets": {r: list(s) for r, s in self.s3_buckets.items()},
            "log_groups": {r: list(s) for r, s in self.log_groups.items()},
            "ssm_parameters": {r: list(s) for r, s in self.ssm_parameters.items()},
            "lambda_functions": {r: list(s) for r, s in self.lambda_functions.items()},
            "iam_roles": list(self.iam_roles),
            "cloudformation_stacks": {r: list(s) for r, s in self.cloudformation_stacks.items()},
        }


# ============================================================================
# Logging setup
# ============================================================================

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging with appropriate level and format."""
    log_level = logging.DEBUG if verbose else logging.INFO

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    logger = logging.getLogger("v1-cleanup")
    logger.setLevel(log_level)
    logger.addHandler(handler)

    return logger


# ============================================================================
# AWS Session Management
# ============================================================================

def get_aws_session(profile: Optional[str] = None, region: Optional[str] = None):
    """Create AWS session using credential chain."""
    try:
        session_kwargs = {}
        if profile:
            session_kwargs["profile_name"] = profile
        if region:
            session_kwargs["region_name"] = region

        session = boto3.Session(**session_kwargs)
        sts = session.client("sts")
        identity = sts.get_caller_identity()

        return session, identity["Account"]

    except NoCredentialsError:
        print("ERROR: No AWS credentials found.")
        sys.exit(1)
    except ProfileNotFound as e:
        print(f"ERROR: AWS profile not found: {e}")
        sys.exit(1)
    except ClientError as e:
        print(f"ERROR: AWS authentication failed: {e}")
        sys.exit(1)


def get_all_regions(session) -> list:
    """Get list of all enabled AWS regions."""
    ec2 = session.client("ec2")
    regions = ec2.describe_regions(AllRegions=False)["Regions"]
    return [r["RegionName"] for r in regions]


# ============================================================================
# Resource Discovery - with region tracking
# ============================================================================

class ResourceScanner:
    """Scans for Vision One related resources with proper region tracking."""

    def __init__(self, session, region: str, logger: logging.Logger,
                 resources: RegionalResources, stack_name: Optional[str] = None):
        self.session = session
        self.region = region
        self.logger = logger
        self.resources = resources
        self.stack_name = stack_name

    def scan_all(self):
        """Run all resource scans for this region."""
        self.logger.info(f"Scanning region: {self.region}")

        # Don't use tag API - it can return stale data
        # Instead, directly query each service
        self._scan_s3_buckets()
        self._scan_log_groups()
        self._scan_ssm_parameters()
        self._scan_lambda_functions()
        self._scan_failed_stacks()

        # IAM is global, only scan once from us-east-1
        if self.region == "us-east-1":
            self._scan_iam_roles()

    def _scan_s3_buckets(self):
        """Scan S3 buckets by name prefix."""
        try:
            s3 = self.session.client("s3", region_name=self.region)
            response = s3.list_buckets()

            for bucket in response.get("Buckets", []):
                bucket_name = bucket["Name"]

                for prefix in S3_BUCKET_PREFIXES:
                    if bucket_name.startswith(prefix):
                        try:
                            location = s3.get_bucket_location(Bucket=bucket_name)
                            bucket_region = location.get("LocationConstraint") or "us-east-1"
                            if bucket_region == self.region:
                                self.resources.add_s3_bucket(self.region, bucket_name)
                        except ClientError:
                            pass
                        break

                if self.stack_name and self.stack_name.lower() in bucket_name.lower():
                    try:
                        location = s3.get_bucket_location(Bucket=bucket_name)
                        bucket_region = location.get("LocationConstraint") or "us-east-1"
                        if bucket_region == self.region:
                            self.resources.add_s3_bucket(self.region, bucket_name)
                    except ClientError:
                        pass

        except ClientError as e:
            self.logger.warning(f"Could not scan S3 buckets: {e}")

    def _scan_log_groups(self):
        """Scan CloudWatch Log Groups by name prefix - verifies existence."""
        try:
            logs = self.session.client("logs", region_name=self.region)
            paginator = logs.get_paginator("describe_log_groups")

            for pattern in LOG_GROUP_PATTERNS:
                try:
                    for page in paginator.paginate(logGroupNamePrefix=pattern):
                        for lg in page.get("logGroups", []):
                            lg_name = lg["logGroupName"]
                            self.resources.add_log_group(self.region, lg_name)
                except ClientError as e:
                    self.logger.debug(f"Log group scan error for {pattern}: {e}")

            if self.stack_name:
                try:
                    for page in paginator.paginate(logGroupNamePrefix=f"/aws/lambda/{self.stack_name}"):
                        for lg in page.get("logGroups", []):
                            lg_name = lg["logGroupName"]
                            self.resources.add_log_group(self.region, lg_name)
                except ClientError:
                    pass

        except ClientError as e:
            self.logger.warning(f"Could not scan log groups in {self.region}: {e}")

    def _scan_ssm_parameters(self):
        """Scan SSM Parameters by path prefix."""
        try:
            ssm = self.session.client("ssm", region_name=self.region)

            for prefix in SSM_PARAMETER_PREFIXES:
                try:
                    paginator = ssm.get_paginator("get_parameters_by_path")
                    for page in paginator.paginate(Path=prefix, Recursive=True):
                        for param in page.get("Parameters", []):
                            param_name = param["Name"]
                            self.resources.add_ssm_parameter(self.region, param_name)
                except ClientError as e:
                    self.logger.debug(f"SSM scan error for {prefix}: {e}")

        except ClientError as e:
            self.logger.warning(f"Could not scan SSM parameters in {self.region}: {e}")

    def _scan_lambda_functions(self):
        """Scan Lambda functions by name prefix."""
        try:
            lambda_client = self.session.client("lambda", region_name=self.region)
            paginator = lambda_client.get_paginator("list_functions")

            for page in paginator.paginate():
                for func in page.get("Functions", []):
                    func_name = func["FunctionName"]

                    for prefix in LAMBDA_PREFIXES:
                        if func_name.startswith(prefix):
                            self.resources.add_lambda_function(self.region, func_name)
                            break

                    if self.stack_name and self.stack_name in func_name:
                        self.resources.add_lambda_function(self.region, func_name)

        except ClientError as e:
            self.logger.warning(f"Could not scan Lambda functions in {self.region}: {e}")

    def _scan_iam_roles(self):
        """Scan IAM roles by name pattern (global)."""
        try:
            iam = self.session.client("iam")
            paginator = iam.get_paginator("list_roles")

            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role["RoleName"]

                    for pattern in IAM_ROLE_PATTERNS:
                        if pattern in role_name:
                            self.resources.add_iam_role(role_name)
                            break

        except ClientError as e:
            self.logger.warning(f"Could not scan IAM roles: {e}")

    def _scan_failed_stacks(self):
        """Find DELETE_FAILED CloudFormation stacks."""
        try:
            cfn = self.session.client("cloudformation", region_name=self.region)
            paginator = cfn.get_paginator("list_stacks")

            for page in paginator.paginate(StackStatusFilter=["DELETE_FAILED"]):
                for stack in page.get("StackSummaries", []):
                    stack_name = stack["StackName"]

                    v1_indicators = ["VisionOne", "Vision-One", "TrendMicro", "v1cs", "v1-", "Dspm", "Sentry", "Calm", "Fss"]

                    for indicator in v1_indicators:
                        if indicator.lower() in stack_name.lower():
                            self.resources.add_cfn_stack(self.region, stack_name)
                            break

        except ClientError as e:
            self.logger.warning(f"Could not scan CloudFormation stacks in {self.region}: {e}")


# ============================================================================
# Resource Deletion - region-aware with existence verification
# ============================================================================

class ResourceCleaner:
    """Handles safe deletion of Vision One resources with region awareness."""

    def __init__(self, session, logger: logging.Logger, dry_run: bool = True):
        self.session = session
        self.logger = logger
        self.dry_run = dry_run
        self.deleted = []
        self.failed = []
        self.skipped = []

    def delete_all(self, resources: RegionalResources) -> tuple:
        """Delete all provided resources in their correct regions."""

        # Delete Lambda functions first (they create log groups)
        for region, functions in resources.lambda_functions.items():
            self._delete_lambda_functions(region, functions)

        # Delete log groups
        for region, log_groups in resources.log_groups.items():
            self._delete_log_groups(region, log_groups)

        # Delete SSM parameters
        for region, parameters in resources.ssm_parameters.items():
            self._delete_ssm_parameters(region, parameters)

        # Delete S3 buckets
        for region, buckets in resources.s3_buckets.items():
            self._delete_s3_buckets(region, buckets)

        # Delete CloudFormation stacks
        for region, stacks in resources.cloudformation_stacks.items():
            self._delete_cloudformation_stacks(region, stacks)

        # Delete IAM roles last (may be referenced by other resources)
        self._delete_iam_roles(resources.iam_roles)

        return self.deleted, self.failed, self.skipped

    def _verify_log_group_exists(self, logs_client, log_group_name: str) -> bool:
        """Verify a log group exists before trying to delete it."""
        try:
            response = logs_client.describe_log_groups(
                logGroupNamePrefix=log_group_name,
                limit=1
            )
            for lg in response.get("logGroups", []):
                if lg["logGroupName"] == log_group_name:
                    return True
            return False
        except ClientError:
            return False

    def _delete_log_groups(self, region: str, log_groups: Set[str]):
        """Delete CloudWatch Log Groups with existence verification."""
        if not log_groups:
            return

        logs = self.session.client("logs", region_name=region)
        self.logger.info(f"Processing {len(log_groups)} log groups in {region}")

        for lg_name in log_groups:
            try:
                # Verify existence first
                if not self._verify_log_group_exists(logs, lg_name):
                    self.logger.debug(f"Log group already deleted: {lg_name}")
                    self.skipped.append(f"logs:{region}:{lg_name} (already deleted)")
                    continue

                if self.dry_run:
                    self.logger.info(f"[DRY-RUN] Would delete log group: {lg_name}")
                    self.deleted.append(f"logs:{region}:{lg_name}")
                else:
                    self.logger.info(f"Deleting log group: {lg_name}")
                    logs.delete_log_group(logGroupName=lg_name)
                    self.deleted.append(f"logs:{region}:{lg_name}")

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                if error_code == "ResourceNotFoundException":
                    self.skipped.append(f"logs:{region}:{lg_name} (not found)")
                else:
                    self.logger.error(f"Failed to delete log group {lg_name}: {error_code}")
                    self.failed.append(f"logs:{region}:{lg_name}: {error_code}")

    def _delete_s3_buckets(self, region: str, buckets: Set[str]):
        """Delete S3 buckets after emptying them."""
        if not buckets:
            return

        s3 = self.session.client("s3", region_name=region)
        s3_resource = self.session.resource("s3", region_name=region)

        for bucket_name in buckets:
            try:
                # Verify bucket exists
                try:
                    s3.head_bucket(Bucket=bucket_name)
                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "")
                    if error_code in ["404", "NoSuchBucket"]:
                        self.skipped.append(f"s3:{region}:{bucket_name} (not found)")
                        continue
                    raise

                if self.dry_run:
                    self.logger.info(f"[DRY-RUN] Would delete S3 bucket: {bucket_name}")
                    self.deleted.append(f"s3:{region}:{bucket_name}")
                else:
                    self.logger.info(f"Emptying S3 bucket: {bucket_name}")
                    bucket = s3_resource.Bucket(bucket_name)
                    bucket.object_versions.delete()
                    bucket.objects.delete()

                    self.logger.info(f"Deleting S3 bucket: {bucket_name}")
                    s3.delete_bucket(Bucket=bucket_name)
                    self.deleted.append(f"s3:{region}:{bucket_name}")

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                self.logger.error(f"Failed to delete bucket {bucket_name}: {error_code}")
                self.failed.append(f"s3:{region}:{bucket_name}: {error_code}")

    def _delete_ssm_parameters(self, region: str, parameters: Set[str]):
        """Delete SSM Parameters."""
        if not parameters:
            return

        ssm = self.session.client("ssm", region_name=region)
        param_list = list(parameters)

        for i in range(0, len(param_list), 10):
            batch = param_list[i:i+10]

            try:
                if self.dry_run:
                    for param in batch:
                        self.logger.info(f"[DRY-RUN] Would delete SSM parameter: {param}")
                        self.deleted.append(f"ssm:{region}:{param}")
                else:
                    self.logger.info(f"Deleting SSM parameters: {batch}")
                    ssm.delete_parameters(Names=batch)
                    for param in batch:
                        self.deleted.append(f"ssm:{region}:{param}")

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                self.logger.error(f"Failed to delete SSM parameters: {error_code}")
                for param in batch:
                    self.failed.append(f"ssm:{region}:{param}: {error_code}")

    def _delete_lambda_functions(self, region: str, functions: Set[str]):
        """Delete Lambda functions."""
        if not functions:
            return

        lambda_client = self.session.client("lambda", region_name=region)

        for func_name in functions:
            try:
                # Verify function exists
                try:
                    lambda_client.get_function(FunctionName=func_name)
                except ClientError as e:
                    if e.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                        self.skipped.append(f"lambda:{region}:{func_name} (not found)")
                        continue
                    raise

                if self.dry_run:
                    self.logger.info(f"[DRY-RUN] Would delete Lambda function: {func_name}")
                    self.deleted.append(f"lambda:{region}:{func_name}")
                else:
                    self.logger.info(f"Deleting Lambda function: {func_name}")
                    lambda_client.delete_function(FunctionName=func_name)
                    self.deleted.append(f"lambda:{region}:{func_name}")

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                self.logger.error(f"Failed to delete Lambda {func_name}: {error_code}")
                self.failed.append(f"lambda:{region}:{func_name}: {error_code}")

    def _delete_iam_roles(self, roles: Set[str]):
        """Delete IAM roles after detaching policies."""
        if not roles:
            return

        iam = self.session.client("iam")

        for role_name in roles:
            try:
                # Verify role exists
                try:
                    iam.get_role(RoleName=role_name)
                except ClientError as e:
                    if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                        self.skipped.append(f"iam:role/{role_name} (not found)")
                        continue
                    raise

                if self.dry_run:
                    self.logger.info(f"[DRY-RUN] Would delete IAM role: {role_name}")
                    self.deleted.append(f"iam:role/{role_name}")
                else:
                    self.logger.info(f"Cleaning up IAM role: {role_name}")

                    # Detach managed policies
                    attached = iam.list_attached_role_policies(RoleName=role_name)
                    for policy in attached.get("AttachedPolicies", []):
                        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy["PolicyArn"])

                    # Delete inline policies
                    inline = iam.list_role_policies(RoleName=role_name)
                    for policy_name in inline.get("PolicyNames", []):
                        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)

                    # Remove from instance profiles
                    profiles = iam.list_instance_profiles_for_role(RoleName=role_name)
                    for profile in profiles.get("InstanceProfiles", []):
                        iam.remove_role_from_instance_profile(
                            InstanceProfileName=profile["InstanceProfileName"],
                            RoleName=role_name
                        )

                    iam.delete_role(RoleName=role_name)
                    self.deleted.append(f"iam:role/{role_name}")

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                self.logger.error(f"Failed to delete IAM role {role_name}: {error_code}")
                self.failed.append(f"iam:role/{role_name}: {error_code}")

    def _delete_cloudformation_stacks(self, region: str, stacks: Set[str]):
        """Force delete CloudFormation stacks."""
        if not stacks:
            return

        cfn = self.session.client("cloudformation", region_name=region)

        for stack_name in stacks:
            try:
                if self.dry_run:
                    self.logger.info(f"[DRY-RUN] Would delete CloudFormation stack: {stack_name}")
                    self.deleted.append(f"cfn:{region}:{stack_name}")
                else:
                    self.logger.info(f"Deleting CloudFormation stack: {stack_name}")

                    try:
                        resources = cfn.list_stack_resources(StackName=stack_name)
                        retain = [
                            r["LogicalResourceId"]
                            for r in resources.get("StackResourceSummaries", [])
                            if r.get("ResourceStatus") == "DELETE_FAILED"
                        ]

                        if retain:
                            cfn.delete_stack(StackName=stack_name, RetainResources=retain)
                        else:
                            cfn.delete_stack(StackName=stack_name)

                    except ClientError:
                        cfn.delete_stack(StackName=stack_name)

                    self.deleted.append(f"cfn:{region}:{stack_name}")

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                self.logger.error(f"Failed to delete stack {stack_name}: {error_code}")
                self.failed.append(f"cfn:{region}:{stack_name}: {error_code}")


# ============================================================================
# Main Execution
# ============================================================================

def print_summary(resources: RegionalResources, region_count: int):
    """Print a summary of found resources."""
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Regions scanned: {region_count}")
    print()

    # S3 Buckets
    total_buckets = sum(len(s) for s in resources.s3_buckets.values())
    if total_buckets > 0:
        print(f"S3 Buckets: {total_buckets}")
        for region, buckets in resources.s3_buckets.items():
            for bucket in list(buckets)[:5]:
                print(f"  - [{region}] {bucket}")
            if len(buckets) > 5:
                print(f"  ... and {len(buckets) - 5} more in {region}")

    # Log Groups
    total_logs = sum(len(s) for s in resources.log_groups.values())
    if total_logs > 0:
        print(f"Log Groups: {total_logs}")
        shown = 0
        for region, log_groups in resources.log_groups.items():
            for lg in list(log_groups)[:10 - shown]:
                print(f"  - [{region}] {lg}")
                shown += 1
            if shown >= 10:
                break
        if total_logs > 10:
            print(f"  ... and {total_logs - 10} more")

    # SSM Parameters
    total_ssm = sum(len(s) for s in resources.ssm_parameters.values())
    if total_ssm > 0:
        print(f"SSM Parameters: {total_ssm}")
        for region, params in resources.ssm_parameters.items():
            for param in list(params)[:5]:
                print(f"  - [{region}] {param}")

    # Lambda Functions
    total_lambda = sum(len(s) for s in resources.lambda_functions.values())
    if total_lambda > 0:
        print(f"Lambda Functions: {total_lambda}")
        for region, funcs in resources.lambda_functions.items():
            for func in list(funcs)[:5]:
                print(f"  - [{region}] {func}")

    # IAM Roles
    if resources.iam_roles:
        print(f"IAM Roles: {len(resources.iam_roles)}")
        for role in list(resources.iam_roles)[:5]:
            print(f"  - {role}")

    # CloudFormation Stacks
    total_cfn = sum(len(s) for s in resources.cloudformation_stacks.values())
    if total_cfn > 0:
        print(f"CloudFormation Stacks: {total_cfn}")
        for region, stacks in resources.cloudformation_stacks.items():
            for stack in stacks:
                print(f"  - [{region}] {stack}")

    total = resources.total_count()
    print()
    print(f"Total resources found: {total}")
    print("=" * 60)

    return total


def confirm_deletion(total: int) -> bool:
    """Prompt user to confirm deletion."""
    print()
    print("WARNING: You are about to DELETE the resources listed above.")
    print("This action is IRREVERSIBLE.")
    print()

    response = input(f"Type 'DELETE {total} RESOURCES' to confirm: ")
    return response == f"DELETE {total} RESOURCES"


def main():
    parser = argparse.ArgumentParser(
        description="Vision One CloudFormation Resource Cleanup Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --dry-run                         # Scan current region (safe)
  %(prog)s --dry-run --all-regions           # Scan all regions
  %(prog)s --dry-run --region us-west-2      # Scan specific region
  %(prog)s --execute --region us-east-1      # Delete resources
        """
    )

    parser.add_argument("--dry-run", action="store_true", default=True)
    parser.add_argument("--execute", action="store_true", help="Actually delete resources")
    parser.add_argument("--region", type=str, help="AWS region to scan")
    parser.add_argument("--all-regions", action="store_true", help="Scan all regions")
    parser.add_argument("--stack-name", type=str, help="Filter by stack name pattern")
    parser.add_argument("--profile", type=str, help="AWS profile to use")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation")

    args = parser.parse_args()
    dry_run = not args.execute
    logger = setup_logging(args.verbose)

    if args.output == "text":
        print()
        print("Vision One CloudFormation Resource Cleanup Tool")
        print("-" * 50)
        print(f"Mode: {'DRY-RUN (no changes)' if dry_run else 'EXECUTE (will delete)'}")
        print()

    session, account_id = get_aws_session(args.profile, args.region)

    if args.output == "text":
        print(f"AWS Account: {account_id}")

    if args.all_regions:
        regions = get_all_regions(session)
        if args.output == "text":
            print(f"Scanning all {len(regions)} regions...")
    elif args.region:
        regions = [args.region]
    else:
        regions = [session.region_name or "us-east-1"]

    if args.output == "text":
        print(f"Regions: {', '.join(regions)}")
        print()

    # Scan all regions with proper tracking
    resources = RegionalResources()

    for region in regions:
        scanner = ResourceScanner(session, region, logger, resources, args.stack_name)
        scanner.scan_all()

    # Output results
    if args.output == "json":
        output = {
            "account_id": account_id,
            "regions": regions,
            "dry_run": dry_run,
            "resources": resources.to_dict(),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        print(json.dumps(output, indent=2))
        return

    total = print_summary(resources, len(regions))

    if total == 0:
        print("No Vision One resources found.")
        return

    if dry_run:
        print()
        print("This was a DRY-RUN. No resources were deleted.")
        print("To delete resources, run with --execute flag.")
        return

    if not args.yes:
        if not confirm_deletion(total):
            print("Aborted. No resources were deleted.")
            return

    print()
    print("Starting deletion...")
    print()

    cleaner = ResourceCleaner(session, logger, dry_run=False)
    deleted, failed, skipped = cleaner.delete_all(resources)

    print()
    print("=" * 60)
    print("DELETION COMPLETE")
    print("=" * 60)
    print(f"Successfully deleted: {len(deleted)}")
    print(f"Skipped (already gone): {len(skipped)}")
    print(f"Failed to delete: {len(failed)}")

    if failed:
        print()
        print("Failed resources:")
        for item in failed:
            print(f"  - {item}")


if __name__ == "__main__":
    main()
