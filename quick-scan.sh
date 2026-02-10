#!/usr/bin/env bash
#
# Vision One Resource Quick Scan
#
# Fast bash-based discovery of Vision One resources.
# Uses AWS CLI directly for quick ad-hoc checks.
# READ-ONLY - never modifies or deletes anything.
#
# Requirements:
#   - AWS CLI v2 installed and configured
#   - jq for JSON parsing
#
# Usage:
#   ./quick-scan.sh                    # Scan current region
#   ./quick-scan.sh us-west-2          # Scan specific region
#   ./quick-scan.sh all                # Scan all regions (slower)
#
# Security:
#   - Read-only operations only
#   - Uses standard AWS credential chain
#   - No credentials stored or logged

set -euo pipefail

# Colors
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    BOLD=''
    NC=''
fi

# Counters
TOTAL_FOUND=0

header() {
    echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}"
}

found() {
    echo -e "  ${GREEN}[FOUND]${NC} $1"
    ((TOTAL_FOUND++)) || true
}

info() {
    echo -e "  ${YELLOW}[INFO]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check prerequisites
check_prerequisites() {
    if ! command -v aws &> /dev/null; then
        error "AWS CLI is not installed. Install from: https://aws.amazon.com/cli/"
        exit 1
    fi

    if ! command -v jq &> /dev/null; then
        error "jq is not installed. Install with: brew install jq (macOS) or apt install jq (Linux)"
        exit 1
    fi

    # Verify AWS credentials work
    if ! aws sts get-caller-identity &> /dev/null; then
        error "AWS credentials not configured or invalid"
        echo "Configure with: aws configure"
        exit 1
    fi
}

# Get all enabled regions
get_all_regions() {
    aws ec2 describe-regions --query 'Regions[].RegionName' --output text | tr '\t' '\n' | sort
}

# Scan for tagged resources
scan_tagged_resources() {
    local region=$1

    header "Tagged Resources (TrendMicroProduct) - ${region}"

    local tags=("cam" "ct" "cs" "dspm" "fss" "sentry")

    for tag_value in "${tags[@]}"; do
        local count
        count=$(aws resourcegroupstaggingapi get-resources \
            --region "${region}" \
            --tag-filters "Key=TrendMicroProduct,Values=${tag_value}" \
            --query 'length(ResourceTagMappingList)' \
            --output text 2>/dev/null || echo "0")

        if [[ "${count}" -gt 0 ]]; then
            found "TrendMicroProduct=${tag_value}: ${count} resources"

            # Show first few ARNs
            aws resourcegroupstaggingapi get-resources \
                --region "${region}" \
                --tag-filters "Key=TrendMicroProduct,Values=${tag_value}" \
                --query 'ResourceTagMappingList[0:3].ResourceARN' \
                --output text 2>/dev/null | while read -r arn; do
                    echo "       ${arn}"
                done
        fi
    done
}

# Scan S3 buckets
scan_s3_buckets() {
    local region=$1

    header "S3 Buckets - ${region}"

    local prefixes=("v1cs-" "cloud-one-sentry-" "v1-avtd-" "v1-common-" "trendmicro-")

    # List all buckets (global operation)
    local buckets
    buckets=$(aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null || echo "")

    for bucket in ${buckets}; do
        for prefix in "${prefixes[@]}"; do
            if [[ "${bucket}" == ${prefix}* ]]; then
                # Check bucket region
                local bucket_region
                bucket_region=$(aws s3api get-bucket-location --bucket "${bucket}" \
                    --query 'LocationConstraint' --output text 2>/dev/null || echo "error")

                # Handle null (us-east-1) case
                [[ "${bucket_region}" == "None" || "${bucket_region}" == "null" ]] && bucket_region="us-east-1"

                if [[ "${bucket_region}" == "${region}" ]]; then
                    found "${bucket}"
                fi
                break
            fi
        done
    done
}

# Scan CloudWatch Log Groups
scan_log_groups() {
    local region=$1

    header "CloudWatch Log Groups - ${region}"

    local prefixes=(
        "/aws/lambda/Vision-One-"
        "/aws/lambda/v1-"
        "/aws/lambda/trendmicro-container-security-"
        "/aws/lambda/v1cs-"
        "/aws/lambda/StackSet-V1DspmStackSet-"
        "/aws/lambda/StackSet-V1CommonStackSet-"
        "/aws/lambda/StackSet-V1SentryStackSet-"
    )

    for prefix in "${prefixes[@]}"; do
        local groups
        groups=$(aws logs describe-log-groups \
            --region "${region}" \
            --log-group-name-prefix "${prefix}" \
            --query 'logGroups[].logGroupName' \
            --output text 2>/dev/null || echo "")

        for group in ${groups}; do
            found "${group}"
        done
    done
}

# Scan SSM Parameters
scan_ssm_parameters() {
    local region=$1

    header "SSM Parameters - ${region}"

    local prefixes=("/V1CS" "/TrendMicro")

    for prefix in "${prefixes[@]}"; do
        local params
        params=$(aws ssm get-parameters-by-path \
            --region "${region}" \
            --path "${prefix}" \
            --recursive \
            --query 'Parameters[].Name' \
            --output text 2>/dev/null || echo "")

        for param in ${params}; do
            found "${param}"
        done
    done
}

# Scan Lambda Functions
scan_lambda_functions() {
    local region=$1

    header "Lambda Functions - ${region}"

    local prefixes=("v1-" "v1cs-" "trendmicro-container-security-" "Vision-One-")

    local functions
    functions=$(aws lambda list-functions \
        --region "${region}" \
        --query 'Functions[].FunctionName' \
        --output text 2>/dev/null || echo "")

    for func in ${functions}; do
        for prefix in "${prefixes[@]}"; do
            if [[ "${func}" == ${prefix}* ]]; then
                found "${func}"
                break
            fi
        done
    done
}

# Scan DELETE_FAILED CloudFormation Stacks
scan_failed_stacks() {
    local region=$1

    header "DELETE_FAILED CloudFormation Stacks - ${region}"

    local stacks
    stacks=$(aws cloudformation list-stacks \
        --region "${region}" \
        --stack-status-filter DELETE_FAILED \
        --query 'StackSummaries[].StackName' \
        --output text 2>/dev/null || echo "")

    local v1_patterns=("VisionOne" "Vision-One" "TrendMicro" "v1cs" "v1-" "Dspm" "Sentry" "Calm" "Fss")

    for stack in ${stacks}; do
        for pattern in "${v1_patterns[@]}"; do
            if [[ "${stack,,}" == *"${pattern,,}"* ]]; then
                found "${stack}"
                break
            fi
        done
    done
}

# Scan IAM Roles (global)
scan_iam_roles() {
    header "IAM Roles (Global)"

    local patterns=("VisionOne" "TrendMicro" "v1-avtd" "v1-common" "v1cs-")

    local roles
    roles=$(aws iam list-roles --query 'Roles[].RoleName' --output text 2>/dev/null || echo "")

    for role in ${roles}; do
        for pattern in "${patterns[@]}"; do
            if [[ "${role}" == *"${pattern}"* ]]; then
                found "${role}"
                break
            fi
        done
    done
}

# Run scan for a single region
scan_region() {
    local region=$1

    echo -e "\n${BOLD}Scanning region: ${region}${NC}"
    echo "================================================"

    scan_tagged_resources "${region}"
    scan_s3_buckets "${region}"
    scan_log_groups "${region}"
    scan_ssm_parameters "${region}"
    scan_lambda_functions "${region}"
    scan_failed_stacks "${region}"

    # IAM is global, only scan once
    if [[ "${region}" == "us-east-1" ]]; then
        scan_iam_roles
    fi
}

# Print summary
print_summary() {
    echo ""
    echo "================================================"
    echo -e "${BOLD}SUMMARY${NC}"
    echo "================================================"
    echo -e "Total Vision One resources found: ${BOLD}${TOTAL_FOUND}${NC}"
    echo ""

    if [[ ${TOTAL_FOUND} -gt 0 ]]; then
        echo "To delete these resources, use the Python cleanup tool:"
        echo "  ./v1-cleanup.sh --execute"
        echo ""
        echo "Or for a detailed scan first:"
        echo "  ./v1-cleanup.sh --dry-run --output json > scan-results.json"
    else
        echo "No Vision One resources found."
    fi
}

# Main
main() {
    echo ""
    echo -e "${BOLD}Vision One Resource Quick Scan${NC}"
    echo "================================"
    echo "Read-only scan for orphaned Vision One resources"
    echo ""

    check_prerequisites

    # Get AWS account info
    local account_id
    account_id=$(aws sts get-caller-identity --query 'Account' --output text)
    echo -e "AWS Account: ${BOLD}${account_id}${NC}"

    local target_region="${1:-}"

    if [[ "${target_region}" == "all" ]]; then
        echo "Mode: All regions"
        echo ""

        local regions
        regions=$(get_all_regions)

        for region in ${regions}; do
            scan_region "${region}"
        done

    elif [[ -n "${target_region}" ]]; then
        echo "Mode: Single region (${target_region})"
        scan_region "${target_region}"

    else
        # Default to current region from AWS config
        local default_region
        default_region=$(aws configure get region 2>/dev/null || echo "us-east-1")
        echo "Mode: Single region (${default_region})"
        scan_region "${default_region}"
    fi

    print_summary
}

main "$@"
