#!/usr/bin/env bash
#
# Vision One CloudFormation Resource Cleanup - Bash Wrapper
#
# A simple wrapper around v1-cleanup.py for convenience.
# Always runs in dry-run mode unless explicitly told otherwise.
#
# Usage:
#   ./v1-cleanup.sh                    # Dry-run scan, current region
#   ./v1-cleanup.sh --all-regions      # Dry-run scan, all regions
#   ./v1-cleanup.sh --execute          # Delete (requires confirmation)
#
# Security:
#   - Dry-run is the default (safe)
#   - Validates Python and boto3 are available
#   - Never stores credentials

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="${SCRIPT_DIR}/v1-cleanup.py"

# Colors for output (if terminal supports it)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

error() {
    echo -e "${RED}ERROR:${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}WARNING:${NC} $1" >&2
}

info() {
    echo -e "${GREEN}INFO:${NC} $1"
}

# Check Python is available
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        # Verify it's Python 3
        if python --version 2>&1 | grep -q "Python 3"; then
            PYTHON_CMD="python"
        else
            error "Python 3 is required. Found: $(python --version 2>&1)"
            exit 1
        fi
    else
        error "Python 3 is not installed or not in PATH"
        echo "Install Python 3 and try again."
        exit 1
    fi
}

# Check boto3 is available
check_boto3() {
    if ! ${PYTHON_CMD} -c "import boto3" 2>/dev/null; then
        error "boto3 Python package is not installed"
        echo ""
        echo "Install it with:"
        echo "  pip install boto3"
        echo ""
        echo "Or with a virtual environment:"
        echo "  python3 -m venv venv"
        echo "  source venv/bin/activate"
        echo "  pip install boto3"
        exit 1
    fi
}

# Check the Python script exists
check_script() {
    if [[ ! -f "${PYTHON_SCRIPT}" ]]; then
        error "Python script not found: ${PYTHON_SCRIPT}"
        exit 1
    fi
}

# Show help
show_help() {
    cat << 'EOF'
Vision One CloudFormation Resource Cleanup Tool

Usage: v1-cleanup.sh [OPTIONS]

Options:
  --dry-run           Scan only, no deletions (DEFAULT)
  --execute           Actually delete resources (requires confirmation)
  --region REGION     Scan specific AWS region
  --all-regions       Scan all enabled AWS regions
  --stack-name NAME   Filter by CloudFormation stack name pattern
  --profile PROFILE   Use specific AWS profile
  --output FORMAT     Output format: text (default) or json
  --verbose, -v       Enable verbose logging
  --yes, -y           Skip confirmation (use with extreme caution)
  --help, -h          Show this help message

Examples:
  ./v1-cleanup.sh                              # Safe scan, current region
  ./v1-cleanup.sh --all-regions                # Safe scan, all regions
  ./v1-cleanup.sh --region us-east-1           # Scan specific region
  ./v1-cleanup.sh --stack-name Vision-One      # Filter by stack name
  ./v1-cleanup.sh --execute --region us-east-1 # Delete (with confirmation)
  ./v1-cleanup.sh --output json > report.json  # Export as JSON

Security Notes:
  - Dry-run mode is enabled by default
  - Deletion requires --execute AND interactive confirmation
  - Uses standard AWS credential chain
  - Never stores or logs credentials
EOF
}

# Main
main() {
    # Check for help flag first
    for arg in "$@"; do
        if [[ "$arg" == "--help" || "$arg" == "-h" ]]; then
            show_help
            exit 0
        fi
    done

    # Preflight checks
    check_python
    check_boto3
    check_script

    # Check if --execute is being used
    for arg in "$@"; do
        if [[ "$arg" == "--execute" ]]; then
            warn "EXECUTE mode enabled - resources WILL be deleted!"
            echo ""
            break
        fi
    done

    # Run the Python script with all passed arguments
    # If no arguments, default to --dry-run
    if [[ $# -eq 0 ]]; then
        info "Running in dry-run mode (default, safe)"
        echo ""
        exec ${PYTHON_CMD} "${PYTHON_SCRIPT}" --dry-run
    else
        exec ${PYTHON_CMD} "${PYTHON_SCRIPT}" "$@"
    fi
}

main "$@"
