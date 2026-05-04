#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 SAP SE and IPv6 Web Resource Checker contributors
#
# SPDX-License-Identifier: Apache-2.0
#

# Test runner script for webres6-api
# Usage: ./run_tests.sh [options]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# temp directory for prometheus data
export PROMETHEUS_MULTIPROC_DIR="$(mktemp -d)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default options
COVERAGE=0
VERBOSE=0
SPECIFIC_TEST=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--coverage)
            COVERAGE=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -t|--test)
            SPECIFIC_TEST="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -c, --coverage     Run tests with coverage report"
            echo "  -v, --verbose      Run tests with verbose output"
            echo "  -t, --test TEST    Run specific test file or pattern"
            echo "  -h, --help         Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                           # Run all tests"
            echo "  $0 -c                        # Run with coverage"
            echo "  $0 -t test_webres6_api.py   # Run specific test file"
            echo "  $0 -c -v                     # Coverage with verbose output"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${GREEN}=== Webres6 API Test Runner ===${NC}"
echo ""

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo -e "${YELLOW}pytest not found. Installing test dependencies...${NC}"
    pip install -e ".[test]"
fi

# Build pytest command
PYTEST_CMD="pytest"

if [ $VERBOSE -eq 1 ]; then
    PYTEST_CMD="$PYTEST_CMD -vv"
fi

if [ $COVERAGE -eq 1 ]; then
    PYTEST_CMD="$PYTEST_CMD --cov=webres6_api --cov=webres6_storage --cov=webres6_whois --cov-report=term --cov-report=html"
    echo -e "${GREEN}Running tests with coverage...${NC}"
else
    echo -e "${GREEN}Running tests...${NC}"
fi

if [ -n "$SPECIFIC_TEST" ]; then
    PYTEST_CMD="$PYTEST_CMD $SPECIFIC_TEST"
    echo -e "${YELLOW}Running specific test: $SPECIFIC_TEST${NC}"
fi

echo ""

# clean up prometheus data directory after tests
if [ -d "$PROMETHEUS_MULTIPROC_DIR" ]; then
    trap "rm -rf $PROMETHEUS_MULTIPROC_DIR" EXIT
fi 

# Run tests
if $PYTEST_CMD; then
    echo ""
    echo -e "${GREEN}✓ All tests passed!${NC}"

    if [ $COVERAGE -eq 1 ]; then
        echo ""
        echo -e "${GREEN}Coverage report generated in htmlcov/index.html${NC}"

        # Open coverage report if on macOS
        if [[ "$OSTYPE" == "darwin"* ]]; then
            echo -e "${YELLOW}Opening coverage report...${NC}"
            open htmlcov/index.html 2>/dev/null || true
        fi
    fi

    exit 0
else
    echo ""
    echo -e "${RED}✗ Tests failed!${NC}"
    exit 1
fi
