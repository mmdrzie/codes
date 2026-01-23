#!/bin/bash

# OWASP ZAP Security Scan Script
# Performs automated security scanning of the application

set -e  # Exit on any error

# Configuration
TARGET_URL="http://localhost:3000"
ZAP_PORT=8090
ZAP_API_KEY="changeme"
REPORT_DIR="./reports/security"
REPORT_FILE="$REPORT_DIR/zap-scan-report.html"
CONTEXT_NAME="MyAppContext"
USER_AGENT="Mozilla/5.0 (OWASP ZAP)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting OWASP ZAP Security Scan${NC}"
echo "=================================="

# Create reports directory if it doesn't exist
mkdir -p $REPORT_DIR

# Check if ZAP is running
echo -e "${YELLOW}Checking if ZAP daemon is running...${NC}"
if ! curl -s http://localhost:$ZAP_PORT > /dev/null 2>&1; then
    echo -e "${RED}ZAP daemon is not running. Starting ZAP in daemon mode...${NC}"
    
    # Start ZAP in daemon mode (background)
    docker run -u zap -d -p $ZAP_PORT:$ZAP_PORT --name owasp-zap \
        -v $(pwd)/.owasp-zap:/home/zap/.ZAP_D \
        owasp/zap2docker-stable zap.sh \
        -daemon -host 0.0.0.0 -port $ZAP_PORT -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
    
    # Wait for ZAP to start
    echo -e "${YELLOW}Waiting for ZAP to start...${NC}"
    until curl -s http://localhost:$ZAP_PORT > /dev/null 2>&1; do
        sleep 5
        echo -n "."
    done
    echo ""
    echo -e "${GREEN}ZAP started successfully${NC}"
else
    echo -e "${GREEN}ZAP daemon is already running${NC}"
fi

# Function to send ZAP API request
zap_api_request() {
    local endpoint=$1
    local method=${2:-GET}
    local data=${3:-""}
    
    if [ "$method" = "POST" ]; then
        curl -s -X POST "http://localhost:$ZAP_PORT/JSON/$endpoint/?apikey=$ZAP_API_KEY&$data"
    else
        curl -s "http://localhost:$ZAP_PORT/JSON/$endpoint/?apikey=$ZAP_API_KEY&$data"
    fi
}

# Function to wait for ZAP spider to complete
wait_for_spider() {
    local task_id=$1
    while true; do
        status=$(curl -s "http://localhost:$ZAP_PORT/JSON/spider/view/status/?apikey=$ZAP_API_KEY&scanId=$task_id" | jq -r '.status')
        if [ "$status" = "100" ] || [ "$status" = "" ]; then
            break
        fi
        echo "Spider progress: $status%"
        sleep 10
    done
}

# Function to wait for ZAP scanner to complete
wait_for_scanner() {
    local task_id=$1
    while true; do
        status=$(curl -s "http://localhost:$ZAP_PORT/JSON/ascan/view/status/?apikey=$ZAP_API_KEY&scanId=$task_id" | jq -r '.status')
        if [ "$status" = "100" ] || [ "$status" = "" ]; then
            break
        fi
        echo "Scanner progress: $status%"
        sleep 15
    done
}

# Step 1: Start fresh session
echo -e "${YELLOW}Step 1: Starting fresh ZAP session${NC}"
zap_api_request "core/action/newSession" "POST" "name=zap-session&overwrite=true"

# Step 2: Set up context
echo -e "${YELLOW}Step 2: Setting up context ($CONTEXT_NAME)${NC}"
zap_api_request "context/action/newContext" "POST" "contextName=$CONTEXT_NAME"

# Include URLs in context
echo -e "${YELLOW}Adding target URL to context${NC}"
zap_api_request "context/action/includeInContext" "POST" "contextName=$CONTEXT_NAME&regex=$TARGET_URL.*"

# Step 3: Spider the application
echo -e "${YELLOW}Step 3: Starting spider scan on $TARGET_URL${NC}"
spider_response=$(zap_api_request "spider/action/scan" "POST" "url=$TARGET_URL&contextName=$CONTEXT_NAME&userAgent=$USER_AGENT")
spider_id=$(echo $spider_response | jq -r '.scan')

if [ "$spider_id" != "null" ]; then
    wait_for_spider $spider_id
    echo -e "${GREEN}Spider scan completed${NC}"
else
    echo -e "${RED}Spider scan failed to start${NC}"
    exit 1
fi

# Step 4: Active scan
echo -e "${YELLOW}Step 4: Starting active security scan${NC}"
scanner_response=$(zap_api_request "ascan/action/scan" "POST" "url=$TARGET_URL&contextName=$CONTEXT_NAME&recurse=true&inScopeOnly=true")
scanner_id=$(echo $scanner_response | jq -r '.scan')

if [ "$scanner_id" != "null" ]; then
    wait_for_scanner $scanner_id
    echo -e "${GREEN}Active scan completed${NC}"
else
    echo -e "${RED}Active scan failed to start${NC}"
    exit 1
fi

# Step 5: Wait for passive scan to complete
echo -e "${YELLOW}Step 5: Waiting for passive scan to complete${NC}"
sleep 30  # Give some time for passive scanning to finish

# Step 6: Generate HTML report
echo -e "${YELLOW}Step 6: Generating HTML report${NC}"
curl -s -o $REPORT_FILE "http://localhost:$ZAP_PORT/OTHER/core/other/htmlreport/?apikey=$ZAP_API_KEY"

# Step 7: Get alert summary
echo -e "${YELLOW}Step 7: Getting security alerts${NC}"
alerts_json="$REPORT_DIR/alerts.json"
curl -s "http://localhost:$ZAP_PORT/JSON/core/view/alerts/?apikey=$ZAP_API_KEY&baseurl=$TARGET_URL" -o $alerts_json

# Parse and display alert summary
high_alerts=$(jq '[.alerts[] | select(.risk = "High")] | length' $alerts_json)
medium_alerts=$(jq '[.alerts[] | select(.risk = "Medium")] | length' $alerts_json)
low_alerts=$(jq '[.alerts[] | select(.risk = "Low")] | length' $alerts_json)
info_alerts=$(jq '[.alerts[] | select(.risk = "Informational")] | length' $alerts_json)

echo ""
echo -e "${YELLOW}Security Scan Results:${NC}"
echo "========================="
echo -e "High Risk Alerts: ${RED}$high_alerts${NC}"
echo -e "Medium Risk Alerts: ${YELLOW}$medium_alerts${NC}"
echo -e "Low Risk Alerts: $low_alerts"
echo -e "Info Alerts: $info_alerts"
echo ""

# Determine pass/fail status
if [ "$high_alerts" -eq 0 ] && [ "$medium_alerts" -eq 0 ]; then
    echo -e "${GREEN}✓ Security scan PASSED - No high or medium risk vulnerabilities found${NC}"
    SCAN_STATUS="PASS"
else
    echo -e "${RED}✗ Security scan FAILED - Vulnerabilities detected${NC}"
    SCAN_STATUS="FAIL"
fi

# Generate summary report
cat > $REPORT_DIR/summary.txt << EOF
OWASP ZAP Security Scan Summary
===============================

Target: $TARGET_URL
Scan Date: $(date)
Status: $SCAN_STATUS

Alert Counts:
- High Risk: $high_alerts
- Medium Risk: $medium_alerts  
- Low Risk: $low_alerts
- Info: $info_alerts

Report Location: $REPORT_FILE

Recommendations:
$(if [ "$high_alerts" -gt 0 ] || [ "$medium_alerts" -gt 0 ]; then
    echo "- Address all high and medium risk vulnerabilities immediately"
    echo "- Review low risk vulnerabilities for potential exploitation"
    echo "- Implement additional security controls as needed"
else
    echo "- Maintain current security posture"
    echo "- Schedule regular re-scanning"
fi)
EOF

echo -e "${GREEN}Scan report saved to: $REPORT_FILE${NC}"
echo -e "${GREEN}Summary report saved to: $REPORT_DIR/summary.txt${NC}"

# Stop ZAP container if we started it
if [ "$(docker ps -q -f name=owasp-zap)" ]; then
    echo -e "${YELLOW}Stopping ZAP container${NC}"
    docker stop owasp-zap > /dev/null 2>&1
    docker rm owasp-zap > /dev/null 2>&1
fi

echo ""
if [ "$SCAN_STATUS" = "PASS" ]; then
    echo -e "${GREEN}OWASP ZAP scan completed successfully - All clear!${NC}"
    exit 0
else
    echo -e "${RED}OWASP ZAP scan completed - Issues found that need attention${NC}"
    exit 1
fi