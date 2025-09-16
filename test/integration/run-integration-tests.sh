#!/bin/bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_TIMEOUT=300s
COMPOSE_FILE="docker-compose.yml"
TEST_DIR="$(dirname "$(realpath "$0")")"
PROJECT_ROOT="$(dirname "$(dirname "$TEST_DIR")")"

echo -e "${BLUE}🚀 Starting kubectl-ssh-oidc Integration Tests${NC}"
echo "========================================================"

cd "$TEST_DIR"

# Check prerequisites
check_prerequisites() {
    echo -e "${BLUE}🔍 Checking prerequisites...${NC}"
    
    local missing_tools=()
    
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        missing_tools+=("docker-compose")
    fi
    
    if ! command -v go &> /dev/null; then
        missing_tools+=("go")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${RED}❌ Missing required tools: ${missing_tools[*]}${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ All prerequisites satisfied${NC}"
}

# Clean up any existing containers
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up containers...${NC}"
    
    docker-compose down -v --remove-orphans 2>/dev/null || true
    
    # Remove any leftover images from previous test runs
    docker images -q "kubectl-ssh-oidc/dex" | xargs -r docker rmi -f 2>/dev/null || true
    
    echo -e "${GREEN}✅ Cleanup completed${NC}"
}

# Build the custom Dex image
build_dex_image() {
    echo -e "${BLUE}🏗️  Building custom Dex image with SSH connector...${NC}"
    
    cd "$PROJECT_ROOT"
    
    # Build the image using our Dockerfile with repository root as context
    docker build -f docker/dex/Dockerfile -t kubectl-ssh-oidc/dex:latest .
    
    echo -e "${GREEN}✅ Custom Dex image built successfully${NC}"
    
    cd "$TEST_DIR"
}

# Verify Dex image contains SSH connector
verify_dex_image() {
    echo -e "${BLUE}🔍 Verifying Dex image contains SSH connector...${NC}"
    
    # Create a temporary config to test the SSH connector is recognized
    cat > temp-verify-config.yaml << 'EOF'
issuer: http://localhost:5556/dex
storage:
  type: memory
web:
  http: 127.0.0.1:5556
logger:
  level: info
connectors:
- type: ssh
  id: ssh
  name: SSH Test
  config:
    users:
      "test": 
        keys: ["SHA256:dummy"]
        username: "test"
        email: "test@example.com"
        groups: ["test"]
    allowed_issuers: ["test"]
    token_ttl: 3600
staticClients:
- id: test
  name: 'Test'  
  secret: test
EOF

    # Test that Dex can parse the SSH connector config without errors
    # Capture output and check for SSH connector
    local output
    output=$(timeout 10s docker run --rm -v "$PWD/temp-verify-config.yaml:/config.yaml:ro" \
        kubectl-ssh-oidc/dex:latest serve /config.yaml 2>&1) || true
    
    if echo "$output" | grep -q "config connector: ssh"; then
        echo -e "${GREEN}✅ SSH connector verified in Dex image${NC}"
    else
        echo -e "${RED}❌ SSH connector not properly loaded in Dex${NC}"
        echo "Debug output: $output"
        rm -f temp-verify-config.yaml
        exit 1
    fi
    
    rm -f temp-verify-config.yaml
}

# Run the integration tests
run_tests() {
    echo -e "${BLUE}🧪 Running integration tests...${NC}"
    
    cd "$TEST_DIR"
    
    # Set integration test environment
    export INTEGRATION_TEST=true
    export CGO_ENABLED=1
    
    # Run the tests with timeout
    timeout "$TEST_TIMEOUT" go test -v -timeout="$TEST_TIMEOUT" ./... || {
        local exit_code=$?
        echo -e "${RED}❌ Integration tests failed (exit code: $exit_code)${NC}"
        
        # Show container logs for debugging
        echo -e "${YELLOW}📋 Container logs for debugging:${NC}"
        echo "============================================="
        echo "Dex logs:"
        docker-compose logs dex || true
        echo "============================================="
        
        return $exit_code
    }
    
    echo -e "${GREEN}✅ All integration tests passed!${NC}"
}

# Main execution
main() {
    # Trap to ensure cleanup happens
    trap cleanup EXIT
    
    check_prerequisites
    cleanup
    build_dex_image
    verify_dex_image
    run_tests
    
    echo -e "${GREEN}🎉 Integration tests completed successfully!${NC}"
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --help, -h    Show this help message"
    echo "  --cleanup     Only run cleanup and exit"
    echo "  --build       Only build the Dex image and exit"
    echo "  --verify      Only verify the Dex image and exit"
    echo ""
    echo "Environment variables:"
    echo "  TEST_TIMEOUT  Test timeout duration (default: 300s)"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        show_usage
        exit 0
        ;;
    --cleanup)
        cleanup
        exit 0
        ;;
    --build)
        build_dex_image
        exit 0
        ;;
    --verify)
        build_dex_image
        verify_dex_image
        exit 0
        ;;
    "")
        main
        ;;
    *)
        echo -e "${RED}Unknown option: $1${NC}"
        show_usage
        exit 1
        ;;
esac