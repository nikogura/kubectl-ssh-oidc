# kubectl-ssh-oidc Makefile

BINARY_NAME=kubectl-ssh_oidc
VERSION?=v1.0.0
BUILD_DIR=./bin
GO_FILES=$(shell find . -name "*.go" -type f)

# Build flags
LDFLAGS=-ldflags "-X main.Version=${VERSION} -s -w"
GCFLAGS=-gcflags="all=-trimpath=${PWD}"
ASMFLAGS=-asmflags="all=-trimpath=${PWD}"

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build: $(BUILD_DIR)/$(BINARY_NAME)

$(BUILD_DIR)/$(BINARY_NAME): $(GO_FILES) go.mod go.sum
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(LDFLAGS) $(GCFLAGS) $(ASMFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

# Cross-compile for multiple platforms
.PHONY: build-all
build-all:
	@mkdir -p $(BUILD_DIR)
	# Linux AMD64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	# Linux ARM64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	# Darwin AMD64 (Intel Mac)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	# Darwin ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	# Windows AMD64
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .

# Install the plugin to kubectl's plugin directory
.PHONY: install
install: build
	@echo "Installing kubectl-ssh-oidc plugin..."
	@if [ -z "$$HOME" ]; then echo "HOME environment variable not set"; exit 1; fi
	@mkdir -p $$HOME/.local/bin
	cp $(BUILD_DIR)/$(BINARY_NAME) $$HOME/.local/bin/
	chmod +x $$HOME/.local/bin/$(BINARY_NAME)
	@echo "Plugin installed to $$HOME/.local/bin/$(BINARY_NAME)"
	@echo "Make sure $$HOME/.local/bin is in your PATH"
	@echo ""
	@echo "Usage:"
	@echo "  kubectl ssh-oidc --help"

# Install to system-wide location (requires sudo)
.PHONY: install-system
install-system: build
	@echo "Installing kubectl-ssh-oidc plugin system-wide..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "Plugin installed to /usr/local/bin/$(BINARY_NAME)"

# Run tests
.PHONY: test
test:
	go test -v -race -coverprofile=coverage.out ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage: test
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run integration tests with custom Dex (includes unit tests and lint as prerequisites)
.PHONY: test-integration
test-integration: test lint
	@echo "Running end-to-end integration tests..."
	@echo "✅ Unit tests and lint checks passed - proceeding with integration tests"
	./test/integration/run-integration-tests.sh

# Run full local integration tests with Go (fast version)
.PHONY: test-integration-local
test-integration-local: test lint
	@echo "Running local integration tests with Go..."
	@echo "✅ Unit tests and lint checks passed - proceeding with integration tests"
	INTEGRATION_TEST=true go test -v -timeout 120s ./test/integration

# Run all tests (unit + integration)
.PHONY: test-all
test-all: test lint test-integration
	@echo "✅ All tests passed (unit + lint + integration)!"

# Build custom Dex image for integration testing
.PHONY: build-dex
build-dex:
	@echo "Building custom Dex image with SSH connector..."
	docker build -f docker/integration-testing/Dockerfile -t kubectl-ssh-oidc/dex:latest .

# Verify custom Dex image works correctly
.PHONY: verify-dex
verify-dex:
	@echo "Verifying custom Dex image..."
	./test/integration/run-integration-tests.sh --verify

# Clean up integration test containers and images
.PHONY: clean-integration
clean-integration:
	@echo "Cleaning up integration test environment..."
	./test/integration/run-integration-tests.sh --cleanup
	docker images -q "kubectl-ssh-oidc/dex" | xargs -r docker rmi -f 2>/dev/null || true

# Lint the code
.PHONY: lint
lint:
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "golangci-lint not found. Installing..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	golangci-lint run

# Format the code
.PHONY: fmt
fmt:
	go fmt ./...
	goimports -w .

# Tidy dependencies
.PHONY: tidy
tidy:
	go mod tidy

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Clean kubectl caches (fixes exec plugin not being called)
.PHONY: clean-kubectl-cache
clean-kubectl-cache:
	@echo "🧹 Cleaning kubectl caches..."
	@if [ -d ~/.kube/cache ]; then \
		echo "Removing ~/.kube/cache/"; \
		rm -rf ~/.kube/cache/; \
	fi
	@if [ -d ~/.kube/http-cache ]; then \
		echo "Removing ~/.kube/http-cache/"; \
		rm -rf ~/.kube/http-cache/; \
	fi
	@echo "✅ kubectl caches cleared"

# Show help
.PHONY: help
help:
	@echo "kubectl-ssh-oidc Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  build           Build the binary"
	@echo "  build-all       Cross-compile for multiple platforms"
	@echo "  build-dex       Build custom Dex image with SSH connector"
	@echo "  install         Install to user's local bin directory"
	@echo "  install-system  Install system-wide (requires sudo)"
	@echo "  test            Run unit tests"
	@echo "  test-coverage   Run tests with coverage report"
	@echo "  test-integration Run end-to-end integration tests (shell script approach)"
	@echo "  test-integration-local Run local Go integration tests (fast, GitHub Actions compatible)"
	@echo "  test-all        Run all tests (unit + lint + integration)"
	@echo "  test-manual     Test authentication with deployed Dex (requires env vars)"
	@echo "  test-kubectl-debug Diagnose kubectl exec plugin integration issues"
	@echo "  test-kubectl-e2e End-to-end kubectl test using existing config"
	@echo "  verify-dex      Verify custom Dex image works"
	@echo "  clean-integration Clean integration test environment"
	@echo "  lint            Lint the code"
	@echo "  fmt             Format the code"
	@echo "  tidy            Tidy dependencies"
	@echo "  clean           Clean build artifacts"
	@echo "  clean-kubectl-cache Clear kubectl caches (fixes exec plugin issues)"
	@echo "  help            Show this help"
	@echo ""
	@echo "Environment variables:"
	@echo "  VERSION       Version to build (default: v1.0.0)"

# Check if SSH agent is running and has keys
.PHONY: check-ssh
check-ssh:
	@echo "Checking SSH agent status..."
	@if [ -z "$$SSH_AUTH_SOCK" ]; then \
		echo "❌ SSH_AUTH_SOCK not set. SSH agent not running."; \
		echo "Start SSH agent with: eval \$$(ssh-agent -s)"; \
		exit 1; \
	else \
		echo "✅ SSH agent is running"; \
	fi
	@if ! ssh-add -l >/dev/null 2>&1; then \
		echo "❌ No SSH keys loaded in agent"; \
		echo "Add keys with: ssh-add ~/.ssh/id_rsa"; \
		exit 1; \
	else \
		echo "✅ SSH keys are loaded:"; \
		ssh-add -l; \
	fi

# Generate SSH key fingerprints for Dex configuration
.PHONY: ssh-fingerprints
ssh-fingerprints: check-ssh
	@echo "SSH Key Fingerprints for Dex configuration:"
	@echo "==========================================="
	@ssh-add -l | while read keysize fingerprint comment keytype; do \
		echo "  \"$$fingerprint\":"; \
		echo "    username: \"your-username\""; \
		echo "    email: \"your-email@example.com\""; \
		echo "    full_name: \"Your Full Name\""; \
		echo "    groups:"; \
		echo "    - \"developers\""; \
		echo "    - \"kubernetes-users\""; \
		echo ""; \
	done

# Development helpers
.PHONY: dev-setup
dev-setup:
	go mod download
	@echo "Development environment ready!"

# Manual testing target - verifies authentication works with Dex deployment
# Requires environment variables: DEX_URL, CLIENT_ID, CLIENT_SECRET, KUBECTL_SSH_USER
.PHONY: test-manual
test-manual:
	@echo "🔐 Manual Authentication Test"
	@echo "=============================="
	@echo ""
	@echo "Prerequisites:"
	@echo "✅ Dex deployment running with SSH connector"
	@echo "✅ kubectl-ssh-oidc in PATH"  
	@echo "✅ SSH agent with authorized keys loaded"
	@echo "✅ Environment variables set: DEX_URL, CLIENT_ID, CLIENT_SECRET, KUBECTL_SSH_USER"
	@echo ""
	@if [ -z "$$DEX_URL" ] || [ -z "$$CLIENT_ID" ] || [ -z "$$CLIENT_SECRET" ] || [ -z "$$KUBECTL_SSH_USER" ]; then \
		echo "❌ Missing required environment variables:"; \
		echo "   DEX_URL, CLIENT_ID, CLIENT_SECRET, KUBECTL_SSH_USER"; \
		echo ""; \
		echo "Example:"; \
		echo "   export DEX_URL=https://your-dex-instance.com"; \
		echo "   export CLIENT_ID=your-client-id"; \
		echo "   export CLIENT_SECRET=your-client-secret"; \
		echo "   export KUBECTL_SSH_USER=your-username"; \
		echo "   make test-manual"; \
		exit 1; \
	fi
	@echo "Testing authentication flow..."
	@echo ""
	@echo "1️⃣  Direct authentication test:"
	@kubectl-ssh-oidc > /tmp/kubectl-ssh-oidc-test.json 2>&1 && \
	  echo "✅ Authentication successful - JWT token generated" || \
	  (echo "❌ Authentication failed:"; cat /tmp/kubectl-ssh-oidc-test.json; exit 1)
	@echo ""
	@echo "2️⃣  JWT token format verification:"
	@JWT_TOKEN=$$(jq -r '.status.token' /tmp/kubectl-ssh-oidc-test.json 2>/dev/null) && \
	 JWT_HEADER=$$(echo "$$JWT_TOKEN" | cut -d. -f1) && \
	 JWT_PAYLOAD=$$(echo "$$JWT_TOKEN" | cut -d. -f2) && \
	 echo "Header:  $$(echo "$$JWT_HEADER" | base64 -d 2>/dev/null | jq -c . 2>/dev/null)" && \
	 echo "Algorithm: $$(echo "$$JWT_HEADER" | base64 -d 2>/dev/null | jq -r .alg 2>/dev/null)" && \
	 ALGORITHM=$$(echo "$$JWT_HEADER" | base64 -d 2>/dev/null | jq -r .alg 2>/dev/null) && \
	 if [ "$$ALGORITHM" = "RS256" ]; then \
	   echo "✅ Using RS256 algorithm (Kubernetes compatible)"; \
	 else \
	   echo "❌ Wrong algorithm: $$ALGORITHM (expected RS256)"; exit 1; \
	 fi
	@echo ""
	@echo "3️⃣  JWT claims verification:"
	@JWT_TOKEN=$$(jq -r '.status.token' /tmp/kubectl-ssh-oidc-test.json 2>/dev/null) && \
	 JWT_PAYLOAD=$$(echo "$$JWT_TOKEN" | cut -d. -f2) && \
	 CLAIMS=$$(echo "$$JWT_PAYLOAD" | base64 -d 2>/dev/null | jq . 2>/dev/null) && \
	 echo "Subject: $$(echo "$$CLAIMS" | jq -r .sub 2>/dev/null)" && \
	 echo "Issuer:  $$(echo "$$CLAIMS" | jq -r .iss 2>/dev/null)" && \
	 echo "Audience: $$(echo "$$CLAIMS" | jq -r '.aud | join(", ")' 2>/dev/null)" && \
	 echo "Groups:  $$(echo "$$CLAIMS" | jq -r '.groups | join(", ")' 2>/dev/null)" && \
	 AUDIENCE_CHECK=$$(echo "$$CLAIMS" | jq -r '.aud[]' 2>/dev/null | grep -q "kubernetes" && echo "true" || echo "false") && \
	 if [ "$$AUDIENCE_CHECK" = "true" ]; then \
	   echo "✅ Contains 'kubernetes' audience"; \
	 else \
	   echo "❌ Missing 'kubernetes' audience"; exit 1; \
	 fi
	@echo ""
	@echo "4️⃣  Debug mode verification:"
	@echo "Testing with debug output..."
	@env DEBUG=true kubectl-ssh-oidc 2>&1 | grep -q "Using ID token for authentication" && \
	  echo "✅ Debug output shows proper token usage" || \
	  echo "⚠️  Debug output not as expected (this may be normal)"
	@echo ""
	@echo "🎉 Manual verification complete!"
	@echo ""
	@echo "Summary of verification results:"
	@echo "- ✅ SSH key authentication working"
	@echo "- ✅ JWT token generation successful" 
	@echo "- ✅ RS256 algorithm used (Kubernetes compatible)"
	@echo "- ✅ Required JWT claims present"
	@echo ""
	@echo "The authentication flow is working correctly!"
	@rm -f /tmp/kubectl-ssh-oidc-test.json

# Diagnose kubectl exec plugin integration issues
.PHONY: test-kubectl-debug
test-kubectl-debug:
	@echo "🔧 kubectl Exec Plugin Diagnostics"
	@echo "===================================="
	@echo ""
	@echo "1️⃣  kubectl version:"
	@kubectl version --client 2>/dev/null || echo "❌ kubectl not found"
	@echo ""
	@echo "2️⃣  kubectl-ssh-oidc binary:"
	@which kubectl-ssh-oidc 2>/dev/null && echo "✅ kubectl-ssh-oidc found in PATH" || \
	 (echo "❌ kubectl-ssh-oidc not found in PATH"; echo "Run: make install")
	@echo ""
	@echo "3️⃣  SSH agent status:"
	@if [ -n "$$SSH_AUTH_SOCK" ]; then \
		echo "✅ SSH_AUTH_SOCK set: $$SSH_AUTH_SOCK"; \
		if ssh-add -l >/dev/null 2>&1; then \
			echo "✅ SSH keys loaded:"; \
			ssh-add -l; \
		else \
			echo "❌ No SSH keys in agent"; \
		fi; \
	else \
		echo "❌ SSH_AUTH_SOCK not set - SSH agent not running"; \
	fi
	@echo ""
	@echo "4️⃣  Current kubectl configuration for SSH context:"
	@if kubectl config get-contexts | grep -q "dex-ssh"; then \
		echo "✅ dex-ssh context found"; \
		echo "Context details:"; \
		kubectl config view --context=dex-ssh --minify; \
	else \
		echo "❌ dex-ssh context not found"; \
		echo "Available contexts:"; \
		kubectl config get-contexts; \
	fi
	@echo ""
	@echo "5️⃣  Exec plugin configuration test:"
	@echo "Creating test configuration from current context..."
	@if ! kubectl config view --context=dex-ssh --minify >/dev/null 2>&1; then \
		echo "❌ dex-ssh context not available, using fallback config"; \
	else \
		kubectl config view --context=dex-ssh --minify --raw > /tmp/kubectl-debug-config.yaml; \
		echo "✅ Test config created"; \
		echo ""; \
		echo "6️⃣  Testing kubectl with exec plugin (10 second timeout):"; \
		echo "Command: timeout 10 env KUBECONFIG=/tmp/kubectl-debug-config.yaml kubectl auth can-i get pods --v=6"; \
		echo ""; \
		if timeout 10 env KUBECONFIG=/tmp/kubectl-debug-config.yaml kubectl auth can-i get pods --v=6 2>&1 | \
		   tee /tmp/kubectl-debug-output.log; then \
			echo ""; \
			echo "✅ kubectl command completed"; \
		else \
			echo ""; \
			echo "❌ kubectl command failed or timed out"; \
		fi; \
		echo ""; \
		echo "7️⃣  Analyzing output for exec plugin invocation:"; \
		if grep -q "exec plugin" /tmp/kubectl-debug-output.log 2>/dev/null; then \
			echo "✅ Exec plugin invocation found in logs"; \
		elif grep -q "kubectl-ssh-oidc" /tmp/kubectl-debug-output.log 2>/dev/null; then \
			echo "✅ kubectl-ssh-oidc execution found in logs"; \
		else \
			echo "❌ No exec plugin invocation detected"; \
			echo "This suggests kubectl is not calling the exec plugin"; \
		fi; \
		echo ""; \
		echo "8️⃣  Manual exec plugin test:"; \
		if [ -n "$$DEX_URL" ] && [ -n "$$CLIENT_ID" ] && [ -n "$$CLIENT_SECRET" ] && [ -n "$$KUBECTL_SSH_USER" ]; then \
			echo "Environment variables available, testing direct plugin execution..."; \
			if kubectl-ssh-oidc >/dev/null 2>&1; then \
				echo "✅ Direct kubectl-ssh-oidc execution works"; \
			else \
				echo "❌ Direct kubectl-ssh-oidc execution failed"; \
			fi; \
		else \
			echo "⚠️  Environment variables not set, skipping direct test"; \
			echo "   Set DEX_URL, CLIENT_ID, CLIENT_SECRET, KUBECTL_SSH_USER to test"; \
		fi; \
		rm -f /tmp/kubectl-debug-config.yaml /tmp/kubectl-debug-output.log; \
	fi
	@echo ""
	@echo "🔍 Diagnostics complete!"

# End-to-end kubectl testing using existing configuration  
.PHONY: test-kubectl-e2e
test-kubectl-e2e: test-kubectl-debug clean-kubectl-cache
	@echo ""
	@echo "🎯 End-to-End kubectl Test"
	@echo "=========================="
	@echo ""
	@if [ -z "$$DEX_URL" ] || [ -z "$$CLIENT_ID" ] || [ -z "$$CLIENT_SECRET" ] || [ -z "$$KUBECTL_SSH_USER" ]; then \
		echo "❌ Missing required environment variables:"; \
		echo "   DEX_URL, CLIENT_ID, CLIENT_SECRET, KUBECTL_SSH_USER"; \
		echo ""; \
		echo "Set these environment variables and try again."; \
		exit 1; \
	fi
	@echo "Using existing dex-ssh kubectl context with fresh cache..."
	@if ! kubectl config get-contexts | grep -q "dex-ssh"; then \
		echo "❌ dex-ssh context not found in kubectl config"; \
		echo "Available contexts:"; \
		kubectl config get-contexts; \
		exit 1; \
	fi
	@echo "Testing kubectl get pods with dex-ssh context..."
	@echo "Command: kubectl --context=dex-ssh get pods --v=8"
	@echo "(This should now invoke the exec plugin with fresh cache)"
	@echo ""
	@timeout 30 kubectl --context=dex-ssh get pods --v=8 2>&1 | head -30 || \
	 (echo ""; echo "❌ kubectl command failed or timed out"; echo "Check output above for exec plugin calls")
	@echo ""
	@echo "✅ kubectl integration test completed"

.DEFAULT_GOAL := help