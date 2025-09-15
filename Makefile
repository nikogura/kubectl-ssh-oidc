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
	docker build -f docker/dex/Dockerfile -t kubectl-ssh-oidc/dex:latest docker/dex/

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
	@echo "  test-integration Run end-to-end integration tests (with unit+lint prereqs)"
	@echo "  test-integration-local Run local Go integration tests (fast, with unit+lint prereqs)"
	@echo "  test-all        Run all tests (unit + lint + integration)"
	@echo "  verify-dex      Verify custom Dex image works"
	@echo "  clean-integration Clean integration test environment"
	@echo "  lint            Lint the code"
	@echo "  fmt             Format the code"
	@echo "  tidy            Tidy dependencies"
	@echo "  clean           Clean build artifacts"
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

.DEFAULT_GOAL := help