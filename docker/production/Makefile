# Build variables - defaults to latest versions from GitHub
# Can be overridden via environment variables: make DEX_VERSION=v2.40.0 KUBECTL_SSH_OIDC_VERSION=v0.2.0 build

# Function to get latest GitHub release tag
define get_latest_release
$(shell curl -s https://api.github.com/repos/$(1)/releases/latest | jq -r '.tag_name // "$(2)"' 2>/dev/null || echo "$(2)")
endef

# Default to latest releases from GitHub, with fallbacks
DEX_VERSION ?= $(call get_latest_release,dexidp/dex,v2.39.1)
KUBECTL_SSH_OIDC_VERSION ?= $(call get_latest_release,nikogura/kubectl-ssh-oidc,0.1.0)

# Container registry settings - customize for your registry
# Examples:
#   Docker Hub: CONTAINER_REGISTRY = your-dockerhub-username
#   GitHub Container Registry: CONTAINER_REGISTRY = ghcr.io/your-github-username
#   AWS ECR: CONTAINER_REGISTRY = 123456789012.dkr.ecr.us-west-2.amazonaws.com
#   Azure ACR: CONTAINER_REGISTRY = yourregistry.azurecr.io
#   Google GCR: CONTAINER_REGISTRY = gcr.io/your-project-id
CONTAINER_REGISTRY ?=

# Image naming
IMAGE_NAME ?= dex-ssh-oidc
IMAGE_TAG ?= $(DEX_VERSION)-kubectl-$(KUBECTL_SSH_OIDC_VERSION)
LOCAL_IMAGE_TAG = $(IMAGE_NAME):$(IMAGE_TAG)

# Full container tag (only set if registry is specified)
ifdef CONTAINER_REGISTRY
	REMOTE_IMAGE_TAG = $(CONTAINER_REGISTRY)/$(LOCAL_IMAGE_TAG)
else
	REMOTE_IMAGE_TAG = $(LOCAL_IMAGE_TAG)
endif

# Use detected versions directly (already resolved from GitHub API or fallback)
ACTUAL_DEX_VERSION := $(DEX_VERSION)

.PHONY: build tag push info clean help check-registry versions

# Default target
build: info
	@echo "Building custom Dex image with SSH connector..."
	docker build \
		--build-arg DEX_VERSION="$(ACTUAL_DEX_VERSION)" \
		--build-arg KUBECTL_SSH_OIDC_VERSION="$(KUBECTL_SSH_OIDC_VERSION)" \
		--build-arg CACHE_BUST="$(shell date +%s)" \
		-t "$(LOCAL_IMAGE_TAG)" \
		.
	@echo "Build complete: $(LOCAL_IMAGE_TAG)"

tag: build check-registry
	@echo "Tagging $(LOCAL_IMAGE_TAG) -> $(REMOTE_IMAGE_TAG)"
	docker tag $(LOCAL_IMAGE_TAG) $(REMOTE_IMAGE_TAG)

push: tag
	@echo "Pushing $(REMOTE_IMAGE_TAG)..."
	docker push $(REMOTE_IMAGE_TAG)
	@echo "Push complete: $(REMOTE_IMAGE_TAG)"

info:
	@echo "=== Build Configuration ==="
	@echo "Dex version: $(ACTUAL_DEX_VERSION) (auto-detected from GitHub)"
	@echo "kubectl-ssh-oidc version: $(KUBECTL_SSH_OIDC_VERSION) (auto-detected from GitHub)"
	@echo "Local image tag: $(LOCAL_IMAGE_TAG)"
	@echo "Remote image tag: $(REMOTE_IMAGE_TAG)"
ifdef CONTAINER_REGISTRY
	@echo "Container registry: $(CONTAINER_REGISTRY)"
else
	@echo "Container registry: <not set - local builds only>"
endif
	@echo "Note: Set DEX_VERSION and/or KUBECTL_SSH_OIDC_VERSION env vars to override auto-detection"
	@echo

versions:
	@echo "=== Version Detection ==="
	@echo "Auto-detecting latest versions from GitHub..."
	@echo
	@echo "Dex latest release:"
	@curl -s https://api.github.com/repos/dexidp/dex/releases/latest | jq -r '.tag_name // "Unable to detect"' 2>/dev/null || echo "Unable to detect (jq required)"
	@echo
	@echo "kubectl-ssh-oidc latest release:"
	@curl -s https://api.github.com/repos/nikogura/kubectl-ssh-oidc/releases/latest | jq -r '.tag_name // "Unable to detect"' 2>/dev/null || echo "Unable to detect (jq required)"
	@echo
	@echo "Currently configured versions:"
	@echo "  DEX_VERSION=$(DEX_VERSION)"
	@echo "  KUBECTL_SSH_OIDC_VERSION=$(KUBECTL_SSH_OIDC_VERSION)"

check-registry:
ifndef CONTAINER_REGISTRY
	@echo "WARNING: CONTAINER_REGISTRY not set. Use 'make CONTAINER_REGISTRY=your-registry.com tag' to tag for remote registry."
	@echo "See 'make help' for registry examples."
endif

clean:
	@echo "Cleaning up local images..."
	-docker rmi $(LOCAL_IMAGE_TAG) 2>/dev/null || true
ifdef CONTAINER_REGISTRY
	-docker rmi $(REMOTE_IMAGE_TAG) 2>/dev/null || true
endif
	@echo "Cleanup complete"

help:
	@echo "=== Dex with SSH Connector Build System ==="
	@echo
	@echo "Available targets:"
	@echo "  build         - Build the Docker image (default)"
	@echo "  tag           - Build and tag image for registry"
	@echo "  push          - Build, tag, and push image to registry"
	@echo "  info          - Show build configuration"
	@echo "  versions      - Show version detection from GitHub"
	@echo "  clean         - Remove built images"
	@echo "  help          - Show this help message"
	@echo
	@echo "Configuration Variables:"
	@echo "  DEX_VERSION              - Dex version to build (default: latest from GitHub)"
	@echo "  KUBECTL_SSH_OIDC_VERSION - kubectl-ssh-oidc version (default: latest from GitHub)"
	@echo "  IMAGE_NAME               - Local image name (default: $(IMAGE_NAME))"
	@echo "  CONTAINER_REGISTRY       - Target registry for push (default: none)"
	@echo
	@echo "Version Detection:"
	@echo "  The Makefile automatically detects the latest releases from GitHub."
	@echo "  Current detected versions:"
	@echo "    Dex: $(DEX_VERSION)"
	@echo "    kubectl-ssh-oidc: $(KUBECTL_SSH_OIDC_VERSION)"
	@echo "  Override with: make DEX_VERSION=v2.40.0 KUBECTL_SSH_OIDC_VERSION=v0.2.0 build"
	@echo
	@echo "Registry Examples:"
	@echo "  Docker Hub:"
	@echo "    make CONTAINER_REGISTRY=your-username build tag push"
	@echo
	@echo "  GitHub Container Registry:"
	@echo "    make CONTAINER_REGISTRY=ghcr.io/your-username build tag push"
	@echo
	@echo "  AWS ECR:"
	@echo "    make CONTAINER_REGISTRY=123456789012.dkr.ecr.us-west-2.amazonaws.com build tag push"
	@echo
	@echo "  Azure Container Registry:"
	@echo "    make CONTAINER_REGISTRY=yourregistry.azurecr.io build tag push"
	@echo
	@echo "  Google Container Registry:"
	@echo "    make CONTAINER_REGISTRY=gcr.io/your-project-id build tag push"
	@echo
	@echo "Example Usage:"
	@echo "  make build                                    # Build locally"
	@echo "  make CONTAINER_REGISTRY=my.registry.com push # Build and push to registry"
	@echo "  make DEX_VERSION=v2.40.0 build               # Build with specific Dex version"