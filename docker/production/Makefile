# Build variables - defaults to latest versions from GitHub
# Can be overridden via environment variables: make DEX_VERSION=v2.40.0 KUBECTL_SSH_OIDC_VERSION=v0.2.0 build

# Function to get latest GitHub release tag
define get_latest_release
$(shell curl -s https://api.github.com/repos/$(1)/releases/latest | jq -r '.tag_name // "$(2)"' 2>/dev/null || echo "$(2)")
endef

# Default to latest releases from GitHub, with fallbacks
DEX_VERSION ?= $(call get_latest_release,dexidp/dex,v2.39.1)
KUBECTL_SSH_OIDC_VERSION ?= $(call get_latest_release,nikogura/kubectl-ssh-oidc,0.1.0)

# Container repository settings - customize for your repository
# Examples:
#   Docker Hub: CONTAINER_REPO = your-dockerhub-username/your-dex-repo
#   GitHub Container Registry: CONTAINER_REPO = ghcr.io/your-github-username/your-dex-repo
#   AWS ECR: CONTAINER_REPO = 123456789012.dkr.ecr.us-west-2.amazonaws.com/your-dex-repo
#   Azure ACR: CONTAINER_REPO = yourregistry.azurecr.io/your-dex-repo
#   Google GCR: CONTAINER_REPO = gcr.io/your-project-id/your-dex-repo
CONTAINER_REPO ?=

# Image naming - tag format: <dex-version>-<kubectl-ssh-oidc-version>
IMAGE_TAG ?= $(DEX_VERSION)-$(KUBECTL_SSH_OIDC_VERSION)
LOCAL_IMAGE_TAG = dex:$(IMAGE_TAG)

# Full container tag (only set if repository is specified)
ifdef CONTAINER_REPO
	REMOTE_IMAGE_TAG = $(CONTAINER_REPO):$(IMAGE_TAG)
else
	REMOTE_IMAGE_TAG = $(LOCAL_IMAGE_TAG)
endif

# Use detected versions directly (already resolved from GitHub API or fallback)
ACTUAL_DEX_VERSION := $(DEX_VERSION)

.PHONY: build tag push info clean help check-repo versions

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

tag: build check-repo
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
ifdef CONTAINER_REPO
	@echo "Container repository: $(CONTAINER_REPO)"
else
	@echo "Container repository: <not set - local builds only>"
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

check-repo:
ifndef CONTAINER_REPO
	@echo "WARNING: CONTAINER_REPO not set. Use 'make CONTAINER_REPO=your-registry.com/your-dex-repo tag' to tag for remote repository."
	@echo "See 'make help' for repository examples."
endif

clean:
	@echo "Cleaning up local images..."
	-docker rmi $(LOCAL_IMAGE_TAG) 2>/dev/null || true
ifdef CONTAINER_REPO
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
	@echo "  CONTAINER_REPO           - Target repository for push (default: none)"
	@echo
	@echo "Version Detection:"
	@echo "  The Makefile automatically detects the latest releases from GitHub."
	@echo "  Current detected versions:"
	@echo "    Dex: $(DEX_VERSION)"
	@echo "    kubectl-ssh-oidc: $(KUBECTL_SSH_OIDC_VERSION)"
	@echo "  Override with: make DEX_VERSION=v2.40.0 KUBECTL_SSH_OIDC_VERSION=v0.2.0 build"
	@echo
	@echo "Repository Examples:"
	@echo "  Docker Hub:"
	@echo "    make CONTAINER_REPO=your-username/dex build tag push"
	@echo
	@echo "  GitHub Container Registry:"
	@echo "    make CONTAINER_REPO=ghcr.io/your-username/dex build tag push"
	@echo
	@echo "  AWS ECR:"
	@echo "    make CONTAINER_REPO=123456789012.dkr.ecr.us-west-2.amazonaws.com/dex build tag push"
	@echo
	@echo "  Azure Container Registry:"
	@echo "    make CONTAINER_REPO=yourregistry.azurecr.io/dex build tag push"
	@echo
	@echo "  Google Container Registry:"
	@echo "    make CONTAINER_REPO=gcr.io/your-project-id/dex build tag push"
	@echo
	@echo "Example Usage:"
	@echo "  make build                                        # Build locally (dex:v2.44.0-0.1.1)"
	@echo "  make CONTAINER_REPO=my.registry.com/dex push      # Build and push to repository"
	@echo "  make DEX_VERSION=v2.40.0 build                    # Build with specific Dex version"