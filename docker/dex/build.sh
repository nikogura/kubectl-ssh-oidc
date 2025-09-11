#!/bin/bash

set -euo pipefail

# Build variables
DEX_VERSION=${DEX_VERSION:-v2.39.1}
IMAGE_TAG=${IMAGE_TAG:-custom-dex:${DEX_VERSION}-ssh}

echo "Building custom Dex image with SSH connector..."
echo "Dex version: ${DEX_VERSION}"
echo "Go version: 1.24"
echo "Image tag: ${IMAGE_TAG}"

# Build the image
docker build \
    --build-arg DEX_VERSION="${DEX_VERSION}" \
    -t "${IMAGE_TAG}" \
    .

echo "Build complete: ${IMAGE_TAG}"

# Optional: show image details
docker images | grep custom-dex