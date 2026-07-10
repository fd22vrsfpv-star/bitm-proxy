#!/bin/bash
set -e

IMAGE=mitm-proxy
CONTAINER=mitm-proxy
VOLUME=mitm-proxy-data

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
    exit 1
fi

# Check if Docker daemon is running
if ! docker ping &> /dev/null 2>&1; then
    echo -e "${RED}Error: Docker daemon is not running${NC}"
    echo "Try: sudo systemctl start docker"
    exit 1
fi

# Check if Dockerfile exists
if [ ! -f Dockerfile ]; then
    echo -e "${RED}Error: Dockerfile not found in current directory${NC}"
    echo "Run this script from the mitm-proxy root directory"
    exit 1
fi

echo -e "${YELLOW}Building Docker image...${NC}"
if ! docker build -t "$IMAGE" .; then
    echo -e "${RED}Error: Failed to build Docker image${NC}"
    exit 1
fi

echo -e "${YELLOW}Removing old container (if exists)...${NC}"
docker rm -f "$CONTAINER" 2>/dev/null || true

echo -e "${YELLOW}Creating volume...${NC}"
docker volume create "$VOLUME" 2>/dev/null || true

echo -e "${YELLOW}Starting container...${NC}"
if ! docker run --name "$CONTAINER" \
    -p 8091:8091 -p 8092:8092 \
    -p 8000:8000 \
    -p 8085:8085 \
    -p 3100-3199:3100-3199 \
    -v "$VOLUME":/data \
    -e REQUIRE_API_KEY=false \
    -it "$IMAGE"; then
    echo -e "${RED}Error: Failed to start container${NC}"
    echo "Check if ports are already in use:"
    echo "  sudo lsof -i :8091 -i :8092 -i :8000 -i :8085"
    exit 1
fi

echo -e "${GREEN}Container started successfully${NC}"
