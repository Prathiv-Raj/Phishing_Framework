#!/bin/bash
set -e

DOCKERHUB_USERNAME="${1:-your-dockerhub-username}"
IMAGE_NAME="ab-phish"
TAG="latest"
FULL_IMAGE="${DOCKERHUB_USERNAME}/${IMAGE_NAME}:${TAG}"

echo "================================================"
echo " AB-Phish Docker Build & Push"
echo " Image: ${FULL_IMAGE}"
echo "================================================"

# Step 1: Fix Docker DNS (WSL2 workaround)
echo "[1/4] Fixing Docker DNS..."
sudo mkdir -p /etc/docker
sudo bash -c 'cat > /etc/docker/daemon.json <<EOF
{
  "dns": ["8.8.8.8", "8.8.4.4"]
}
EOF'
sudo systemctl restart docker
sleep 3
echo "      DNS fixed → 8.8.8.8"

# Step 2: Build Go binary on host
echo "[2/4] Building Go binary..."
go build -o abphish_bin .
echo "      Binary built: $(ls -lh abphish_bin | awk '{print $5}')"

# Step 3: Build Docker image
echo "[3/4] Building Docker image: ${FULL_IMAGE}..."
docker build \
  --no-cache \
  -t "${IMAGE_NAME}:${TAG}" \
  -t "${FULL_IMAGE}" \
  .
echo "      Image built successfully"

# Step 4: Push to Docker Hub
echo "[4/4] Pushing to Docker Hub..."
docker login
docker push "${FULL_IMAGE}"
echo "      Pushed: ${FULL_IMAGE}"

echo ""
echo "================================================"
echo " Done! Run your container with:"
echo ""
echo "  docker run -d \\"
echo "    --name ab-phish \\"
echo "    -p 3333:3333 \\"
echo "    -p 80:80 \\"
echo "    -v ab-phish-db:/opt/ab-phish/abphish.db \\"
echo "    ${FULL_IMAGE}"
echo "================================================"
