#!/bin/bash

# AGARI Folio Deployment Script for k3d
# This script builds and deploys the Folio API to the agari k3d cluster

set -e

# Configuration
CLUSTER_NAME="agari"
NAMESPACE="agari"
IMAGE_NAME="ghcr.io/openupsa/agari-folio"
TAG="latest"
HELM_RELEASE="folio"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}AGARI Folio Deployment to k3d${NC}"
echo "================================"

# Check if k3d cluster exists
echo -e "${YELLOW}Checking k3d cluster '${CLUSTER_NAME}'...${NC}"
if ! k3d cluster list | grep -q "${CLUSTER_NAME}"; then
    echo -e "${RED}Error: k3d cluster '${CLUSTER_NAME}' not found${NC}"
    echo "Please ensure the agari k3d cluster is running"
    exit 1
fi

echo -e "${GREEN}✓ k3d cluster '${CLUSTER_NAME}' found${NC}"

# Build Docker image
echo -e "${YELLOW}Building Docker image...${NC}"
docker build -t "${IMAGE_NAME}:${TAG}" .

# Import image to k3d
echo -e "${YELLOW}Importing image to k3d cluster...${NC}"
k3d image import "${IMAGE_NAME}:${TAG}" -c "${CLUSTER_NAME}"

echo -e "${GREEN}✓ Image imported to k3d cluster${NC}"

# Deploy with Helm
echo -e "${YELLOW}Deploying with Helm...${NC}"

# Check if namespace exists
kubectl config use-context "k3d-${CLUSTER_NAME}"
if ! kubectl get namespace "${NAMESPACE}" &> /dev/null; then
    echo -e "${YELLOW}Creating namespace '${NAMESPACE}'...${NC}"
    kubectl create namespace "${NAMESPACE}"
fi

# Install or upgrade Helm release
if helm list -n "${NAMESPACE}" | grep -q "${HELM_RELEASE}"; then
    echo -e "${YELLOW}Upgrading existing Helm release...${NC}"
    helm upgrade "${HELM_RELEASE}" ./helm -n "${NAMESPACE}"
else
    echo -e "${YELLOW}Installing new Helm release...${NC}"
    helm install "${HELM_RELEASE}" ./helm -n "${NAMESPACE}"
fi

echo -e "${GREEN}✓ Deployment completed${NC}"

# Wait for deployment to be ready
echo -e "${YELLOW}Waiting for deployment to be ready...${NC}"
kubectl wait --for=condition=available --timeout=300s deployment/${HELM_RELEASE} -n "${NAMESPACE}"

# Show deployment status
echo -e "${GREEN}Deployment Status:${NC}"
kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=folio
kubectl get services -n "${NAMESPACE}" -l app.kubernetes.io/name=folio
kubectl get ingress -n "${NAMESPACE}" -l app.kubernetes.io/name=folio

echo -e "${GREEN}✓ AGARI Folio deployed successfully!${NC}"
echo ""
echo -e "${YELLOW}Access URLs:${NC}"
echo "  API: http://folio.local/"
echo "  Swagger Docs: http://folio.local/docs/"
echo ""
echo -e "${YELLOW}To test the API:${NC}"
echo "  kubectl port-forward svc/${HELM_RELEASE} 5001:80 -n ${NAMESPACE}"
echo "  Then access: http://localhost:5001/docs/"
