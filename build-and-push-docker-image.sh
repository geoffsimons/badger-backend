#!/bin/bash

# --- Configuration Variables ---
AWS_REGION="us-west-2"
ECR_REPO_NAME="badger-repo" # <-- CONFIRMED REPO NAME
# Generate a timestamp for the image tag: YYYYMMDDHHMMSS
DATETIME=$(date +%Y%m%d%H%M%S)
IMAGE_TAG="badger-backend-${DATETIME}" # Format: badger-backend-YYYYMMDDHHMMSS

# --- 1. Get AWS Account ID ---
echo "Retrieving AWS account ID..."
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)

if [ -z "$AWS_ACCOUNT_ID" ]; then
  echo "Error: Could not retrieve AWS account ID. Check your AWS CLI configuration."
  exit 1
fi

FULL_IMAGE_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}:${IMAGE_TAG}"
echo "Full Image URI: ${FULL_IMAGE_URI}"

# --- 2. Authenticate Docker to ECR ---
echo "Authenticating Docker to ECR..."
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

if [ $? -ne 0 ]; then
  echo "Error: Docker ECR login failed."
  exit 1
fi

# --- 3. Build the Docker Image ---
# Ensure your Spring Boot JAR is built before running this script!
echo "Building Docker image..."
# Use a generic local name for building, then tag it with the full URI
docker build -t ${ECR_REPO_NAME}:local-build .

if [ $? -ne 0 ]; then
  echo "Error: Docker build failed."
  exit 1
fi

# --- 4. Tag the Image ---
echo "Tagging image with URI: ${FULL_IMAGE_URI}"
docker tag ${ECR_REPO_NAME}:local-build ${FULL_IMAGE_URI}

# --- 5. Push the Image to ECR ---
echo "Pushing image to ECR..."
docker push ${FULL_IMAGE_URI}

if [ $? -ne 0 ]; then
  echo "Error: Docker push failed."
  exit 1
fi

echo "--- Deployment Complete ---"
echo "New backend image successfully pushed: ${FULL_IMAGE_URI}"

# Optional: Output the Terraform string for easy copy/paste
echo "--------------------------------------------------------"
echo "ACTION REQUIRED: Update your ecs.tf with this image value:"
echo "--------------------------------------------------------"
echo "${FULL_IMAGE_URI}"