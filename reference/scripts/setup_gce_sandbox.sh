#!/usr/bin/env bash
# ==============================================================================
# Hardened Isolated GCE Sandbox Setup Script for Mantis
# ==============================================================================
# Provisions a zero-internet VPC, private subnet, IAP-only firewall rules,
# link-local DNS sinkhole policy, and golden machine image for safe PoC execution.
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Configuration Variables (override via environment variables or edit below)
# ------------------------------------------------------------------------------
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || echo "")}"
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-us-central1-a}"
VPC_NAME="${VPC_NAME:-mantis-isolated-vpc}"
SUBNET_NAME="${SUBNET_NAME:-mantis-isolated-subnet}"
SUBNET_RANGE="${SUBNET_RANGE:-10.0.0.0/24}"
DNS_POLICY_NAME="${DNS_POLICY_NAME:-mantis-block-public-dns}"
IMAGE_NAME="${IMAGE_NAME:-mantis-assessment-disk-v1}"
SOURCE_INSTANCE="${SOURCE_INSTANCE:-}"

if [[ -z "${PROJECT_ID}" ]]; then
    echo "ERROR: PROJECT_ID is not set and no default GCP project is configured in gcloud."
    echo "Usage: PROJECT_ID=my-project-id [SOURCE_INSTANCE=my-dev-vm] $0"
    exit 1
fi

echo "======================================================================"
echo "Configuring Isolated GCE Sandbox for Mantis"
echo "Project:        ${PROJECT_ID}"
echo "Region / Zone:  ${REGION} / ${ZONE}"
echo "VPC / Subnet:   ${VPC_NAME} / ${SUBNET_NAME} (${SUBNET_RANGE})"
echo "DNS Policy:     ${DNS_POLICY_NAME}"
echo "Golden Image:   ${IMAGE_NAME}"
echo "======================================================================"

# ------------------------------------------------------------------------------
# 1. Create Isolated Custom VPC
# ------------------------------------------------------------------------------
if gcloud compute networks describe "${VPC_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "[1/5] VPC '${VPC_NAME}' already exists. Skipping creation."
else
    echo "[1/5] Creating isolated VPC '${VPC_NAME}'..."
    gcloud compute networks create "${VPC_NAME}" \
        --project="${PROJECT_ID}" \
        --subnet-mode=custom \
        --description="Isolated zero-internet VPC for Mantis sandbox execution"
fi

# ------------------------------------------------------------------------------
# 2. Create Private Subnet (No Internet, No Cloud NAT, No Google API Access)
# ------------------------------------------------------------------------------
if gcloud compute networks subnets describe "${SUBNET_NAME}" --region="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "[2/5] Subnet '${SUBNET_NAME}' already exists. Skipping creation."
else
    echo "[2/5] Creating private subnet '${SUBNET_NAME}' in region '${REGION}'..."
    gcloud compute networks subnets create "${SUBNET_NAME}" \
        --project="${PROJECT_ID}" \
        --network="${VPC_NAME}" \
        --region="${REGION}" \
        --range="${SUBNET_RANGE}" \
        --no-enable-private-ip-google-access \
        --description="Private subnet with Private Google Access disabled"
fi

# ------------------------------------------------------------------------------
# 3. Allow Ingress Strictly from Google Cloud Identity-Aware Proxy (IAP)
# ------------------------------------------------------------------------------
FIREWALL_RULE="allow-iap-ssh-${VPC_NAME}"
if gcloud compute firewall-rules describe "${FIREWALL_RULE}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "[3/5] Firewall rule '${FIREWALL_RULE}' already exists. Skipping creation."
else
    echo "[3/5] Creating IAP SSH ingress firewall rule '${FIREWALL_RULE}'..."
    gcloud compute firewall-rules create "${FIREWALL_RULE}" \
        --project="${PROJECT_ID}" \
        --network="${VPC_NAME}" \
        --allow=tcp:22 \
        --source-ranges=35.235.240.0/20 \
        --description="Allow SSH strictly through Google Cloud IAP tunnel"
fi

# ------------------------------------------------------------------------------
# 4. Sinkhole Link-Local DNS Public Recursion via Cloud DNS Response Policy
# ------------------------------------------------------------------------------
if gcloud dns response-policies describe "${DNS_POLICY_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "[4/5] DNS Response Policy '${DNS_POLICY_NAME}' already exists. Skipping creation."
else
    echo "[4/5] Creating Cloud DNS Response Policy '${DNS_POLICY_NAME}'..."
    gcloud dns response-policies create "${DNS_POLICY_NAME}" \
        --project="${PROJECT_ID}" \
        --networks="${VPC_NAME}" \
        --description="Block public recursive DNS queries on link-local resolver"

    gcloud dns response-policies rules create block-all-domains \
        --project="${PROJECT_ID}" \
        --response-policy="${DNS_POLICY_NAME}" \
        --dns-name="*." \
        --local-data=name="*.",type="A",ttl=300,rrdatas="0.0.0.0"
fi

# ------------------------------------------------------------------------------
# 5. Create Assessment Machine Image (Optional if SOURCE_INSTANCE provided)
# ------------------------------------------------------------------------------
if [[ -n "${SOURCE_INSTANCE}" ]]; then
    DETECTED_ZONE=$(gcloud compute instances list --filter="name=(${SOURCE_INSTANCE})" --format="value(zone)" --project="${PROJECT_ID}" 2>/dev/null | head -n1 || echo "")
    INSTANCE_ZONE="${SOURCE_ZONE:-${DETECTED_ZONE:-${ZONE}}}"

    if gcloud compute images describe "${IMAGE_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        echo "[5/5] Custom disk image '${IMAGE_NAME}' already exists. Skipping capture."
    else
        echo "[5/5] Creating assessment disk image '${IMAGE_NAME}' from '${SOURCE_INSTANCE}' (zone: ${INSTANCE_ZONE})..."
        gcloud compute images create "${IMAGE_NAME}" \
            --project="${PROJECT_ID}" \
            --source-disk="${SOURCE_INSTANCE}" \
            --source-disk-zone="${INSTANCE_ZONE}" \
            --force \
            --description="Assessment disk image with pre-warmed build dependencies for Mantis"
    fi
else
    echo "[5/5] No SOURCE_INSTANCE specified. Skipping disk image creation."
    echo "      To capture a disk image later: gcloud compute images create ${IMAGE_NAME} --source-disk=YOUR_DEV_VM --source-disk-zone=${ZONE} --force"
fi

echo ""
echo "======================================================================"
echo "GCE Sandbox Isolation Infrastructure Ready!"
echo "======================================================================"
echo "Add the following sandbox block to your reference/workflow.json:"
echo ""
cat <<EOF
{
  "sandbox": {
    "type": "gce",
    "options": {
      "project": "${PROJECT_ID}",
      "zone": "${ZONE}",
      "image": "${IMAGE_NAME}",
      "subnet": "${SUBNET_NAME}",
      "workdir": "/workspace",
      "tunnel_through_iap": true,
      "no_service_account": true,
      "no_external_ip": true,
      "verify_isolation": true,
      "timeout_seconds": 60
    }
  }
}
EOF
echo ""
