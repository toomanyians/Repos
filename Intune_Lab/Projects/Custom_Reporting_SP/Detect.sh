#!/bin/bash
set -euo pipefail
###############################################
# Configuration
###############################################
CERT_THUMBPRINT="<THUMBPRINT>"
KEYCHAIN="/Library/Keychains/System.keychain"
###############################################
# Normalize thumbprint
###############################################
CERT_THUMBPRINT=$(echo "$CERT_THUMBPRINT" | tr '[:upper:]' '[:lower:]')
###############################################
# Detection
###############################################
IDENTITY_FOUND=$(security find-identity -v "$KEYCHAIN" | tr -d ' ' | tr '[:upper:]' '[:lower:]' | grep "$CERT_THUMBPRINT" || true)
if [[ -n "$IDENTITY_FOUND" ]]; then
    echo "Certificate identity detected."
    exit 0
else
    echo "Certificate identity not detected."
    exit 1
fi