#!/bin/bash
set -euo pipefail
###############################################
# Configuration
###############################################
PACKAGE_NAME="<PACKAGE NAME>"
VERSION="<VERSION>"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PAYLOAD_DIR="$SCRIPT_DIR/payload"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"
OUTPUT_DIR="$SCRIPT_DIR"
OUTPUT_PKG="$OUTPUT_DIR/${PACKAGE_NAME}.pkg"
###############################################
# Validation
###############################################
echo "Checking package structure..."
if [[ ! -d "$PAYLOAD_DIR" ]]; then
    echo "ERROR: Missing payload directory"
    exit 1
fi
if [[ ! -d "$SCRIPTS_DIR" ]]; then
    echo "ERROR: Missing scripts directory"
    exit 1
fi
if [[ ! -f "$SCRIPTS_DIR/postinstall" ]]; then
    echo "ERROR: Missing postinstall script"
    exit 1
fi
###############################################
# Prepare scripts
###############################################
echo "Setting script permissions..."
chmod 755 "$SCRIPTS_DIR/postinstall"
###############################################
# Build PKG
###############################################
echo "Building package..."
pkgbuild \
    --root "$PAYLOAD_DIR" \
    --scripts "$SCRIPTS_DIR" \
    --identifier "com.mycompany.datacollect" \
    --version "$VERSION" \
    "$OUTPUT_PKG"
###############################################
# Validate output
###############################################
if [[ ! -f "$OUTPUT_PKG" ]]; then
    echo "ERROR: Package was not created"
    exit 1
fi
echo
echo "Package created successfully:"
echo "$OUTPUT_PKG"