#----------------------------------------------
#
# Configuration
#
#----------------------------------------------
# This must be the SYSTEM keychain
KEYCHAIN="/Library/Keychains/System.keychain"
# PRIVATE KEY CONFIG
THUMBPRINT="<PFX THUMBPRINT>"
#----------------------------------------------
# Detection
#----------------------------------------------
if security find-identity -v "$KEYCHAIN" \
    | tr '[:upper:]' '[:lower:]' \
    | grep -q "$THUMBPRINT"
then
    echo "Certificate identity detected."
    exit 0
else
    echo "Certificate identity not detected."
    exit 1
fi