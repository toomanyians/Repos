#!/bin/bash
set -euo pipefail
set -o errtrace
trap 'echo "ERROR: Command \"$BASH_COMMAND\" failed on line $LINENO"; exit 1' ERR
#
###############################################
# CONFIGURATION
###############################################

IDENTITY_NAME="<Certificate name to match>"
TENANT_ID="<Your Tenant ID>"
CLIENT_ID="<Your App registration Client ID>"

# Log Analytics Data (for JSON submission)
DCRIMMUTABLEID="<DCR Immutable ID>"
DCEURI="<DCE Ingestion URL>"
STREAMNAME="<Stream name>"

###############################################
# BUILD CLIENT ASSERTION USING MACOS KEYCHAIN
# Requires Python3 and pyObjC
###############################################
#
assertion=$(python3 - "$IDENTITY_NAME" "$TENANT_ID" "$CLIENT_ID" <<'EOF'
import sys, time, json, base64, uuid, hashlib
from ctypes import *
from ctypes.util import find_library

identity_name = sys.argv[1]
tenant_id = sys.argv[2]
client_id = sys.argv[3]

# Load macOS frameworks
Security = CDLL(find_library("Security"))
CoreFoundation = CDLL(find_library("CoreFoundation"))

CFTypeRef = c_void_p
CFArrayRef = c_void_p

# CF helpers
CoreFoundation.CFArrayCreate.argtypes = [CFTypeRef, POINTER(CFTypeRef), c_long, CFTypeRef]
CoreFoundation.CFArrayCreate.restype = CFArrayRef
CoreFoundation.CFDataCreate.argtypes = [c_void_p,POINTER(c_ubyte),c_long]
CoreFoundation.CFDataCreate.restype = c_void_p
CoreFoundation.CFDataGetBytePtr.argtypes = [c_void_p]
CoreFoundation.CFDataGetBytePtr.restype = c_void_p
CoreFoundation.CFDataGetLength.argtypes = [c_void_p]
CoreFoundation.CFDataGetLength.restype = c_long
CoreFoundation.CFStringGetCString.argtypes = [c_void_p, c_char_p, c_long, c_uint32]
CoreFoundation.CFStringGetCString.restype = c_bool
CoreFoundation.CFStringGetCStringPtr.argtypes = [c_void_p, c_uint32]
CoreFoundation.CFStringGetCStringPtr.restype = c_char_p
# Security API helpers
Security.SecCertificateCopyData.argtypes = [c_void_p]
Security.SecCertificateCopyData.restype = c_void_p
Security.SecCertificateCopySubjectSummary.argtypes = [c_void_p]
Security.SecCertificateCopySubjectSummary.restype = c_void_p
Security.SecIdentityCopyCertificate.argtypes = [c_void_p, POINTER(c_void_p)]
Security.SecIdentityCopyCertificate.restype = c_int32
Security.SecIdentitySearchCopyNext.argtypes = [c_void_p, POINTER(c_void_p)]
Security.SecIdentitySearchCopyNext.restype = c_int32
Security.SecIdentitySearchCreate.argtypes = [CFArrayRef, c_uint32, POINTER(c_void_p)]
Security.SecIdentitySearchCreate.restype = c_int32
Security.SecIdentityCopyPrivateKey.argtypes = [c_void_p, POINTER(c_void_p)]
Security.SecIdentityCopyPrivateKey.restype = c_int32
Security.SecKeychainOpen.argtypes = [c_char_p, POINTER(c_void_p)]
Security.SecKeychainOpen.restype = c_int32
Security.SecKeyCreateSignature.argtypes = [c_void_p,c_void_p,c_void_p,POINTER(c_void_p)]
Security.SecKeyCreateSignature.restype = c_void_p

def CFStringToStr(cf_str):
    if not cf_str:
        return ""
    c_ptr = CoreFoundation.CFStringGetCStringPtr(cf_str, 0)
    if c_ptr:
        return c_ptr.decode()
    buf = create_string_buffer(4096)
    CoreFoundation.CFStringGetCString(cf_str, buf, 4096, 0)
    return buf.value.decode()

# Load System keychain
system_keychain = c_void_p()
status = Security.SecKeychainOpen(b"/Library/Keychains/System.keychain",byref(system_keychain))
if status != 0:
    print("ERROR: cannot open System keychain")
    sys.exit(1)

# Build CFArrayRef containing ONLY the System keychain
values = (CFTypeRef * 1)(system_keychain.value)
keychain_array = CoreFoundation.CFArrayCreate(None, values, 1, None)

# Create identity search
search = c_void_p()
status = Security.SecIdentitySearchCreate(keychain_array,0,byref(search))
if status != 0 or not search.value:
    print("ERROR: failed to create identity search")
    sys.exit(1)

# Find identity by Common Name
identity = c_void_p()
cert = c_void_p()

while True:
    status = Security.SecIdentitySearchCopyNext(search, byref(identity))
    if status != 0:
        break

    Security.SecIdentityCopyCertificate(identity, byref(cert))
    summary = Security.SecCertificateCopySubjectSummary(cert)
    name = CFStringToStr(summary)

    if identity_name.lower() in name.lower():
        break

if not identity.value:
    print("ERROR: identity not found in System keychain")
    sys.exit(1)

# Extract private key
private_key = c_void_p()
status = Security.SecIdentityCopyPrivateKey(identity, byref(private_key))
if status != 0 or not private_key.value:
    print("ERROR: cannot extract private key")
    sys.exit(1)
    
# print("SecIdentityCopyPrivateKey:", status)
# print("Private key:", hex(private_key.value) if private_key.value else None)

# Build JWT header + payload
# Get DER certificate bytes
cert_data = Security.SecCertificateCopyData(cert)
length = CoreFoundation.CFDataGetLength(cert_data)
ptr = CoreFoundation.CFDataGetBytePtr(cert_data)
der_bytes = string_at(ptr, length)

# SHA-1 thumbprint
thumbprint = hashlib.sha1(der_bytes).digest()

# Base64URL encode (no padding)
x5t = base64.urlsafe_b64encode(thumbprint).rstrip(b"=").decode()

header = {"alg": "RS256","typ": "JWT","x5t": x5t}
header_json = json.dumps(header,separators=(",", ":"),sort_keys=False).encode()

now = int(time.time())
exp = now + 600
jti = str(uuid.uuid4())

payload = {"aud": f"https://login.microsoftonline.com/{tenant_id}/v2.0","iss": client_id,"sub": client_id,"jti": jti,"iat": now,"nbf": now,"exp": exp}
payload_json = json.dumps(payload,separators=(",", ":"),sort_keys=False).encode()

def b64url(x):
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()

header_b64 = b64url(header_json)
payload_b64 = b64url(payload_json)
signing_input = f"{header_b64}.{payload_b64}".encode()
buffer = (c_ubyte * len(signing_input)).from_buffer_copy(signing_input)
cf_signing_input = CoreFoundation.CFDataCreate(None,buffer,len(signing_input))

# Sign using SecKeyCreateSignature (RSASSA-PKCS1v1.5 SHA256)
kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256 = c_void_p.in_dll(Security, "kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256")

error = c_void_p()
signature = Security.SecKeyCreateSignature(
    private_key,
    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
    cf_signing_input,
    byref(error)
)

if not signature:
    print("Signing failed")
    sys.exit(1)

# Extract raw bytes from CFDataRef

length = CoreFoundation.CFDataGetLength(signature)
ptr = CoreFoundation.CFDataGetBytePtr(signature)
raw_sig = string_at(ptr, length)

jwt = f"{header_b64}.{payload_b64}.{b64url(raw_sig)}"
print(jwt)
EOF
)
###############################################
# Begin Inventory script
###############################################
#----------------------------
# Detect Intune Device Name
#----------------------------
MANAGEDDEVICENAME=(Hostname)
#
#----------------------------
# Detect Intune Device ID
#----------------------------
MANAGEDDEVICEID=$(plutil -p /Library/Managed\ Preferences/com.apple.security.acme.plist | awk '/"CN"/{getline; match($0,/"[^"]+"/); print substr($0,RSTART+1,RLENGTH-2)}')
#
#----------------------------
# Detect console user
#----------------------------
CURRENT_USER=$(stat -f "%Su" /dev/console)
#
#----------------------------
# XProtect Status
#----------------------------
# Define potential file paths based on macOS versioning structures
XP_NEW_PATH="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents"
XP_LEGACY_PATH="/System/Library/CoreServices/XProtect.bundle/Contents"
# Check which path exists on the host machine and extract the versions
if [[ -d "$XP_NEW_PATH" ]]; then
    INFO="$XP_NEW_PATH/Info.plist"
    META="$XP_NEW_PATH/Resources/XProtect.meta.plist"
    if [[ -f "$INFO" ]]; then
        XP_VERSION=$(defaults read "$INFO" CFBundleShortVersionString 2>/dev/null)
    else
        XP_VERSION="Unknown"
    fi
    if [[ -f "$META" ]]; then
        XP_META=$(plutil -p "$META" | grep "\"Version\"" | awk -F' ' '{print $3}')
    else
        XP_META="Unknown"
    fi
elif [[ -d "$XP_LEGACY_PATH" ]]; then
    INFO="$XP_LEGACY_PATH/Info.plist"
    META="$XP_LEGACY_PATH/Resources/XProtect.meta.plist"
    if [[ -f "$INFO" ]]; then
        XP_VERSION=$(defaults read "$INFO" CFBundleShortVersionString 2>/dev/null)
    else
        XP_VERSION="Unknown"
    fi
    if [[ -f "$META" ]]; then
        XP_META=$(plutil -p "$META" | grep "\"Version\"" | awk -F' ' '{print $3}')
    else
        XP_META="Unknown"
    fi
else
    XP_VERSION="Unknown (XProtect file not found)"
    XP_META="Unknown (XProtect file not found)"
fi
# Real-time protection state
XP_LAUNCH_SCAN=$(XProtect status | awk -F': ' '/launch/{print $2}')
XP_BACKGROUND_SCAN=$(XProtect status | awk -F': ' '/background/{print $2}')
#
#----------------------------
# FileVault Data Volume Encryption
#----------------------------
FILEVAULT_STATUS=$(diskutil apfs list -plist | plutil -convert json -o - - |
jq -r '
[
  .Containers[].Volumes[]
  | select(.Roles[]? == "Data")
  | {
      Name: .Name,
      FileVault: (
        if .Encrypted == true then
          "Encrypted"
        elif .EncryptionProgress != null then
          "Encryption In Progress"
        else
          "Not Encrypted"
        end
      )
    }
  | "\(.Name);\(.FileVault)"
]
| join("|")
')
#----------------------------
# Secure Token Status
#----------------------------
if [[ "$CURRENT_USER" == "root" || -z "$CURRENT_USER" ]]; then
    SECURE_TOKEN_STATUS="No console user"
else
    TOKEN_RESULT=$(sysadminctl -secureTokenStatus "$CURRENT_USER" 2>&1)

    if echo "$TOKEN_RESULT" | grep -qi "ENABLED"; then
        SECURE_TOKEN_STATUS="Enabled"
    elif echo "$TOKEN_RESULT" | grep -qi "DISABLED"; then
        SECURE_TOKEN_STATUS="Disabled"
    else
        SECURE_TOKEN_STATUS="Unknown"
    fi
fi
#----------------------------
# Bootstrap Token Status
#----------------------------
BOOTSTRAP_RESULT=$(profiles status -type bootstraptoken 2>&1)
if echo "$BOOTSTRAP_RESULT" | grep -Eqi "escrowed.*YES|YES.*escrowed"; then
    BOOTSTRAP_TOKEN_STATUS="Escrowed"
elif echo "$BOOTSTRAP_RESULT" | grep -Eqi "escrowed.*NO|NO.*escrowed"; then
    BOOTSTRAP_TOKEN_STATUS="Not Escrowed"
else
    BOOTSTRAP_TOKEN_STATUS="Unknown"
fi
#----------------------------
# Mac Address (MAC0-MACx) Physical network adapter and MAC address "Nutanix VirtIO Ethernet Adapter #2|50:6B:8D:CA:DB:93"
#----------------------------
i=0
while read -r line; do
    if [[ "$line" == Hardware\ Port:* ]]; then
        hwport="${line#Hardware Port: }"
        mac=""
    elif [[ "$line" == Ethernet\ Address:* ]]; then
        mac="${line#Ethernet Address: }"
        declare "MAC$i"="$hwport|$mac"
        (( i++ ))
    fi
done < <(networksetup -listallhardwareports)
# Ensure MAC0–MAC4 exist
while [ "$i" -lt 5 ]; do
    declare "MAC$i"=""
done
#----------------------------
# Build Date
#----------------------------
BuildEpoch=$(stat -f "%m" /var/db/.AppleSetupDone)
BuildDate=$(date -jf "%s" "$BuildEpoch" +"%m/%d/%Y, %I:%M:%S %p")
#
#----------------------------
# Last Boot Time
#----------------------------
LastBoot=$(sysctl -n kern.boottime | awk '{print $4}' | sed 's/,//')
LastBootTime=$(date -jf "%s" "$LastBoot" +"%m/%d/%Y, %I:%M:%S %p")
#
# DEBUGGING OUTPUT
#
echo "Current User"
echo "---------------"
echo "ManagedDeviceName: $MANAGEDDEVICENAME"
echo "Intune ID: $MANAGEDDEVICEID"
echo ""
echo "Current User"
echo "---------------"
echo "Logged In User: $CURRENT_USER"
echo ""
echo "XProtect Status"
echo "---------------"
echo "XProtect Version: $XP_VERSION"
echo "XProtect Meta Version: $XP_META"
echo "XProtect Launch Scan: $XP_LAUNCH_SCAN"
echo "XProtect Background Scan: $XP_BACKGROUND_SCAN"
echo ""
echo "FileVault Status"
echo "---------------"
echo "Data Volume Encryption: $FILEVAULT_STATUS"
echo "Secure Token ($CURRENT_USER): $SECURE_TOKEN_STATUS"
echo "Bootstrap Token: $BOOTSTRAP_TOKEN_STATUS"
echo ""
echo "System Details"
echo "---------------"
echo "Build Date: $BuildDate"
echo "Last Boot: $LastBootTime"
echo ""
echo "MAC Addresses"
echo "---------------"
echo "MAC0: $MAC0"
echo "MAC1: $MAC1"
echo "MAC2: $MAC2"
echo "MAC3: $MAC3"
echo "MAC4: $MAC4"
#
exit 0
#
#----------------------------
# Build json
#----------------------------
jsonData=$(jq -n \
    --arg ManagedDeviceName "$MANAGEDDEVICENAME" \
    --arg ManagedDeviceID "$MANAGEDDEVICEID" \
    --arg DefenderState "" \
    --arg DefenderStart "" \
    --arg DefSpySigAge "" \
    --arg DefNisSigAge "" \
    --arg DefAVSigAge "" \
    --arg DefAMEngine "" \
    --arg BitlockerState "" \
    --arg BitlockerStart "" \
    --arg BitEncrypted "" \
    --arg BitEncryption "" \
    --arg BitProtected "" \
    --arg BitProtector "" \
    --arg XProtect_Version "$XP_VERSION" \
    --arg XProtect_Meta "$XP_META" \
    --arg XProtect_Launch "$XP_LAUNCH_SCAN" \
    --arg XProtect_Background "$XP_BACKGROUND_SCAN" \
    --arg FileVault_Status "$FILEVAULT_STATUS" \
    --arg FileVault_UserToken "$SECURE_TOKEN_STATUS" \
    --arg FileVault_BootToken "$BOOTSTRAP_TOKEN_STATUS" \
    --arg BuildDate "$BuildDate" \
    --arg LastBootTime "$LastBootTime" \
    --arg MAC0 "$MAC0" \
    --arg MAC1 "$MAC1" \
    --arg MAC2 "$MAC2" \
    --arg MAC3 "$MAC3" \
    --arg MAC4 "$MAC4" \
    '
    {
        ManagedDeviceName: $ManagedDeviceName,
        ManagedDeviceID: $ManagedDeviceID,
        DefenderState: "",
        DefenderStart: "",
        DefSpySigAge: "",
        DefNisSigAge: "",
        DefAVSigAge: "",
        DefAMEngine: "",
        BitlockerState: "",
        BitlockerStart: "",
        BitEncrypted: "",
        BitEncryption: "",
        BitProtected: "",
        BitProtector: "",
        XProtect_Version: $XProtect_Version,
        XProtect_Meta: $XProtect_Meta,
        XProtect_Launch: $XProtect_Launch,
        XProtect_Background: $XProtect_Background,
        FileVault_Status: $FileVault_Status,
        FileVault_UserToken: $FileVault_UserToken,
        FileVault_BootToken: $FileVault_BootToken,
        BuildDate: $BuildDate,
        LastBootTime: $LastBootTime,
        MAC0: $MAC0,
        MAC1: $MAC1,
        MAC2: $MAC2,
        MAC3: $MAC3,
        MAC4: $MAC4
    }
    '
)
#
#
# Debugging
echo "$jsonData"
exit 0
#
#----------------------------
# REQUEST TOKEN FROM AZURE AD
#----------------------------
#
response=$(curl -s \
  -X POST "https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "scope=https://monitor.azure.com/.default" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=$assertion")
#
access_token=$(echo "$response" | jq -r '.access_token')
#
if [[ -z "$access_token" || "$access_token" == "null" ]]; then
    echo "Failed to obtain access token"
    echo "$response"
    exit 1
fi
#
# Debugging
echo "$access_token"
exit 0
#
#----------------------------
# Send json
#----------------------------
URI="$DCEURI/dataCollectionRules/$DCRIMMUTABLEID/streams/$STREAMNAME?api-version=2023-01-01"
http_code=$(curl -s \
  -o /dev/null \
  -w "%{http_code}" \
  -X POST "$URI" \
  -H "Authorization: Bearer $access_token" \
  -H "Content-Type: application/json" \
  --data-binary "[$jsonData]"
)
#
#----------------------------
# Report resulting status
#----------------------------
if [[ "$http_code" == "204" ]]; then
    echo "SUCCESS"
else
    echo "FAILED: HTTP $http_code"
    exit 1
fi
