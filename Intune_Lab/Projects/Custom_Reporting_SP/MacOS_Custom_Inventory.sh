#!/bin/bash
set -euo pipefail
set -o errtrace
#
#----------------------------------------------
# CONFIGURATION
#----------------------------------------------
# A substring we use to find the private key
IDENTITY_NAME="Data_Collect"
# Use for authentication
TENANT_ID="<Tenant ID>"
CLIENT_ID="<Application ID>"
# Log Analytics Data (for JSON submission)
DCRIMMUTABLEID="<DCR Immutable ID>"
DCEURI="<DCE URI>"
STREAMNAME="<Stream Name>"
# LOG FILE
LogFile="<LOG FILE>"
#----------------------------------------------
# Logging initialization
#----------------------------------------------
# Delete the existing log if it exists
[[ -n "$LogFile" && -f "$LogFile" ]] && rm -f "$LogFile" 2>/dev/null || true
# Function to write to the log file for code brevity
Write_Log() {
    [[ -n "${1:-}" && -n "${2:-}" ]] || return
    printf "%s\t%s\n" "$(date +"%Y-%m-%d %H:%M:%S")" "$2" >> "$1"
}
#----------------------------------------------
# Trap functions - Error trapping and logging
#----------------------------------------------
# error_handler - Writes log info
error_handler() {
    local exit_code="$1"
    local line_no="$2"
    local cmd="$BASH_COMMAND"
    Write_Log "$LogFile" "RUNTIME ERROR: Command '$cmd' failed at line $line_no with exit code $exit_code"
    echo "ERROR: Command '$cmd' failed at line $line_no (exit $exit_code)" >&2
    exit "$exit_code"
}
# error_exit - Log an error message and terminate
error_exit() {
    local message="$1"
    Write_Log "$LogFile" "ERROR: $message"
    echo "ERROR: $message" >&2
    exit 1
}
# Any error gets trapped and logged here
trap 'error_handler $? $LINENO' ERR
###############################################
# BUILD CLIENT ASSERTION USING MACOS KEYCHAIN
# Requires Python3 and pyObjC
###############################################
#
assertion=$(python3 - "$IDENTITY_NAME" "$TENANT_ID" "$CLIENT_ID" <<'EOF'
import sys, time, json, base64, uuid, hashlib
from datetime import datetime, timedelta, timezone
from ctypes import *
from ctypes.util import find_library
# Load command line arguments
identity_name = sys.argv[1]
tenant_id = sys.argv[2]
client_id = sys.argv[3]
# Load macOS frameworks
Security = CDLL(find_library("Security"))
CoreFoundation = CDLL(find_library("CoreFoundation"))
# Type definitions
# CoreFoundation opaque types
CFTypeRef       = c_void_p
CFDictionaryRef = c_void_p
CFArrayRef      = c_void_p
CFStringRef     = c_void_p
CFDateRef       = c_void_p
CFNumberRef     = c_void_p
# CoreFoundation scalar types
CFTypeID = c_ulong
CFIndex  = c_long
# CF type identification
CoreFoundation.CFGetTypeID.argtypes = [CFTypeRef]
CoreFoundation.CFGetTypeID.restype = CFTypeID
CoreFoundation.CFDataCreate.argtypes = [c_void_p,POINTER(c_ubyte),c_long]
CoreFoundation.CFDataCreate.restype = c_void_p
CoreFoundation.CFDataGetLength.argtypes = [c_void_p]
CoreFoundation.CFDataGetLength.restype = c_long
CoreFoundation.CFDataGetBytePtr.argtypes = [c_void_p]
CoreFoundation.CFDataGetBytePtr.restype = c_void_p
CoreFoundation.CFDateGetTypeID.argtypes = []
CoreFoundation.CFDateGetTypeID.restype = CFTypeID
CoreFoundation.CFArrayCreate.argtypes = [CFTypeRef, POINTER(CFTypeRef), c_long, CFTypeRef]
CoreFoundation.CFArrayCreate.restype = CFArrayRef
CoreFoundation.CFArrayGetTypeID.argtypes = []
CoreFoundation.CFArrayGetTypeID.restype = CFTypeID
CoreFoundation.CFArrayGetCount.argtypes = [CFArrayRef]
CoreFoundation.CFArrayGetCount.restype = c_long
CoreFoundation.CFArrayGetValueAtIndex.argtypes = [CFArrayRef, c_long]
CoreFoundation.CFArrayGetValueAtIndex.restype = CFTypeRef
CoreFoundation.CFStringGetCStringPtr.argtypes = [c_void_p, c_uint32]
CoreFoundation.CFStringGetCStringPtr.restype = c_char_p
CoreFoundation.CFStringGetCString.argtypes = [c_void_p, c_char_p, c_long, c_uint32]
CoreFoundation.CFStringGetCString.restype = c_bool
CoreFoundation.CFStringGetTypeID.argtypes = []
CoreFoundation.CFStringGetTypeID.restype = CFTypeID
CoreFoundation.CFDateGetAbsoluteTime.argtypes = [c_void_p]
CoreFoundation.CFDateGetAbsoluteTime.restype = c_double
CoreFoundation.CFDictionaryGetValue.argtypes = [CFDictionaryRef, CFTypeRef]
CoreFoundation.CFDictionaryGetValue.restype = CFTypeRef
CoreFoundation.CFDictionaryContainsKey.argtypes = [CFDictionaryRef, CFTypeRef]
CoreFoundation.CFDictionaryContainsKey.restype = c_bool
CoreFoundation.CFDictionaryGetTypeID.argtypes = []
CoreFoundation.CFDictionaryGetTypeID.restype = CFTypeID
CoreFoundation.CFDictionaryGetCount.argtypes = [CFDictionaryRef]
CoreFoundation.CFDictionaryGetCount.restype = c_long
CoreFoundation.CFDictionaryGetKeysAndValues.argtypes = [CFDictionaryRef,POINTER(CFTypeRef),POINTER(CFTypeRef)]
CoreFoundation.CFDictionaryGetKeysAndValues.restype = None
CoreFoundation.CFNumberGetValue.argtypes = [CFNumberRef,c_int,c_void_p]
CoreFoundation.CFNumberGetValue.restype = c_bool
CoreFoundation.CFNumberGetValue.argtypes = [CFTypeRef,c_int,c_void_p]
CoreFoundation.CFNumberGetValue.restype = c_bool
CoreFoundation.CFNumberGetTypeID.argtypes = []
CoreFoundation.CFNumberGetTypeID.restype = CFTypeID
# Type Conversion
def CFStringToStr(cf_str):
    if not cf_str:
        return ""
    c_ptr = CoreFoundation.CFStringGetCStringPtr(cf_str, 0)
    if c_ptr:
        return c_ptr.decode()
    buf = create_string_buffer(4096)
    CoreFoundation.CFStringGetCString(cf_str, buf, 4096, 0)
    return buf.value.decode()
def CFDictionaryToDict(cf_dict):
    def convert(obj):
        if not obj:
            return None
        tid = CoreFoundation.CFGetTypeID(obj)
        if tid == CoreFoundation.CFDateGetTypeID():
            return CFDateToDateTime(obj)        
        if tid == CoreFoundation.CFStringGetTypeID():
            return CFStringToStr(obj)
        if tid == CoreFoundation.CFNumberGetTypeID():
            return CFNumberToFloat(obj)
        if tid == CoreFoundation.CFArrayGetTypeID():
            count = CoreFoundation.CFArrayGetCount(obj)
            return [
                convert(CoreFoundation.CFArrayGetValueAtIndex(obj, i))
                for i in range(count)
            ]
        if tid == CoreFoundation.CFDictionaryGetTypeID():
            count = CoreFoundation.CFDictionaryGetCount(obj)
            keys = (CFTypeRef * count)()
            values = (CFTypeRef * count)()
            CoreFoundation.CFDictionaryGetKeysAndValues(
                obj,
                keys,
                values
            )
            d = {}
            for i in range(count):
                d[convert(keys[i])] = convert(values[i])
            return d
        if tid == CoreFoundation.CFNumberGetTypeID():
            return CFNumberToFloat(obj)
        return obj
    return convert(cf_dict)
def CFNumberToFloat(cf_number):
    value = c_double()
    # kCFNumberDoubleType = 13
    if CoreFoundation.CFNumberGetValue(cf_number,13,byref(value)):
        return value.value
    return None
def CFDateToDateTime(cf_date):
    """
    Convert a CFDateRef to a timezone-aware UTC datetime.
    CFDate epoch: 2001-01-01 00:00:00 UTC
    """
    if not cf_date:
        return None
    # Seconds since 2001-01-01 00:00:00 UTC
    abs_time = CoreFoundation.CFDateGetAbsoluteTime(cf_date)
    apple_epoch = datetime(2001, 1, 1, tzinfo=timezone.utc)
    return apple_epoch + timedelta(seconds=abs_time)    
# Security API signatures
Security.SecCertificateCopyValues.argtypes = [c_void_p,c_void_p,POINTER(c_void_p)]
Security.SecCertificateCopyValues.restype = c_void_p
Security.SecCertificateCopyData.argtypes = [c_void_p]
Security.SecCertificateCopyData.restype = c_void_p
Security.SecKeychainOpen.argtypes = [c_char_p, POINTER(c_void_p)]
Security.SecKeychainOpen.restype = c_int32
Security.SecIdentitySearchCreate.argtypes = [CFArrayRef, c_uint32, POINTER(c_void_p)]
Security.SecIdentitySearchCreate.restype = c_int32
Security.SecIdentitySearchCopyNext.argtypes = [c_void_p, POINTER(c_void_p)]
Security.SecIdentitySearchCopyNext.restype = c_int32
Security.SecIdentityCopyCertificate.argtypes = [c_void_p, POINTER(c_void_p)]
Security.SecIdentityCopyCertificate.restype = c_int32
Security.SecCertificateCopySubjectSummary.argtypes = [c_void_p]
Security.SecCertificateCopySubjectSummary.restype = c_void_p
Security.SecIdentityCopyPrivateKey.argtypes = [c_void_p, POINTER(c_void_p)]
Security.SecIdentityCopyPrivateKey.restype = c_int32
Security.SecKeyCreateSignature.argtypes = [c_void_p,c_void_p,c_void_p,POINTER(c_void_p)]
Security.SecKeyCreateSignature.restype = c_void_p
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
status = Security.SecIdentitySearchCreate(keychain_array, 0, byref(search))
if status != 0 or not search.value:
    print("ERROR: failed to create identity search")
    sys.exit(1)
# Find identity by Common Name with private key
identity = c_void_p()
cert = c_void_p()
# Keep looping till we can't find it, or one is found
while True:
    identity = c_void_p()
    status = Security.SecIdentitySearchCopyNext(search,byref(identity))
    if status != 0:
        break
    cert = c_void_p()
    status = Security.SecIdentityCopyCertificate(identity,byref(cert))
    if status != 0 or not cert.value:
        continue
    # Get the certificate name
    summary = Security.SecCertificateCopySubjectSummary(cert)
    name = CFStringToStr(summary)
    # Partial name match
    if identity_name.lower() not in name.lower():
        continue
    # Ask macOS for certificate fields
    error = c_void_p()
    values = Security.SecCertificateCopyValues(cert,None,byref(error))
    if not values:
        print("SecCertificateCopyValues failed")
        if error.value:
            print("CFError:", hex(error.value))

    # Convert CFDictionaryRef → Python dict
    values_dict = CFDictionaryToDict(values)
    # Extract NotBefore / NotAfter
    APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
    not_before_seconds = values_dict["2.16.840.1.113741.2.1.1.1.6"]["value"]
    not_after_seconds = values_dict["2.16.840.1.113741.2.1.1.1.7"]["value"]
    not_before = APPLE_EPOCH + timedelta(seconds=not_before_seconds)
    not_after = APPLE_EPOCH + timedelta(seconds=not_after_seconds)
    now = datetime.now(timezone.utc)
    # Check NotBefore and NotAfter to make sure it isn't expired
    if now < not_before or now > not_after:
        continue
    # Verify a private key exists
    private_key_test = c_void_p()
    status = Security.SecIdentityCopyPrivateKey(identity,byref(private_key_test))
    if status != 0 or not private_key_test.value:
        continue
    # Found matching identity with private key
    break
if not identity.value:
    print("ERROR: identity not found in System keychain")
    sys.exit(1)
# Extract private key
private_key = c_void_p()
status = Security.SecIdentityCopyPrivateKey(identity,byref(private_key))
if status != 0 or not private_key.value:
    print("ERROR: cannot extract private key")
    sys.exit(1)
#
#print("SecIdentityCopyPrivateKey:", status)
#print("Private key:", hex(private_key.value))
#
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
# Build the JWT header
header = {
    "alg": "RS256",
    "typ": "JWT",
    "x5t": x5t
}
header_json = json.dumps(
    header,
    separators=(",", ":"),
    sort_keys=False
).encode()
# Build the JWT payload
now = int(time.time())
exp = now + 600
jti = str(uuid.uuid4())
payload = {
    "aud": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
    "iss": client_id,
    "sub": client_id,
    "jti": jti,
    "iat": now,
    "nbf": now,
    "exp": exp
}
payload_json = json.dumps(
    payload,
    separators=(",", ":"),
    sort_keys=False
).encode()
# Returns Base64 encoded string
def b64url(x):
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
#
header_b64 = b64url(header_json)
payload_b64 = b64url(payload_json)
signing_input = f"{header_b64}.{payload_b64}".encode()
buffer = (c_ubyte * len(signing_input)).from_buffer_copy(signing_input)
cf_signing_input = CoreFoundation.CFDataCreate(None,buffer,len(signing_input))
# Sign using SecKeyCreateSignature (RSASSA-PKCS1v1.5 SHA256)
kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256 = c_void_p.in_dll(Security, "kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256")
error = c_void_p()
signature = Security.SecKeyCreateSignature(private_key,kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,cf_signing_input,byref(error))
if not signature:
    print("Signing failed")
    sys.exit(1)
# Extract raw bytes from CFDataRef
CoreFoundation.CFDataGetLength.argtypes = [c_void_p]
CoreFoundation.CFDataGetLength.restype = c_long
CoreFoundation.CFDataGetBytePtr.argtypes = [c_void_p]
CoreFoundation.CFDataGetBytePtr.restype = c_void_p
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
MANAGEDDEVICENAME=$(Hostname)
Write_Log "$LogFile" "ManagedDeviceName: $MANAGEDDEVICENAME"
#
#----------------------------
# Detect Intune Device ID
#----------------------------
MANAGEDDEVICEID=$(security find-certificate -a | awk -F= '/issu/ && /MICROSOFT INTUNE MDM DEVICE CA/ {getline;print $2}' | sed 's/"//g')
Write_Log "$LogFile" "ManagedDeviceId: $MANAGEDDEVICEID"
#
#----------------------------
# Detect console user
#----------------------------
CURRENT_USER=$(stat -f "%Su" /dev/console)
Write_Log "$LogFile" "Current User: $CURRENT_USER"
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
Write_Log "$LogFile" "XProtect Version: $XP_VERSION"
Write_Log "$LogFile" "XProtect Meta Version: $XP_META"
if command -v XProtect >/dev/null 2>&1; then
    # Real-time protection state
    XP_LAUNCH_SCAN=$(XProtect status | awk -F': ' '/launch/{print $2}')
    XP_BACKGROUND_SCAN=$(XProtect status | awk -F': ' '/background/{print $2}')
    #
    Write_Log "$LogFile" "XProtect launch scan: $XP_LAUNCH_SCAN"
    Write_Log "$LogFile" "XProtect background scan: $XP_BACKGROUND_SCAN"
else
    Write_Log "$LogFile" "XProtect not found"
fi
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
Write_Log "$LogFile" "FileVault: $FILEVAULT_STATUS"
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
Write_Log "$LogFile" "Secure Token Status: $SECURE_TOKEN_STATUS"
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
Write_Log "$LogFile" "Bootstrap Token Status: $BOOTSTRAP_TOKEN_STATUS"
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
    (( i++ ))
done
Write_Log "$LogFile" "MAC Addresses enumerated."
#----------------------------
# Build Date
#----------------------------
BuildEpoch=$(stat -f "%m" /var/db/.AppleSetupDone)
BuildDate=$(date -jf "%s" "$BuildEpoch" +"%m/%d/%Y, %I:%M:%S %p")
Write_Log "$LogFile" "Build Date: $BuildDate"
#
#----------------------------
# Last Boot Time
#----------------------------
LastBoot=$(sysctl -n kern.boottime | awk '{print $4}' | sed 's/,//')
LastBootTime=$(date -jf "%s" "$LastBoot" +"%m/%d/%Y, %I:%M:%S %p")
Write_Log "$LogFile" "Last Boot Time: $LastBootTime"
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
Write_Log "$LogFile" "JSON: $jsonData"
#
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
    Write_Log "$LogFile" "Failed to obtain access token"
    Write_Log "$LogFile" "$response"
    exit 1
fi
#
# Debugging
#echo "$jsonData"
#echo "$access_token"
#exit 0
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
Write_Log "$LogFile" "Http Code: $http_code"
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
